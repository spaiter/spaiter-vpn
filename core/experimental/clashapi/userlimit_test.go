package clashapi

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
	"github.com/spaiter/spaiter-vpn/core/option"
)

// discardConn is a net.Conn that accepts writes instantly, so a throughput
// measurement reflects the limiter and nothing else.
type discardConn struct {
	net.Conn
}

func (discardConn) Write(p []byte) (int, error) { return len(p), nil }
func (discardConn) Read(p []byte) (int, error)  { return 0, io.EOF }
func (discardConn) Close() error                { return nil }

func newRegistryWith(t *testing.T, user string, limit option.UserLimitOptions) *userLimitRegistry {
	t.Helper()
	return newUserLimitRegistry(map[string]option.UserLimitOptions{user: limit})
}

// The property the whole design rests on: sing's unwrapping must stop at the
// limiter. If limitedConn ever reports itself replaceable, UnwrapCountWriter
// walks past it to the raw socket, the copy is spliced, and the cap silently
// stops applying while every counter and test still looks right.
func TestUnwrapStopsAtLimiter(t *testing.T) {
	registry := newRegistryWith(t, "alice", option.UserLimitOptions{DownloadMbps: 8})
	wrapped := registry.WrapConn(context.Background(), "alice", discardConn{})

	writer, _ := N.UnwrapCountWriter(wrapped, nil)
	if writer != wrapped {
		t.Fatalf("unwrapping walked past the limiter: got %T, want the limitedConn itself", writer)
	}
	reader, _ := N.UnwrapCountReader(wrapped, nil)
	if reader != wrapped {
		t.Fatalf("unwrapping walked past the limiter on the read side: got %T", reader)
	}

	// Negative control: the same wrapper that reports itself replaceable does
	// get walked past. Without this the assertion above would still pass if
	// UnwrapCountWriter stopped at every wrapper for some unrelated reason,
	// and the test would be guarding nothing.
	inner := discardConn{}
	replaceable := &replaceableConn{ExtendedConn: bufio.NewExtendedConn(inner)}
	if writer, _ := N.UnwrapCountWriter(replaceable, nil); writer == replaceable {
		t.Fatal("a replaceable wrapper was not unwrapped, so this test cannot tell the two cases apart")
	}
}

// replaceableConn is limitedConn's opposite: it declares itself replaceable,
// which is what makes sing walk past a wrapper.
type replaceableConn struct {
	N.ExtendedConn
}

func (c *replaceableConn) Upstream() any           { return c.ExtendedConn }
func (c *replaceableConn) ReaderReplaceable() bool { return true }
func (c *replaceableConn) WriterReplaceable() bool { return true }

// An uncapped user has to get its connection back untouched, otherwise every
// user pays the cost of losing splice.
func TestUncappedUserIsNotWrapped(t *testing.T) {
	registry := newRegistryWith(t, "alice", option.UserLimitOptions{DownloadMbps: 8})
	conn := discardConn{}

	if got := registry.WrapConn(context.Background(), "bob", conn); got != net.Conn(conn) {
		t.Fatalf("a user with no cap got a wrapper: %T", got)
	}
	// Unattributed traffic carries no user name and must not be capped either.
	if got := registry.WrapConn(context.Background(), "", conn); got != net.Conn(conn) {
		t.Fatalf("unattributed traffic got a wrapper: %T", got)
	}
}

// rate.Limiter.WaitN refuses any n above the burst outright. Buffer sizes are
// chosen by the relay, not by us, so a write bigger than the burst has to be
// split into several waits instead of failing.
func TestWriteLargerThanBurstSucceeds(t *testing.T) {
	registry := newRegistryWith(t, "alice", option.UserLimitOptions{DownloadMbps: 8})
	conn := registry.WrapConn(context.Background(), "alice", discardConn{})

	limit := registry.lookup("alice")
	burst := limit.download.Load().Burst()
	payload := make([]byte, burst*2+1)

	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("write of %d bytes over a burst of %d failed: %v", len(payload), burst, err)
	}
	if n != len(payload) {
		t.Fatalf("short write: %d of %d", n, len(payload))
	}
}

func TestDownloadThroughputMatchesCap(t *testing.T) {
	const (
		capMbps = 80.0
		payload = 5 << 20 // 5 MiB, ~0.5 s at the cap
	)
	registry := newRegistryWith(t, "alice", option.UserLimitOptions{DownloadMbps: capMbps})
	conn := registry.WrapConn(context.Background(), "alice", discardConn{})

	buffer := make([]byte, 32*1024)
	started := time.Now()
	for written := 0; written < payload; written += len(buffer) {
		_, err := conn.Write(buffer)
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	elapsed := time.Since(started)

	measured := float64(payload) * 8 / 1000 / 1000 / elapsed.Seconds()
	// The first burst is free, so the measurement runs slightly fast; the
	// bound that matters is that it is nowhere near unthrottled.
	if measured > capMbps*1.35 {
		t.Fatalf("measured %.1f Mbit/s, cap is %.1f", measured, capMbps)
	}
	if measured < capMbps*0.5 {
		t.Fatalf("measured %.1f Mbit/s, far below the %.1f cap: throttling too hard", measured, capMbps)
	}
}

// Changing an existing cap retunes the bucket in place so that connections
// already established follow the new rate. Replacing the bucket instead would
// leave open connections running at the old rate until they reconnect.
func TestRetuneKeepsTheSameBucket(t *testing.T) {
	registry := newRegistryWith(t, "alice", option.UserLimitOptions{DownloadMbps: 8})
	before := registry.lookup("alice").download.Load()

	registry.Set("alice", option.UserLimitOptions{DownloadMbps: 32})
	after := registry.lookup("alice").download.Load()

	if before != after {
		t.Fatal("the bucket was replaced, so connections already open keep the old rate")
	}
	if measured := toMbps(after); measured < 31.9 || measured > 32.1 {
		t.Fatalf("retuned to %.2f Mbit/s, want 32", measured)
	}
}

// Lifting a cap has to reach connections that are already wrapped, which it
// does by emptying the buckets the wrapper holds a pointer to.
func TestDeleteLiftsCapOnOpenConnections(t *testing.T) {
	registry := newRegistryWith(t, "alice", option.UserLimitOptions{DownloadMbps: 1})
	conn := registry.WrapConn(context.Background(), "alice", discardConn{})

	registry.Delete("alice")

	// At 1 Mbit/s this would take about 8 seconds; uncapped it is instant.
	payload := make([]byte, 1<<20)
	started := time.Now()
	_, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("still throttled after the cap was deleted: write took %s", elapsed)
	}
}

// Zero in both directions is how the API expresses "no cap", and it has to
// land in the same state as never having had one.
func TestSetZeroRemovesTheEntry(t *testing.T) {
	registry := newRegistryWith(t, "alice", option.UserLimitOptions{DownloadMbps: 8})

	registry.Set("alice", option.UserLimitOptions{})

	if limit := registry.lookup("alice"); limit != nil {
		t.Fatal("a zeroed cap left an entry behind")
	}
	if got := len(registry.All()); got != 0 {
		t.Fatalf("All() reports %d caps, want 0", got)
	}
}

func TestOnlyTheCappedDirectionIsWrapped(t *testing.T) {
	registry := newRegistryWith(t, "alice", option.UserLimitOptions{DownloadMbps: 8})
	limit := registry.lookup("alice")

	if limit.download.Load() == nil {
		t.Fatal("download cap was not installed")
	}
	if limit.upload.Load() != nil {
		t.Fatal("an upload bucket was installed from a download-only cap")
	}
}

// The relay reaches a connection through WriteBuffer far more often than
// through Write, so that path has to be throttled too — it is a separate
// method and an easy one to leave unwrapped.
func TestWriteBufferIsThrottled(t *testing.T) {
	registry := newRegistryWith(t, "alice", option.UserLimitOptions{DownloadMbps: 1})
	conn := registry.WrapConn(context.Background(), "alice", discardConn{})

	extended, isExtended := conn.(N.ExtendedConn)
	if !isExtended {
		t.Fatalf("the wrapper is not an ExtendedConn: %T", conn)
	}
	burst := registry.lookup("alice").download.Load().Burst()

	// Spend the free burst first, then time a write that has to wait.
	err := extended.WriteBuffer(buf.As(make([]byte, burst)))
	if err != nil {
		t.Fatalf("priming write: %v", err)
	}
	started := time.Now()
	err = extended.WriteBuffer(buf.As(make([]byte, burst)))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if elapsed := time.Since(started); elapsed < 100*time.Millisecond {
		t.Fatalf("WriteBuffer returned in %s: the cap is not applied on that path", elapsed)
	}
}
