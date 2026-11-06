package vk

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeConn is an owner socket whose Hold blocks until the test drops it.
type fakeConn struct {
	drop   chan struct{}
	closed atomic.Bool
}

func (c *fakeConn) Hold(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.drop:
		return fmt.Errorf("dropped")
	}
}
func (c *fakeConn) Close() error { c.closed.Store(true); return nil }

// fakeSource hands out a distinct link per Open and remembers the conns so a
// test can drop them. It can be told to fail Open a set number of times.
type fakeSource struct {
	mu      sync.Mutex
	opens   int
	conns   []*fakeConn
	failErr error
	failN   int
}

func (s *fakeSource) Open(ctx context.Context) (string, CallConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failN > 0 {
		s.failN--
		return "", nil, s.failErr
	}
	s.opens++
	c := &fakeConn{drop: make(chan struct{})}
	s.conns = append(s.conns, c)
	return fmt.Sprintf("link-%d", s.opens), c, nil
}

func (s *fakeSource) dropLast() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.conns) > 0 {
		close(s.conns[len(s.conns)-1].drop)
	}
}

// fakePub records the most recent published set.
type fakePub struct {
	mu    sync.Mutex
	last  []string
	calls int
}

func (p *fakePub) Publish(_ context.Context, live []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.last = append([]string(nil), live...)
	p.calls++
	return nil
}
func (p *fakePub) snapshot() ([]string, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.last...), p.calls
}

func eventually(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition never held: %s", msg)
}

func TestHolderHoldsNCallsAndPublishesThem(t *testing.T) {
	src := &fakeSource{}
	pub := &fakePub{}
	h := &Holder{Source: src, Pub: pub, N: 3, Log: quietVK()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)

	eventually(t, func() bool {
		live, _ := pub.snapshot()
		return len(live) == 3
	}, "three links should be published")
}

func TestHolderReopensAfterADrop(t *testing.T) {
	src := &fakeSource{}
	pub := &fakePub{}
	h := &Holder{Source: src, Pub: pub, N: 1, Log: quietVK(), ReopenPause: 10 * time.Millisecond, ReloginPause: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)

	eventually(t, func() bool { live, _ := pub.snapshot(); return len(live) == 1 }, "one link held")
	first, _ := pub.snapshot()

	src.dropLast()
	eventually(t, func() bool {
		live, _ := pub.snapshot()
		return len(live) == 1 && live[0] != first[0]
	}, "a dropped call should be replaced by a fresh one")

	src.mu.Lock()
	opens := src.opens
	src.mu.Unlock()
	if opens < 2 {
		t.Fatalf("expected a re-open after the drop, opens=%d", opens)
	}
}

func TestHolderRunsReloginWhenAccessTokenExpires(t *testing.T) {
	var reloginCalls atomic.Int32
	src := &fakeSource{failErr: ErrAccessTokenExpired, failN: 2}
	pub := &fakePub{}
	h := &Holder{
		Source: src, Pub: pub, N: 1, Log: quietVK(),
		Relogin:     func(ctx context.Context) error { reloginCalls.Add(1); return nil },
		ReopenPause: 10 * time.Millisecond, ReloginPause: 10 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)

	// The two failing opens each trigger a relogin, then the third succeeds.
	eventually(t, func() bool { live, _ := pub.snapshot(); return len(live) == 1 }, "recovers after relogin")
	if reloginCalls.Load() == 0 {
		t.Fatal("relogin was never run for a dead access token")
	}
}

func TestLiveSetDedupsAndSorts(t *testing.T) {
	h := &Holder{held: map[int]string{0: "b", 1: "a", 2: "a", 3: ""}}
	got := h.liveSet()
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("liveSet = %v, want [a b]", got)
	}
}

func quietVK() *slog.Logger { return slog.New(slog.DiscardHandler) }
