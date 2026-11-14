package clashapi

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/log"
)

func newTestStats(t *testing.T) *UserStatsManager {
	t.Helper()
	m, err := newUserStatsManager(log.NewNOPFactory().NewLogger("stats"), filepath.Join(t.TempDir(), "user_stats.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.db.Close() })
	return m
}

// The per-inbound table is what tells a transport that carries sustained
// streams from one where only requests get through.
func TestInboundAccountingSeparatesBulkFromRequests(t *testing.T) {
	m := newTestStats(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.ConnectionFinished("alice", "vless-reality-in", 500, 20_000) // requests
		}()
	}
	wg.Wait()
	m.ConnectionFinished("alice", "vless-xhttp-in", 1_000, 50<<20) // a stream
	m.ConnectionFinished("bob", "vless-xhttp-in", 1_000, 3<<20)
	m.ConnectionFinished("bob", "", 10, 10) // no inbound recorded
	m.flush()
	// A second flush with nothing new must not change the rows, and a later
	// smaller connection must not lower the day's maximum.
	m.flush()
	m.ConnectionFinished("alice", "vless-xhttp-in", 0, 1<<20)
	m.flush()

	stats, err := m.GetInboundDaily(1)
	if err != nil {
		t.Fatal(err)
	}
	byInbound := map[string]InboundDailyStats{}
	for _, s := range stats {
		byInbound[s.Inbound] = s
	}
	reality, xhttp := byInbound["vless-reality-in"], byInbound["vless-xhttp-in"]
	if reality.ConnCount != 50 || reality.Download != 50*20_000 || reality.BulkConns != 0 || reality.MaxDownload != 20_000 || reality.Users != 1 {
		t.Fatalf("reality = %+v", reality)
	}
	if xhttp.ConnCount != 3 || xhttp.BulkConns != 3 || xhttp.MaxDownload != 50<<20 || xhttp.Users != 2 {
		t.Fatalf("xhttp = %+v", xhttp)
	}
	if byInbound["-"].ConnCount != 1 {
		t.Fatalf("a connection without an inbound was lost: %+v", stats)
	}

	if err := m.ResetUser("alice"); err != nil {
		t.Fatal(err)
	}
	stats, _ = m.GetInboundDaily(1)
	for _, s := range stats {
		if s.Inbound == "vless-reality-in" {
			t.Fatalf("a reset user's rows survived: %+v", s)
		}
	}
}

// The per-user breakdown keeps each person's inbounds apart, busiest first,
// which is what tells the transport someone rides from the ones their client
// only probes.
func TestUserInboundDailyKeepsUsersApart(t *testing.T) {
	m := newTestStats(t)
	m.ConnectionFinished("alice", "vless-reality-in", 2_000, 40<<20)
	m.ConnectionFinished("alice", "tuic-in", 300, 500)
	m.ConnectionFinished("alice", "tuic-in", 300, 500)
	m.ConnectionFinished("bob", "wg-wdtt-in", 1_000, 2<<20)
	m.flush()

	rows, err := m.GetUserInboundDaily(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].User != "alice" || rows[0].Inbound != "vless-reality-in" || rows[0].BulkConns != 1 {
		t.Fatalf("busiest row first, got %+v", rows[0])
	}
	if rows[1].User != "bob" || rows[1].Inbound != "wg-wdtt-in" {
		t.Fatalf("second row = %+v", rows[1])
	}
	if tuic := rows[2]; tuic.User != "alice" || tuic.ConnCount != 2 || tuic.Download != 1_000 || tuic.BulkConns != 0 {
		t.Fatalf("probe-only inbound = %+v", tuic)
	}
}
