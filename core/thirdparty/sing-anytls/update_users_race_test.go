package anytls

import (
	"sync"
	"sync/atomic"
	"testing"
)

// Upstream assigned the map directly, which races with the auth lookup in
// NewConnection — in Go that is a "concurrent map read and map write" crash,
// not merely a detector warning. Run both sides hard under -race.
func TestUpdateUsersConcurrentWithLookup(t *testing.T) {
	s := &Service{}
	s.UpdateUsers([]User{{Name: "alice", Password: "pw-a"}})

	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var key [32]byte
		for !stop.Load() {
			// Mirrors the lookup NewConnection performs per handshake.
			_, _ = s.users.Load()[key]
		}
	}()

	for i := 0; i < 5000; i++ {
		s.UpdateUsers([]User{{Name: "alice", Password: "pw-a"}, {Name: "bob", Password: "pw-b"}})
		s.UpdateUsers([]User{{Name: "alice", Password: "pw-a"}})
	}
	stop.Store(true)
	wg.Wait()

	if len(s.users.Load()) != 1 {
		t.Fatalf("expected the final store to win, got %d users", len(s.users.Load()))
	}
}
