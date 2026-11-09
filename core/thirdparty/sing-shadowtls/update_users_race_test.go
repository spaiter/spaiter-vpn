package shadowtls

import (
	"sync"
	"sync/atomic"
	"testing"
)

// The user slice is read during every ClientHello verification while
// UpdateUsers may be replacing it; the atomic swap must make that safe.
func TestUpdateUsersConcurrentWithRead(t *testing.T) {
	s := &Service{}
	s.UpdateUsers([]User{{Name: "alice", Password: "pw-a"}})

	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			for range s.users.Load() {
			}
		}
	}()

	for i := 0; i < 5000; i++ {
		s.UpdateUsers([]User{{Name: "alice", Password: "pw-a"}, {Name: "bob", Password: "pw-b"}})
		s.UpdateUsers([]User{{Name: "alice", Password: "pw-a"}})
	}
	stop.Store(true)
	wg.Wait()

	if len(s.users.Load()) != 1 {
		t.Fatalf("expected the final store to win, got %d", len(s.users.Load()))
	}
}
