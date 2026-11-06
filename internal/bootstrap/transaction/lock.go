package transaction

import (
	"fmt"
	"os"
)

// Guard is an exclusive hold on the bootstrap lock that outlives a single file
// transaction.
//
// Apply has to hold the lock from discovery through the final receipt, not just
// across the writes: between re-planning and committing it reads host state,
// generates credentials and starts containers, and a second apply interleaved
// with any of that would race on the same deployment. Manager.Start locks only
// for its own duration, which is right for a one-shot caller and wrong for the
// apply engine, so the engine takes a Guard first and starts its transaction
// inside it.
type Guard struct {
	manager  *Manager
	lock     *os.File
	released bool
}

// Lock acquires the bootstrap lock and completes any interrupted transaction
// before returning, so a caller never plans against a half-applied deployment.
func (m *Manager) Lock() (*Guard, error) {
	if err := m.prepare(); err != nil {
		return nil, err
	}
	lock, err := m.acquire()
	if err != nil {
		return nil, err
	}
	if err := m.recoverLocked(); err != nil {
		releaseLock(lock)
		return nil, err
	}
	return &Guard{manager: m, lock: lock}, nil
}

// Start opens a file transaction under the already-held lock. The transaction
// does not release the lock when it commits or rolls back; the guard does.
func (g *Guard) Start(changes []Change) (*Transaction, error) {
	if g.released {
		return nil, fmt.Errorf("bootstrap lock has already been released")
	}
	return g.manager.startLocked(g.lock, false, changes)
}

// Release unlocks. It is safe to call more than once so callers can defer it
// and still release early on the success path.
func (g *Guard) Release() error {
	if g.released {
		return nil
	}
	g.released = true
	return releaseLock(g.lock)
}
