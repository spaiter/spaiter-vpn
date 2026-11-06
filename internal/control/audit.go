package control

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one audit record. It names who asked for what and what came of it;
// it never carries a credential, a plan body or engine output.
type Entry struct {
	Time        time.Time `json:"time"`
	Peer        Peer      `json:"peer"`
	Operation   Operation `json:"operation"`
	Change      string    `json:"change,omitempty"`
	Ticket      string    `json:"ticket,omitempty"`
	Transaction string    `json:"transaction,omitempty"`
	OK          bool      `json:"ok"`
	Error       string    `json:"error,omitempty"`
}

// Audit appends entries to a root-only JSON-lines file, synced per entry: a
// record written after the fact it records is worth little if a crash eats it.
type Audit struct {
	Path string
	Now  func() time.Time
	// Failed is called when an entry cannot be written; the daemon logs it.
	Failed func(error)

	mu sync.Mutex
}

func (a *Audit) Record(entry Entry) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	entry.Time = now().UTC()
	entry.OK = entry.Error == ""
	if err := a.append(entry); err != nil && a.Failed != nil {
		a.Failed(err)
	}
}

func (a *Audit) append(entry Entry) error {
	if err := os.MkdirAll(filepath.Dir(a.Path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(a.Path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}
	return file.Sync()
}
