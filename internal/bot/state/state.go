// Package state is the bot's on-disk state.
//
// Every format here is the one bot.py already writes, read verbatim. That is
// the whole constraint: the live deployment has users whose keys, peers, WARP
// accounts and subscription tokens exist only in these files, and a format
// change means re-provisioning people who did nothing wrong.
//
// One deliberate difference from the Python: a file that fails to parse is an
// error here, not an empty default. bot.py's _read_json swallowed every
// exception and returned {}, which is what made a half-written subs.json read
// as "no subscriptions at all" and the next save persist that -- destroying
// every token. Atomic writes are still used, but as a second line of defence
// rather than the only one.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Store is the bot's data directory.
type Store struct {
	dir string

	// One mutex per file family that is read-modify-written. The subscription
	// registry and the relay's password file are both shared with another
	// reader -- the HTTP handler and the relay shim -- so a lost update there
	// is a user losing access, not a cosmetic race.
	subsMu   sync.Mutex
	vkMu     sync.Mutex
	relayMu  sync.Mutex
	peersMu  sync.Mutex
	accessMu sync.Mutex
}

// New opens a data directory, creating it and the subdirectories the bot
// writes into.
func New(dir string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("state: no data directory")
	}
	for _, sub := range []string{"", "awg", "warp", "wdtt", filepath.Join("wdtt", "subs-cache")} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return nil, fmt.Errorf("state: create %s: %w", filepath.Join(dir, sub), err)
		}
	}
	return &Store{dir: dir}, nil
}

// Dir is the data directory.
func (s *Store) Dir() string { return s.dir }

// Path joins a path inside the data directory.
func (s *Store) Path(parts ...string) string {
	return filepath.Join(append([]string{s.dir}, parts...)...)
}

// Touch creates or updates a marker file. The bot has no Docker socket: asking
// for a reload means touching a file something privileged watches.
func (s *Store) Touch(name, content string) error {
	path := s.Path(name)
	if content == "" {
		content = time.Now().UTC().Format(time.RFC3339)
	}
	return writeAtomic(path, []byte(content+"\n"), 0o644)
}

// MarkerTime reports when a marker was last touched, and whether it exists.
func (s *Store) MarkerTime(name string) (time.Time, bool) {
	info, err := os.Stat(s.Path(name))
	if err != nil {
		return time.Time{}, false
	}
	return info.ModTime(), true
}

// ReadMarker returns a marker's contents, trimmed, and whether it exists.
//
// The contents are a short reason written by whichever host unit touched it,
// which ends up in the message a subscriber reads, so it is bounded here rather
// than trusted: a marker is a file anything on the host can write to.
func (s *Store) ReadMarker(name string) (string, bool, error) {
	data, err := os.ReadFile(s.Path(name))
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("state: read marker %s: %w", name, err)
	}
	reason := strings.TrimSpace(string(data))
	if len(reason) > MarkerReasonLimit {
		reason = reason[:MarkerReasonLimit]
	}
	return reason, true, nil
}

// MarkerReasonLimit bounds how much of a marker's contents is repeated back to
// a user.
const MarkerReasonLimit = 80

// Remove deletes a file inside the data directory. A missing file is not an
// error: consuming a marker that is already gone is the normal race.
func (s *Store) Remove(parts ...string) error {
	err := os.Remove(s.Path(parts...))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// readJSON decodes a file into v. A missing file leaves v untouched and
// reports false, so callers can tell "nothing yet" from "something is wrong"
// -- the distinction bot.py's _read_json threw away.
func readJSON(path string, v any) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("state: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, fmt.Errorf("state: parse %s: %w", path, err)
	}
	return true, nil
}

// writeJSON renders v and replaces the file atomically.
func writeJSON(path string, v any, perm os.FileMode) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("state: marshal for %s: %w", path, err)
	}
	return writeAtomic(path, data, perm)
}

// writeAtomic writes through a temporary file in the same directory and
// renames it into place, so a concurrent reader sees either the old file or
// the new one and never a truncated mixture.
func writeAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("state: temp file beside %s: %w", path, err)
	}
	name := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(name) // no-op once the rename succeeded
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("state: write %s: %w", name, err)
	}
	// CreateTemp makes the file 0600; the readers of these files are other
	// processes, so the mode has to be set explicitly rather than inherited.
	if err := tmp.Chmod(perm); err != nil {
		return fmt.Errorf("state: chmod %s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("state: sync %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("state: close %s: %w", name, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("state: rename onto %s: %w", path, err)
	}
	return nil
}

// Now is the timestamp format these files use for values the bot creates.
//
// Existing values are passed through as strings rather than parsed and
// re-rendered: the files on disk mix "Z" and "+00:00", and normalising them
// would rewrite every user's record to no purpose.
func Now() string { return time.Now().UTC().Format(time.RFC3339) }
