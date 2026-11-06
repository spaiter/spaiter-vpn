package state

import (
	"slices"
	"strconv"
)

// User is one row of users.json. Timestamps stay strings: the file mixes "Z"
// and "+00:00", and re-rendering them would rewrite every record for nothing.
type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Created   string `json:"created,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
}

// Users is the registry, keyed by Telegram ID as a decimal string -- the shape
// json gives a dict keyed by a number.
type Users map[string]User

// Users reads the registry.
func (s *Store) Users() (Users, error) {
	out := Users{}
	_, err := readJSON(s.Path("users.json"), &out)
	return out, err
}

// Register records an interaction: it creates the row on first sight and
// updates last_seen afterwards, which is what bot.py does on every message.
func (s *Store) Register(u User) error {
	s.accessMu.Lock()
	defer s.accessMu.Unlock()

	users, err := s.Users()
	if err != nil {
		return err
	}
	key := strconv.FormatInt(u.ID, 10)
	existing, found := users[key]
	if found {
		// Identity can change in Telegram; the creation date cannot.
		u.Created = existing.Created
	}
	if u.Created == "" {
		u.Created = Now()
	}
	u.LastSeen = Now()
	users[key] = u
	return writeJSON(s.Path("users.json"), users, 0o644)
}

// Admins reads admins.json, a plain array of IDs.
func (s *Store) Admins() ([]int64, error) {
	var out []int64
	_, err := readJSON(s.Path("admins.json"), &out)
	return out, err
}

// AddAdmin appends an admin. Used for the bootstrap case, where the first
// person to speak to a bot with no admins becomes one.
func (s *Store) AddAdmin(id int64) error {
	s.accessMu.Lock()
	defer s.accessMu.Unlock()
	return s.appendID("admins.json", id)
}

// Whitelist reads the approved users.
func (s *Store) Whitelist() ([]int64, error) {
	var out []int64
	_, err := readJSON(s.Path("whitelist.json"), &out)
	return out, err
}

// Allow approves a user. Idempotent: approving twice is a double click, not an
// error.
func (s *Store) Allow(id int64) error {
	s.accessMu.Lock()
	defer s.accessMu.Unlock()
	return s.appendID("whitelist.json", id)
}

// Deny removes a user from the whitelist.
func (s *Store) Deny(id int64) error {
	s.accessMu.Lock()
	defer s.accessMu.Unlock()

	var ids []int64
	if _, err := readJSON(s.Path("whitelist.json"), &ids); err != nil {
		return err
	}
	ids = slices.DeleteFunc(ids, func(v int64) bool { return v == id })
	return writeJSON(s.Path("whitelist.json"), ids, 0o644)
}

func (s *Store) appendID(file string, id int64) error {
	var ids []int64
	if _, err := readJSON(s.Path(file), &ids); err != nil {
		return err
	}
	if slices.Contains(ids, id) {
		return nil
	}
	ids = append(ids, id)
	return writeJSON(s.Path(file), ids, 0o644)
}

// Pending is the approval queue: Telegram ID to the time it asked.
type Pending map[string]string

// Pending reads the queue.
func (s *Store) Pending() (Pending, error) {
	out := Pending{}
	_, err := readJSON(s.Path("pending.json"), &out)
	return out, err
}

// AddPending enqueues a request, keeping the original timestamp if the user
// asks again.
func (s *Store) AddPending(id int64) error {
	s.accessMu.Lock()
	defer s.accessMu.Unlock()

	pending, err := s.Pending()
	if err != nil {
		return err
	}
	key := strconv.FormatInt(id, 10)
	if _, exists := pending[key]; exists {
		return nil
	}
	pending[key] = Now()
	return writeJSON(s.Path("pending.json"), pending, 0o644)
}

// PopPending removes a request, whether it was approved or refused.
func (s *Store) PopPending(id int64) error {
	s.accessMu.Lock()
	defer s.accessMu.Unlock()

	pending, err := s.Pending()
	if err != nil {
		return err
	}
	delete(pending, strconv.FormatInt(id, 10))
	return writeJSON(s.Path("pending.json"), pending, 0o644)
}

// APKCache remembers the Telegram file_id of an already-uploaded APK, keyed by
// the file's size and mtime so a replaced file is noticed and re-uploaded.
type APKCache struct {
	Key    string `json:"key"`
	FileID string `json:"file_id"`
}

// APKCache reads the cache.
func (s *Store) APKCache() (APKCache, error) {
	var out APKCache
	_, err := readJSON(s.Path("apk_cache.json"), &out)
	return out, err
}

// SetAPKCache records an upload.
func (s *Store) SetAPKCache(c APKCache) error {
	return writeJSON(s.Path("apk_cache.json"), c, 0o644)
}
