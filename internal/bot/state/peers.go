package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Peer is a WireGuard peer the bot provisioned: the client's half of the key
// pair plus the tunnel address the server assigned it.
type Peer struct {
	Priv string `json:"priv"`
	Pub  string `json:"pub"`
	IP   string `json:"ip"`
}

// peerFile is where a peer is stored for a given endpoint.
//
// The name depends on the tag, and that is not cosmetic: a user has a separate
// peer on awg-in, awg3-in, wg-masque-in and wg-wdtt-in, with different keys and
// different addresses. One file per user would have them overwrite each other.
// awg-in is unsuffixed for the same reason it always was -- it is what the
// existing files on disk are called.
func peerFile(uid, tag string) string {
	if tag == "awg-in" {
		return uid + ".json"
	}
	return uid + "-" + tag + ".json"
}

// Peer reads a provisioned peer. found is false when the user has none yet.
func (s *Store) Peer(uid, tag string) (Peer, bool, error) {
	var p Peer
	found, err := readJSON(s.Path("awg", peerFile(uid, tag)), &p)
	return p, found, err
}

// SetPeer records a provisioned peer.
func (s *Store) SetPeer(uid, tag string, p Peer) error {
	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	// 0600: this is the client's private key.
	return writeJSON(s.Path("awg", peerFile(uid, tag)), p, 0o600)
}

// WARPAccount is a registered Cloudflare MASQUE account. Kept as the raw
// object the registering core produced: it is handed back to a client
// verbatim, and re-describing its eleven fields here would only create a
// second definition to keep in step.
type WARPAccount json.RawMessage

// WARPAccount reads a cached account. Registration is slow and creates state
// at Cloudflare, so the cache is what keeps it a one-time cost per user.
func (s *Store) WARPAccount(uid string) (WARPAccount, bool, error) {
	var raw json.RawMessage
	found, err := readJSON(s.Path("warp", uid+".json"), &raw)
	if err != nil || !found {
		return nil, found, err
	}
	// An account without a private key is not usable; treat it as absent so
	// the caller registers rather than handing out something broken.
	var probe struct {
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, false, fmt.Errorf("state: parse warp account %s: %w", uid, err)
	}
	if probe.PrivateKey == "" {
		return nil, false, nil
	}
	return WARPAccount(raw), true, nil
}

// SetWARPAccount caches a freshly registered account.
func (s *Store) SetWARPAccount(uid string, account WARPAccount) error {
	return writeAtomic(s.Path("warp", uid+".json"), account, 0o600)
}

// WDTTPassword is the per-user secret for the WG-over-VK relay.
type WDTTPassword struct {
	Password string `json:"password"`
}

// WDTTPassword reads a user's relay password.
func (s *Store) WDTTPassword(uid string) (string, bool, error) {
	var p WDTTPassword
	found, err := readJSON(s.Path("wdtt", uid+".json"), &p)
	if err != nil || !found {
		return "", found, err
	}
	return p.Password, p.Password != "", nil
}

// SetWDTTPassword records it.
func (s *Store) SetWDTTPassword(uid, password string) error {
	return writeJSON(s.Path("wdtt", uid+".json"), WDTTPassword{Password: password}, 0o600)
}

// RelayPasswords is the relay shim's config file, which the bot writes and the
// shim watches.
//
// Modelled as raw JSON at both levels on purpose. The file holds fields that
// belong to the shim and not to us -- its own bot token, its device bindings,
// and per-password byte counters it updates as traffic flows. Rewriting the
// file from a struct that knows only about wg_priv/wg_ip would silently erase
// all of that. So: read, change the entries we own, write everything else back
// untouched.
type RelayPasswords struct {
	root    map[string]json.RawMessage
	entries map[string]map[string]json.RawMessage
}

// RelayEntry is the part of a password entry the bot owns.
type RelayEntry struct {
	MaxDevices int    `json:"max_devices"`
	WGPriv     string `json:"wg_priv"`
	WGIP       string `json:"wg_ip"`
}

// UpdateRelayPasswords applies mutate to the shim's password file, preserving
// every field it does not touch.
func (s *Store) UpdateRelayPasswords(path string, mutate func(*RelayPasswords) error) error {
	s.relayMu.Lock()
	defer s.relayMu.Unlock()

	// The directory is the relay's config mount, so its absence is a deployment
	// fault rather than a first run. Creating it would put the passwords
	// somewhere the relay is not reading and report success for a user who
	// cannot connect, so it is named instead.
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		return fmt.Errorf("state: the relay config directory for %s is not there, "+
			"so its passwords cannot be written: %w", path, err)
	}

	rp := &RelayPasswords{
		root:    map[string]json.RawMessage{},
		entries: map[string]map[string]json.RawMessage{},
	}
	if _, err := readJSON(path, &rp.root); err != nil {
		return err
	}
	if raw, ok := rp.root["passwords"]; ok {
		if err := json.Unmarshal(raw, &rp.entries); err != nil {
			return fmt.Errorf("state: parse passwords in %s: %w", path, err)
		}
	}

	if err := mutate(rp); err != nil {
		return err
	}

	encoded, err := json.Marshal(rp.entries)
	if err != nil {
		return fmt.Errorf("state: marshal passwords for %s: %w", path, err)
	}
	rp.root["passwords"] = encoded
	data, err := json.Marshal(rp.root)
	if err != nil {
		return fmt.Errorf("state: marshal %s: %w", path, err)
	}
	return writeShared(path, data)
}

// writeShared replaces a file in a directory the bot may not write. A bot
// running as its own account can rewrite passwords.json, which it owns, but
// cannot create the temporary file an atomic rename needs beside it; the
// relay's own saves are in place too, and it rereads the file only when the
// marker the bot touches afterwards tells it to.
func writeShared(path string, data []byte) error {
	err := writeAtomic(path, data, 0o600)
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		return err
	}
	file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if openErr != nil {
		return fmt.Errorf("state: rewrite %s in place: %w", path, openErr)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("state: rewrite %s in place: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// Set adds or updates one password entry, keeping any fields the shim owns on
// an entry that already exists.
func (rp *RelayPasswords) Set(password string, entry RelayEntry) error {
	existing := rp.entries[password]
	if existing == nil {
		existing = map[string]json.RawMessage{}
	}
	fields := map[string]any{
		"max_devices": entry.MaxDevices,
		"wg_priv":     entry.WGPriv,
		"wg_ip":       entry.WGIP,
	}
	for key, value := range fields {
		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("state: marshal %s: %w", key, err)
		}
		existing[key] = encoded
	}
	rp.entries[password] = existing
	return nil
}

// Has reports whether a password is already present.
func (rp *RelayPasswords) Has(password string) bool {
	_, ok := rp.entries[password]
	return ok
}

// Passwords lists the configured passwords.
func (rp *RelayPasswords) Passwords() []string {
	out := make([]string, 0, len(rp.entries))
	for password := range rp.entries {
		out = append(out, password)
	}
	return out
}
