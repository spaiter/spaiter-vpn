package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func put(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestReadsTheLiveFormats uses the shapes taken off the running deployment,
// verbatim. If any of these stops decoding, a live user's provisioning is
// invisible to the Go bot and it would re-provision them.
func TestReadsTheLiveFormats(t *testing.T) {
	s := newStore(t)

	put(t, s.Path("admins.json"), `[100000001]`)
	put(t, s.Path("whitelist.json"), `[100000002, 100000003, 100000004]`)
	put(t, s.Path("pending.json"), `{}`)
	put(t, s.Path("users.json"),
		`{"100000001": {"id": 100000001, "username": "alice", "first_name": "Alice",`+
			`"last_name": "Example", "last_seen": "2026-10-31T21:21:21Z",`+
			`"created": "2026-07-23T11:50:44Z"}}`)
	put(t, s.Path("apk_cache.json"),
		`{"key": "12345678-1700000000", "file_id": "BQACAgIAAxkDAAIBexample"}`)
	// awg-in is unsuffixed; every other endpoint carries its tag.
	put(t, s.Path("awg", "100000005.json"),
		`{"priv": "qNCLJtyJ8HsvbPRD85o1wiCTNqcndih3ryfNmbFtQRM=",`+
			`"pub": "amyDwZNtcK3IXJ5S8bq6MoHUM219OcO+dK46PqbQgZ0=", "ip": "10.10.0.5"}`)
	put(t, s.Path("awg", "100000005-awg3-in.json"),
		`{"priv": "p", "pub": "q", "ip": "10.40.0.3"}`)
	put(t, s.Path("wdtt", "100000001.json"), `{"password": "wdttPassword0001"}`)
	put(t, s.Path("wdtt", "subs.json"),
		`{"subToken01": {"uid": "100000001", "created": "2026-08-15T19:01:00+00:00",`+
			`"last_hash": "0a1b2c3d"}}`)
	// Note the absent by/by_name: pool entries published by the holder service
	// have no submitter, so those fields must be optional.
	put(t, s.Path("wdtt", "vk_hashes.json"),
		`{"vkHashExampl": {"added": "2026-08-13T21:53:38+00:00", "status": "ok",`+
			`"checked": "2026-11-02T21:13:25+00:00", "detail": "TURN urls=2"}}`)

	admins, err := s.Admins()
	if err != nil || len(admins) != 1 || admins[0] != 100000001 {
		t.Fatalf("Admins = %v, %v", admins, err)
	}
	wl, err := s.Whitelist()
	if err != nil || len(wl) != 3 {
		t.Fatalf("Whitelist = %v, %v", wl, err)
	}
	users, err := s.Users()
	if err != nil {
		t.Fatalf("Users: %v", err)
	}
	if u := users["100000001"]; u.Username != "alice" || u.Created != "2026-07-23T11:50:44Z" {
		t.Fatalf("user = %+v", u)
	}
	apk, err := s.APKCache()
	if err != nil || apk.Key != "12345678-1700000000" {
		t.Fatalf("APKCache = %+v, %v", apk, err)
	}

	peer, found, err := s.Peer("100000005", "awg-in")
	if err != nil || !found || peer.IP != "10.10.0.5" {
		t.Fatalf("awg-in peer = %+v, %v, %v", peer, found, err)
	}
	peer3, found, err := s.Peer("100000005", "awg3-in")
	if err != nil || !found || peer3.IP != "10.40.0.3" {
		t.Fatalf("awg3-in peer = %+v, %v, %v", peer3, found, err)
	}

	pw, found, err := s.WDTTPassword("100000001")
	if err != nil || !found || pw != "wdttPassword0001" {
		t.Fatalf("WDTTPassword = %q, %v, %v", pw, found, err)
	}

	subs, err := s.Subscriptions()
	if err != nil || subs["subToken01"].UID != "100000001" {
		t.Fatalf("Subscriptions = %+v, %v", subs, err)
	}
	if subs["subToken01"].Created != "2026-08-15T19:01:00+00:00" {
		t.Error("the +00:00 offset on disk must survive unparsed")
	}

	live, err := s.LiveVKHashes(nil)
	if err != nil || len(live) != 1 || live[0] != "vkHashExampl" {
		t.Fatalf("LiveVKHashes = %v, %v", live, err)
	}
}

// TestPeerFileNamingIsPerEndpoint is the invariant behind four separate files
// per user: one file would have the endpoints overwrite each other's keys.
func TestPeerFileNamingIsPerEndpoint(t *testing.T) {
	s := newStore(t)
	for _, tag := range []string{"awg-in", "awg3-in", "wg-masque-in", "wg-wdtt-in"} {
		if err := s.SetPeer("u1", tag, Peer{Priv: "priv-" + tag, Pub: "pub-" + tag, IP: tag}); err != nil {
			t.Fatalf("SetPeer %s: %v", tag, err)
		}
	}
	for _, tag := range []string{"awg-in", "awg3-in", "wg-masque-in", "wg-wdtt-in"} {
		p, found, err := s.Peer("u1", tag)
		if err != nil || !found {
			t.Fatalf("Peer %s: %v %v", tag, found, err)
		}
		if p.Priv != "priv-"+tag {
			t.Errorf("%s holds %q: the endpoints share a file", tag, p.Priv)
		}
	}
	// And the on-disk name is the one the Python wrote, or the existing files
	// would be invisible.
	if _, err := os.Stat(s.Path("awg", "u1.json")); err != nil {
		t.Errorf("awg-in must stay unsuffixed: %v", err)
	}
	if _, err := os.Stat(s.Path("awg", "u1-awg3-in.json")); err != nil {
		t.Errorf("awg3-in must carry its tag: %v", err)
	}
}

// TestRelayPasswordsPreserveFieldsWeDoNotOwn is the one that would have cost
// real damage. The shim's file carries its own bot token, device bindings and
// byte counters; rewriting it from a struct that knows only wg_priv/wg_ip
// would erase them.
func TestRelayPasswordsPreserveFieldsWeDoNotOwn(t *testing.T) {
	s := newStore(t)
	path := filepath.Join(t.TempDir(), "passwords.json")
	put(t, path, `{
	  "admin_id": 100000001,
	  "bot_token": "the-relay-own-token",
	  "devices": {"dev-1": {"seen": 7}},
	  "main_password": "",
	  "passwords": {
	    "existing-pw": {
	      "device_id": "d", "device_ids": null, "max_devices": 1,
	      "expires_at": 0, "down_bytes": 1234, "up_bytes": 567,
	      "wg_priv": "old-priv", "wg_ip": "10.30.0.3"
	    }
	  }
	}`)

	err := s.UpdateRelayPasswords(path, func(rp *RelayPasswords) error {
		if !rp.Has("existing-pw") {
			t.Error("the existing password was not read")
		}
		if err := rp.Set("new-pw", RelayEntry{MaxDevices: 1, WGPriv: "p", WGIP: "10.30.0.9"}); err != nil {
			return err
		}
		// Updating the entry we own must not drop the shim's counters on it.
		return rp.Set("existing-pw", RelayEntry{MaxDevices: 2, WGPriv: "new-priv", WGIP: "10.30.0.3"})
	})
	if err != nil {
		t.Fatalf("UpdateRelayPasswords: %v", err)
	}

	var got map[string]json.RawMessage
	if _, err := readJSON(path, &got); err != nil {
		t.Fatalf("reread: %v", err)
	}
	for _, key := range []string{"admin_id", "bot_token", "devices", "main_password"} {
		if _, ok := got[key]; !ok {
			t.Errorf("top-level %q was erased", key)
		}
	}
	if string(got["bot_token"]) != `"the-relay-own-token"` {
		t.Errorf("bot_token = %s", got["bot_token"])
	}

	var entries map[string]map[string]json.RawMessage
	if err := json.Unmarshal(got["passwords"], &entries); err != nil {
		t.Fatalf("decode passwords: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %v, want both", entries)
	}
	existing := entries["existing-pw"]
	if string(existing["down_bytes"]) != "1234" || string(existing["up_bytes"]) != "567" {
		t.Errorf("the shim's counters were lost: %v", existing)
	}
	if string(existing["device_id"]) != `"d"` {
		t.Errorf("device binding was lost: %v", existing["device_id"])
	}
	// What we do own was updated.
	if string(existing["wg_priv"]) != `"new-priv"` || string(existing["max_devices"]) != "2" {
		t.Errorf("our own fields were not updated: %v", existing)
	}
}

// TestCorruptFileIsAnError is the difference from the Python, and the reason
// subs.json once lost every token: a half-written file read as {} and the next
// save made that permanent.
func TestCorruptFileIsAnError(t *testing.T) {
	s := newStore(t)
	put(t, s.Path("wdtt", "subs.json"), `{"token": {"uid": "1"`) // truncated

	if _, err := s.Subscriptions(); err == nil {
		t.Fatal("a truncated registry was read as empty")
	} else if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error should say it could not parse: %v", err)
	}

	// And a mutation refuses rather than overwriting what it could not read.
	err := s.UpdateSubscriptions(func(Subscriptions) error {
		t.Error("the mutator ran against unreadable state")
		return nil
	})
	if err == nil {
		t.Fatal("UpdateSubscriptions proceeded over a corrupt file")
	}
}

func TestMissingFileIsNotAnError(t *testing.T) {
	s := newStore(t)
	if subs, err := s.Subscriptions(); err != nil || len(subs) != 0 {
		t.Fatalf("absent registry = %v, %v; want empty and no error", subs, err)
	}
	if _, found, err := s.Peer("nobody", "awg-in"); err != nil || found {
		t.Fatalf("absent peer = %v, %v", found, err)
	}
}

// TestSubscriptionTokenIsStablePerUser keeps a handed-out link working.
func TestSubscriptionTokenIsStablePerUser(t *testing.T) {
	s := newStore(t)
	first, err := s.SubscriptionToken("u1")
	if err != nil {
		t.Fatalf("SubscriptionToken: %v", err)
	}
	again, err := s.SubscriptionToken("u1")
	if err != nil {
		t.Fatalf("SubscriptionToken: %v", err)
	}
	if first != again {
		t.Errorf("token changed: %q then %q", first, again)
	}
	other, err := s.SubscriptionToken("u2")
	if err != nil {
		t.Fatalf("SubscriptionToken: %v", err)
	}
	if other == first {
		t.Error("two users got the same token")
	}
	if len(first) < 30 {
		t.Errorf("token %q is too short to be unguessable", first)
	}
}

// TestUpdateSubscriptionsRereads covers the race the Python comment describes:
// a token issued while a refresh was running must survive the refresh's write.
func TestUpdateSubscriptionsRereads(t *testing.T) {
	s := newStore(t)
	token, err := s.SubscriptionToken("u1")
	if err != nil {
		t.Fatalf("SubscriptionToken: %v", err)
	}

	// Simulate the refresh loop: it took its snapshot, then someone else got a
	// subscription, and only then does it write back.
	snapshot, err := s.Subscriptions()
	if err != nil {
		t.Fatalf("Subscriptions: %v", err)
	}
	newcomer, err := s.SubscriptionToken("u2")
	if err != nil {
		t.Fatalf("SubscriptionToken: %v", err)
	}

	err = s.UpdateSubscriptions(func(fresh Subscriptions) error {
		if len(fresh) != 2 {
			t.Errorf("the mutator saw %d subscriptions, want the re-read state", len(fresh))
		}
		// Write only what is ours, for a token that still exists.
		sub := fresh[token]
		sub.LastHash = "h1"
		fresh[token] = sub
		return nil
	})
	if err != nil {
		t.Fatalf("UpdateSubscriptions: %v", err)
	}
	_ = snapshot

	after, err := s.Subscriptions()
	if err != nil {
		t.Fatalf("Subscriptions: %v", err)
	}
	if _, ok := after[newcomer]; !ok {
		t.Error("the subscription issued mid-refresh was erased")
	}
	if after[token].LastHash != "h1" {
		t.Error("last_hash was not recorded")
	}
	if after[token].UID != "u1" {
		t.Error("the mutation lost the uid")
	}
}

func TestBundleCacheRoundTripAndTraversal(t *testing.T) {
	s := newStore(t)
	if err := s.SetBundleCache("tok-1", []byte(`{"outbounds":[]}`)); err != nil {
		t.Fatalf("SetBundleCache: %v", err)
	}
	data, found, err := s.BundleCache("tok-1")
	if err != nil || !found || string(data) != `{"outbounds":[]}` {
		t.Fatalf("BundleCache = %q %v %v", data, found, err)
	}
	if _, found, err := s.BundleCache("absent"); err != nil || found {
		t.Fatalf("absent cache = %v %v", found, err)
	}

	// A token arrives from an HTTP path. Whatever it contains, it must not
	// address a file outside the cache directory.
	if err := s.SetBundleCache("../../escaped", []byte(`x`)); err != nil {
		t.Fatalf("SetBundleCache: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir(), "..", "escaped.json")); err == nil {
		t.Error("a traversal token wrote outside the data directory")
	}
}

// TestWriteLeavesNoTemporaries matters because the subscription server reads
// this directory, and a stray .subs.json.* would be served or confuse a glob.
func TestWriteLeavesNoTemporaries(t *testing.T) {
	s := newStore(t)
	if _, err := s.SubscriptionToken("u1"); err != nil {
		t.Fatalf("SubscriptionToken: %v", err)
	}
	entries, err := os.ReadDir(s.Path("wdtt"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("left a temporary behind: %s", e.Name())
		}
	}
}

func TestPermissionsSeparateKeysFromTokens(t *testing.T) {
	s := newStore(t)
	if err := s.SetPeer("u1", "awg-in", Peer{Priv: "secret"}); err != nil {
		t.Fatalf("SetPeer: %v", err)
	}
	if _, err := s.SubscriptionToken("u1"); err != nil {
		t.Fatalf("SubscriptionToken: %v", err)
	}
	for path, want := range map[string]os.FileMode{
		s.Path("awg", "u1.json"):    0o600, // a private key
		s.Path("wdtt", "subs.json"): 0o644, // read by the subscription server
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s is %o, want %o", filepath.Base(path), got, want)
		}
	}
}

func TestRegisterKeepsCreationDate(t *testing.T) {
	s := newStore(t)
	if err := s.Register(User{ID: 1, Username: "first"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	users, _ := s.Users()
	created := users["1"].Created
	if created == "" {
		t.Fatal("no creation date was set")
	}

	if err := s.Register(User{ID: 1, Username: "renamed"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	users, _ = s.Users()
	if users["1"].Created != created {
		t.Error("re-registering moved the creation date")
	}
	if users["1"].Username != "renamed" {
		t.Error("the identity was not refreshed")
	}
	if users["1"].LastSeen == "" {
		t.Error("last_seen was not set")
	}
}

func TestAccessListsAreIdempotent(t *testing.T) {
	s := newStore(t)
	for range 3 {
		if err := s.Allow(42); err != nil {
			t.Fatalf("Allow: %v", err)
		}
	}
	wl, _ := s.Whitelist()
	if len(wl) != 1 {
		t.Errorf("whitelist = %v, want one entry", wl)
	}
	if err := s.Deny(42); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if wl, _ := s.Whitelist(); len(wl) != 0 {
		t.Errorf("whitelist = %v after Deny", wl)
	}

	if err := s.AddPending(7); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	pending, _ := s.Pending()
	stamp := pending["7"]
	if err := s.AddPending(7); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	pending, _ = s.Pending()
	if pending["7"] != stamp {
		t.Error("asking twice moved the queue timestamp")
	}
	if err := s.PopPending(7); err != nil {
		t.Fatalf("PopPending: %v", err)
	}
	if pending, _ := s.Pending(); len(pending) != 0 {
		t.Errorf("pending = %v after pop", pending)
	}
}

// TestConcurrentTokenIssuanceLosesNobody is why the registry has a mutex: two
// users pressing the button at once must both end up with a token.
func TestConcurrentTokenIssuanceLosesNobody(t *testing.T) {
	s := newStore(t)
	const n = 16
	var wg sync.WaitGroup
	tokens := make([]string, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tokens[i], errs[i] = s.SubscriptionToken(string(rune('a' + i)))
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}
	subs, err := s.Subscriptions()
	if err != nil {
		t.Fatalf("Subscriptions: %v", err)
	}
	if len(subs) != n {
		t.Errorf("registry holds %d of %d tokens", len(subs), n)
	}
}

func TestWARPAccountWithoutKeyCountsAsAbsent(t *testing.T) {
	s := newStore(t)
	put(t, s.Path("warp", "u1.json"), `{"id": "x"}`)
	if _, found, err := s.WARPAccount("u1"); err != nil || found {
		t.Errorf("an account with no private key should read as absent: %v %v", found, err)
	}

	put(t, s.Path("warp", "u2.json"), `{"private_key": "k", "ipv4": "172.16.0.2"}`)
	account, found, err := s.WARPAccount("u2")
	if err != nil || !found {
		t.Fatalf("WARPAccount = %v %v", found, err)
	}
	// Handed back verbatim: it goes into a client config unchanged.
	if !strings.Contains(string(account), `"ipv4": "172.16.0.2"`) {
		t.Errorf("account was reshaped: %s", account)
	}
}

func TestMarkers(t *testing.T) {
	s := newStore(t)
	if _, ok := s.MarkerTime(".notify-subs"); ok {
		t.Error("marker exists before being touched")
	}
	if err := s.Touch(".notify-subs", "because"); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	if _, ok := s.MarkerTime(".notify-subs"); !ok {
		t.Error("marker was not created")
	}
	data, err := os.ReadFile(s.Path(".notify-subs"))
	if err != nil || !strings.Contains(string(data), "because") {
		t.Fatalf("marker content = %q, %v", data, err)
	}
	if err := s.Remove(".notify-subs"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := s.Remove(".notify-subs"); err != nil {
		t.Errorf("removing an absent marker should be fine: %v", err)
	}
}

// TestRelayPasswordsAreRewrittenInADirectoryTheBotCannotWrite: a bot running
// as its own account owns passwords.json but may not create files beside it.
func TestRelayPasswordsAreRewrittenInADirectoryTheBotCannotWrite(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "relay")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "passwords.json")
	if err := os.WriteFile(path, []byte(`{"bot_token":"keep","passwords":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	err = store.UpdateRelayPasswords(path, func(db *RelayPasswords) error {
		return db.Set("pw", RelayEntry{MaxDevices: 1, WGPriv: "k", WGIP: "10.30.0.3"})
	})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"pw"`) || !strings.Contains(string(data), `"keep"`) {
		t.Fatalf("passwords.json = %s", data)
	}
}
