package state

import (
	"fmt"
	"os"
	"testing"
)

// TestAgainstLiveDataDir reads a real deployment's data directory and reports
// anything these decoders cannot make sense of.
//
// Skipped unless BOT_LIVE_DATA_DIR is set, because it depends on a host:
//
//	BOT_LIVE_DATA_DIR=~/appdata/vpn-bot/data \
//	  go test -run TestAgainstLiveDataDir ./internal/bot/state/
//
// Hand-written fixtures prove the formats as understood; this proves them as
// they actually are, which is the thing that decides whether a live user gets
// re-provisioned. Worth re-running at cutover.
//
// Read-only on purpose: the store is built directly rather than through New,
// which would create directories in someone's live data.
func TestAgainstLiveDataDir(t *testing.T) {
	dir := os.Getenv("BOT_LIVE_DATA_DIR")
	if dir == "" {
		t.Skip("set BOT_LIVE_DATA_DIR to check a real deployment")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("BOT_LIVE_DATA_DIR is not readable: %v", err)
	}
	s := &Store{dir: dir}

	admins, err := s.Admins()
	if err != nil {
		t.Errorf("admins.json: %v", err)
	}
	whitelist, err := s.Whitelist()
	if err != nil {
		t.Errorf("whitelist.json: %v", err)
	}
	pending, err := s.Pending()
	if err != nil {
		t.Errorf("pending.json: %v", err)
	}
	users, err := s.Users()
	if err != nil {
		t.Fatalf("users.json: %v", err)
	}
	if _, err := s.APKCache(); err != nil {
		t.Errorf("apk_cache.json: %v", err)
	}
	subs, err := s.Subscriptions()
	if err != nil {
		t.Fatalf("subs.json: %v", err)
	}
	hashes, err := s.VKHashes()
	if err != nil {
		t.Errorf("vk_hashes.json: %v", err)
	}
	live, err := s.LiveVKHashes(nil)
	if err != nil {
		t.Errorf("live hashes: %v", err)
	}

	t.Logf("admins=%d whitelist=%d pending=%d users=%d subs=%d hashes=%d live=%d",
		len(admins), len(whitelist), len(pending), len(users), len(subs), len(hashes), len(live))

	for key, u := range users {
		uid := fmt.Sprint(u.ID)
		if uid != key {
			t.Errorf("users.json key %q holds id %d", key, u.ID)
		}
		for _, tag := range []string{"awg-in", "awg3-in", "wg-masque-in", "wg-wdtt-in"} {
			peer, found, err := s.Peer(uid, tag)
			if err != nil {
				t.Errorf("peer %s/%s: %v", uid, tag, err)
				continue
			}
			if found && (peer.IP == "" || peer.Priv == "" || peer.Pub == "") {
				t.Errorf("peer %s/%s decoded incomplete: %+v", uid, tag, peer)
			}
		}
		if _, _, err := s.WARPAccount(uid); err != nil {
			t.Errorf("warp account %s: %v", uid, err)
		}
		if _, _, err := s.WDTTPassword(uid); err != nil {
			t.Errorf("wdtt password %s: %v", uid, err)
		}
	}

	// Every subscription must point at a user that exists and have a cached
	// bundle to serve, or a poll would 404 for someone holding a valid link.
	for token, sub := range subs {
		if _, ok := users[sub.UID]; !ok {
			t.Errorf("subscription %s… belongs to unknown uid %q", token[:6], sub.UID)
		}
		if _, found, err := s.BundleCache(token); err != nil {
			t.Errorf("bundle cache %s…: %v", token[:6], err)
		} else if !found {
			t.Logf("subscription %s… has no cached bundle yet", token[:6])
		}
	}
}
