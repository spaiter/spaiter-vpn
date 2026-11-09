package state

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

var claimShape = regexp.MustCompile(`^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}$`)

func TestClaimCodeAdoptsTheBotOnceAndIsStoredHashed(t *testing.T) {
	s := newStore(t)
	now := time.Now()
	code, err := s.IssueClaim(10*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if !claimShape.MatchString(code) {
		t.Fatalf("code %q has the wrong shape", code)
	}
	raw, _ := os.ReadFile(s.claimPath())
	if strings.Contains(string(raw), code) || strings.Contains(string(raw), strings.ReplaceAll(code, "-", "")) {
		t.Error("the claim file holds a usable code")
	}
	if info, _ := os.Stat(s.claimPath()); info.Mode().Perm() != 0o600 {
		t.Errorf("claim file is %v", info.Mode().Perm())
	}

	// Case and stray spaces are forgiven; the dashes are part of the code.
	ok, err := s.Claim(" "+strings.ToLower(code)+" ", 42, now)
	if err != nil || !ok {
		t.Fatalf("Claim = %v, %v", ok, err)
	}
	admins, _ := s.Admins()
	if !reflect.DeepEqual(admins, []int64{42}) {
		t.Errorf("admins = %v", admins)
	}
	if ok, _ := s.Claim(code, 43, now); ok {
		t.Error("a claim code worked twice")
	}
	if _, err := os.Stat(s.claimPath()); err == nil {
		t.Error("a used claim stayed on disk")
	}
}

func TestClaimIsDestroyedByGuessingOrTime(t *testing.T) {
	s := newStore(t)
	now := time.Now()
	if ok, err := s.Claim("ANY", 1, now); ok || err != nil {
		t.Errorf("no claim outstanding: %v %v", ok, err)
	}

	code, _ := s.IssueClaim(time.Minute, now)
	for i := 1; i < MaxClaimAttempts; i++ {
		if ok, err := s.Claim("WRONG-CODE-HERE", 1, now); ok || err != nil {
			t.Fatalf("guess %d: %v %v", i, ok, err)
		}
		var claim ClaimFile
		readJSON(s.claimPath(), &claim)
		if claim.Attempts != i {
			t.Errorf("after %d guesses the count is %d", i, claim.Attempts)
		}
	}
	// The last allowed guess burns the claim, so even the right code is too late.
	s.Claim("WRONG-CODE-HERE", 1, now)
	if _, err := os.Stat(s.claimPath()); err == nil {
		t.Error("the claim outlived its last allowed guess")
	}
	if ok, _ := s.Claim(code, 1, now); ok {
		t.Error("the right code worked after the claim was exhausted")
	}
	if admins, _ := s.Admins(); len(admins) != 0 {
		t.Errorf("admins = %v", admins)
	}

	code, _ = s.IssueClaim(time.Minute, now)
	if ok, _ := s.Claim(code, 1, now.Add(2*time.Minute)); ok {
		t.Error("an expired code worked")
	}
	if _, err := os.Stat(s.claimPath()); err == nil {
		t.Error("an expired claim stayed on disk")
	}

	// A new code replaces the old one.
	first, _ := s.IssueClaim(time.Minute, now)
	second, _ := s.IssueClaim(time.Minute, now)
	if first == second {
		t.Fatal("two codes were identical")
	}
	if ok, _ := s.Claim(first, 1, now); ok {
		t.Error("a replaced code worked")
	}
	// ...and the wrong guess above cost an attempt, not the claim.
	if ok, _ := s.Claim(second, 7, now); !ok {
		t.Error("the current code did not work")
	}
}

func TestClaimFileThatIsNotJSONIsAnError(t *testing.T) {
	s := newStore(t)
	put(t, s.claimPath(), "{")
	if _, err := s.Claim("X", 1, time.Now()); err == nil {
		t.Error("a corrupt claim file was ignored")
	}
}

func TestAdminsAndAPKCache(t *testing.T) {
	s := newStore(t)
	for range 2 {
		if err := s.AddAdmin(7); err != nil {
			t.Fatal(err)
		}
	}
	s.AddAdmin(8)
	if admins, _ := s.Admins(); !reflect.DeepEqual(admins, []int64{7, 8}) {
		t.Errorf("admins = %v", admins)
	}
	if got, err := s.APKCache(); err != nil || got != (APKCache{}) {
		t.Errorf("empty cache = %+v, %v", got, err)
	}
	want := APKCache{Key: "1.2.3:99", FileID: "BAAD"}
	if err := s.SetAPKCache(want); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.APKCache(); got != want {
		t.Errorf("cache = %+v", got)
	}
}

func TestWARPAndRelayPerUserSecretsArePrivate(t *testing.T) {
	s := newStore(t)
	if err := s.SetWARPAccount("5", WARPAccount(`{"private_key":"k","ipv4":"172.16.0.2"}`)); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.WARPAccount("5")
	if err != nil || !ok || !strings.Contains(string(got), `"ipv4"`) {
		t.Fatalf("WARPAccount = %s, %v, %v", got, ok, err)
	}
	if info, _ := os.Stat(s.Path("warp", "5.json")); info.Mode().Perm() != 0o600 {
		t.Errorf("warp account is %v", info.Mode().Perm())
	}
	put(t, s.Path("warp", "6.json"), "{")
	if _, _, err := s.WARPAccount("6"); err == nil {
		t.Error("a corrupt account was ignored")
	}

	if _, ok, _ := s.WDTTPassword("5"); ok {
		t.Error("a password before one was set")
	}
	if err := s.SetWDTTPassword("5", "hunter2hunter2"); err != nil {
		t.Fatal(err)
	}
	if pw, ok, err := s.WDTTPassword("5"); pw != "hunter2hunter2" || !ok || err != nil {
		t.Errorf("password = %q %v %v", pw, ok, err)
	}
	if info, _ := os.Stat(s.Path("wdtt", "5.json")); info.Mode().Perm() != 0o600 {
		t.Errorf("relay password is %v", info.Mode().Perm())
	}
	s.SetWDTTPassword("empty", "")
	if _, ok, _ := s.WDTTPassword("empty"); ok {
		t.Error("an empty password counted as set")
	}
}

func TestRelayPasswordsErrorsAndListing(t *testing.T) {
	s := newStore(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.json")

	// A missing config directory is named, not created.
	missing := filepath.Join(dir, "nope", "passwords.json")
	err := s.UpdateRelayPasswords(missing, func(*RelayPasswords) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "not there") {
		t.Errorf("missing dir: %v", err)
	}
	if _, statErr := os.Stat(filepath.Dir(missing)); statErr == nil {
		t.Error("the relay's directory was created")
	}

	put(t, path, `{"bot_token":"keep","passwords":{"old":{"wg_ip":"10.0.0.2","bytes":5}}}`)
	if err := s.UpdateRelayPasswords(path, func(rp *RelayPasswords) error {
		if !rp.Has("old") || rp.Has("new") {
			t.Error("Has is wrong")
		}
		if err := rp.Set("new", RelayEntry{MaxDevices: 3, WGPriv: "p", WGIP: "10.0.0.3"}); err != nil {
			return err
		}
		got := rp.Passwords()
		if len(got) != 2 {
			t.Errorf("Passwords = %v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A failing mutation writes nothing.
	before, _ := os.ReadFile(path)
	boom := errors.New("boom")
	if err := s.UpdateRelayPasswords(path, func(rp *RelayPasswords) error {
		rp.Set("never", RelayEntry{})
		return boom
	}); !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("a failed mutation changed the file")
	}

	put(t, path, `{"passwords": 5}`)
	if err := s.UpdateRelayPasswords(path, func(*RelayPasswords) error { return nil }); err == nil || !strings.Contains(err.Error(), "parse passwords") {
		t.Errorf("bad passwords: %v", err)
	}
	put(t, path, `[`)
	if err := s.UpdateRelayPasswords(path, func(*RelayPasswords) error { return nil }); err == nil {
		t.Error("a corrupt file was rewritten")
	}
}

func TestLiveVKHashesDropOnlyTheDeadAndFallBackStepwise(t *testing.T) {
	s := newStore(t)
	fallback := []string{"cfg-a", "cfg-b"}
	got, err := s.LiveVKHashes(fallback)
	if err != nil || !reflect.DeepEqual(got, fallback) {
		t.Fatalf("no file: %v, %v", got, err)
	}

	if err := s.UpdateVKHashes(func(h VKHashes) error {
		h["zzz"] = VKHash{Status: "ok"}
		h["aaa"] = VKHash{Status: "unknown"}
		h["mmm"] = VKHash{Status: "dead"}
		h["bbb"] = VKHash{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LiveVKHashes(fallback); !reflect.DeepEqual(got, []string{"aaa", "bbb", "zzz"}) {
		t.Errorf("live = %v", got)
	}

	// Everything dead: still handed out, rather than leaving a client with none.
	s.UpdateVKHashes(func(h VKHashes) error {
		for k := range h {
			h[k] = VKHash{Status: "dead"}
		}
		return nil
	})
	if got, _ := s.LiveVKHashes(fallback); !reflect.DeepEqual(got, []string{"aaa", "bbb", "mmm", "zzz"}) {
		t.Errorf("all dead = %v", got)
	}

	boom := errors.New("boom")
	if err := s.UpdateVKHashes(func(h VKHashes) error { h["x"] = VKHash{}; return boom }); !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
	if h, _ := s.VKHashes(); len(h) != 4 {
		t.Errorf("a failed update changed the pool: %v", h)
	}

	put(t, s.vkPath(), "[")
	if _, err := s.LiveVKHashes(nil); err == nil {
		t.Error("a corrupt pool was ignored")
	}
	if err := s.UpdateVKHashes(func(VKHashes) error { return nil }); err == nil {
		t.Error("a corrupt pool was rewritten")
	}
}

func TestSubscriptionBaseIsAbsentUntilRecorded(t *testing.T) {
	s := newStore(t)
	if _, found, err := s.SubscriptionBase(); found || err != nil {
		t.Errorf("before: %v %v", found, err)
	}
	want := SubscriptionBase{HostCF: "sub.example.com", HostDirect: "d.example.com:10866"}
	if err := s.SetSubscriptionBase(want); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.SubscriptionBase()
	if err != nil || !found || got != want {
		t.Errorf("after: %+v %v %v", got, found, err)
	}
	if info, _ := os.Stat(s.subscriptionBasePath()); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
}

func TestMarkerContentsAreBounded(t *testing.T) {
	s := newStore(t)
	if _, ok, err := s.ReadMarker(".m"); ok || err != nil {
		t.Errorf("absent: %v %v", ok, err)
	}
	s.Touch(".m", "  maintenance  ")
	if got, ok, _ := s.ReadMarker(".m"); !ok || got != "maintenance" {
		t.Errorf("trimmed = %q %v", got, ok)
	}
	s.Touch(".m", strings.Repeat("x", 500))
	if got, _, _ := s.ReadMarker(".m"); len(got) != MarkerReasonLimit {
		t.Errorf("len = %d", len(got))
	}
	// With no reason the marker still says when it was touched.
	s.Touch(".m", "")
	if got, _, _ := s.ReadMarker(".m"); !regexp.MustCompile(`^\d{4}-\d\d-\d\dT`).MatchString(got) {
		t.Errorf("default content = %q", got)
	}
	// A marker that is a directory is a read error, not "absent".
	os.MkdirAll(s.Path(".dir"), 0o755)
	if _, _, err := s.ReadMarker(".dir"); err == nil {
		t.Error("an unreadable marker was reported absent")
	}
}

func TestNewRefusesWhatItCannotUseAndTokensDiffer(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Error("an empty directory was accepted")
	}
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o600)
	if _, err := New(filepath.Join(file, "data")); err == nil {
		t.Error("a directory under a file was accepted")
	}
	a, _ := NewToken()
	b, _ := NewToken()
	if a == b || len(a) != 32 {
		t.Errorf("tokens %q %q", a, b)
	}
}

func TestWritesFailLoudlyWhenTheDirectoryIsGone(t *testing.T) {
	s := newStore(t)
	os.RemoveAll(s.Dir())
	if err := s.Touch(".m", "x"); err == nil {
		t.Error("Touch into a vanished directory succeeded")
	}
	if err := s.SetAPKCache(APKCache{Key: "k"}); err == nil {
		t.Error("SetAPKCache into a vanished directory succeeded")
	}
}
