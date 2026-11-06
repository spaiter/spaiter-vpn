package ui

import (
	"os"
	"path/filepath"
	"testing"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

// newVKCodeUI builds a UI whose data dir is a temp dir, with the vk-relogin
// directory already made, so the code-delivery paths have somewhere to write.
func newVKCodeUI(t *testing.T) *UI {
	t.Helper()
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var cfg botcfg.Config
	cfg.Paths.DataDir = t.TempDir()
	if err := os.MkdirAll(cfg.Paths.VKReloginDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	return &UI{cfg: cfg, store: store, access: NewAccess(store, quiet()), log: quiet()}
}

func setStatus(t *testing.T, u *UI, status string) {
	t.Helper()
	if err := os.WriteFile(u.cfg.Paths.VKReloginStatus(), []byte(status+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSixDigits(t *testing.T) {
	cases := map[string]string{
		"123456":   "123456",
		" 123456 ": "123456",
		"12345":    "", // too short
		"1234567":  "", // too long
		"12 34 56": "", // spaced, not a bare code
		"12345a":   "", // not all digits
		"code 123": "",
		"":         "",
	}
	for in, want := range cases {
		if got := sixDigits(in); got != want {
			t.Errorf("sixDigits(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDeliverCodeWritesWhenAwaiting(t *testing.T) {
	u := newVKCodeUI(t)
	setStatus(t, u, "awaiting-code")

	if msg := u.deliverVKReloginCode("123456"); msg != "vk_code_accepted" {
		t.Fatalf("message = %q, want vk_code_accepted", msg)
	}
	got, err := os.ReadFile(u.cfg.Paths.VKReloginCode())
	if err != nil {
		t.Fatalf("code file: %v", err)
	}
	if string(got) != "123456\n" {
		t.Fatalf("code file = %q, want \"123456\\n\"", got)
	}
	// No temp file left behind.
	if _, err := os.Stat(u.cfg.Paths.VKReloginCode() + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("a .tmp file was left behind")
	}
}

func TestDeliverCodeRefusesWhenNotAwaiting(t *testing.T) {
	for _, status := range []string{"starting", "verifying", "ok:11", ""} {
		u := newVKCodeUI(t)
		if status != "" {
			setStatus(t, u, status)
		}
		if msg := u.deliverVKReloginCode("123456"); msg != "vk_code_not_waiting" {
			t.Errorf("status %q: message = %q, want vk_code_not_waiting", status, msg)
		}
		if _, err := os.Stat(u.cfg.Paths.VKReloginCode()); !os.IsNotExist(err) {
			t.Errorf("status %q: a code file was written when none was wanted", status)
		}
	}
}

func TestDeliverCodeRejectsABadCodeBeforeTouchingTheFile(t *testing.T) {
	u := newVKCodeUI(t)
	setStatus(t, u, "awaiting-code")
	for _, bad := range []string{"12345", "1234567", "abcdef", "12 34 56"} {
		if msg := u.deliverVKReloginCode(bad); msg != "vk_code_bad" {
			t.Errorf("code %q: message = %q, want vk_code_bad", bad, msg)
		}
	}
	if _, err := os.Stat(u.cfg.Paths.VKReloginCode()); !os.IsNotExist(err) {
		t.Errorf("a bad code should not write the file")
	}
}

func TestAwaitingCodeReadsTheStatusFile(t *testing.T) {
	u := newVKCodeUI(t)
	if u.vkReloginAwaitingCode() {
		t.Fatal("no status file should mean not awaiting")
	}
	setStatus(t, u, "awaiting-code")
	if !u.vkReloginAwaitingCode() {
		t.Fatal("awaiting-code status should be read as awaiting")
	}
	// A path that is a directory, not a file, must not panic or report awaiting.
	_ = os.Remove(u.cfg.Paths.VKReloginStatus())
	if err := os.MkdirAll(filepath.Clean(u.cfg.Paths.VKReloginStatus()), 0o700); err == nil {
		if u.vkReloginAwaitingCode() {
			t.Error("a directory in place of the status file should not be awaiting")
		}
	}
}
