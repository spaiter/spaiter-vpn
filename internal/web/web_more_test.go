package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/control"
)

type funcControl func(control.Request) (control.Response, error)

func (f funcControl) Do(_ context.Context, r control.Request) (control.Response, error) { return f(r) }

func TestKeysRoundTripAndRefuseUnsafeFiles(t *testing.T) {
	text, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := NewKey()
	if text == other {
		t.Fatal("two keys were identical")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := LoadKey(path)
	if err != nil || len(key) != KeyLen {
		t.Fatalf("LoadKey = %d bytes, %v", len(key), err)
	}

	if _, err := LoadKey(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing key file loaded")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); err == nil || !strings.Contains(err.Error(), "accessible to others") {
		t.Errorf("world-readable key: %v", err)
	}
	for name, body := range map[string]string{"not hex": "zz\n", "short": "abcd\n", "empty": ""} {
		bad := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(bad, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKey(bad); err == nil || !strings.Contains(err.Error(), "hex key") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Mode checks come before reads: an unreadable file with safe bits fails on read.
	if os.Geteuid() != 0 {
		unreadable := filepath.Join(dir, "unreadable")
		if err := os.WriteFile(unreadable, []byte(text), 0o000); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKey(unreadable); err == nil {
			t.Error("an unreadable key loaded")
		}
	}
}

func TestTokensRejectForgeryAndGarbage(t *testing.T) {
	key := make([]byte, KeyLen)
	now := time.Unix(1_800_000_000, 0)
	token, err := LoginToken(key, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyToken(key, token, now); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyToken(key, "!!not-base64!!", now); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("garbage: %v", err)
	}
	if _, err := verifyToken(key, token[:len(token)-4], now); err == nil {
		t.Error("truncated token accepted")
	}
	otherKey := make([]byte, KeyLen)
	otherKey[0] = 1
	if _, err := verifyToken(otherKey, token, now); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Errorf("wrong key: %v", err)
	}
	if _, err := verifyToken(key, token, now.Add(2*time.Minute)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired: %v", err)
	}
}

func TestTheServerClockDefaultsToTheRealOne(t *testing.T) {
	s := &Server{}
	if d := time.Since(s.now()); d < 0 || d > time.Minute {
		t.Errorf("now() is %v off", d)
	}
}

func TestLogoutEndsTheSessionAndClearsTheCookie(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.login()
	w := h.do("POST", "/logout", url.Values{"csrf": {csrf}}, cookie, "https://vpn.example")
	if w.Code != http.StatusOK {
		t.Fatalf("logout = %d", w.Code)
	}
	cleared := w.Result().Cookies()
	if len(cleared) != 1 || cleared[0].MaxAge >= 0 || cleared[0].Value != "" {
		t.Errorf("cookie after logout = %#v", cleared)
	}
	if w := h.do("GET", "/", nil, cookie, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("the old session still works: %d", w.Code)
	}
}

func TestCancelForwardsTheTicketAndGoesHome(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.login()
	h.ctl.requests = nil
	w := h.do("POST", "/cancel", url.Values{"csrf": {csrf}, "ticket": {"abc"}}, cookie, "")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("cancel = %d %q", w.Code, w.Header().Get("Location"))
	}
	if len(h.ctl.requests) != 1 || h.ctl.requests[0].Operation != control.OpCancel || h.ctl.requests[0].Ticket != "abc" {
		t.Errorf("requests = %#v", h.ctl.requests)
	}
}

func TestEveryChangeKindBecomesATypedRequest(t *testing.T) {
	cases := []struct {
		name  string
		form  url.Values
		check func(control.Change) bool
	}{
		{"enable", url.Values{"kind": {"settings"}, "enable": {"awg-in"}}, func(c control.Change) bool { return len(c.Enable) == 1 && c.Enable[0] == "awg-in" }},
		{"disable", url.Values{"kind": {"settings"}, "disable": {" awg-in "}}, func(c control.Change) bool { return len(c.Disable) == 1 && c.Disable[0] == "awg-in" }},
		{"image", url.Values{"kind": {"image"}, "image": {" repo/core:2 "}}, func(c control.Change) bool { return c.Image == "repo/core:2" }},
		{"rotate", url.Values{"kind": {"rotate"}, "users": {"alice, bob carol"}}, func(c control.Change) bool { return strings.Join(c.Users, "|") == "alice|bob|carol" }},
		{"rollback latest", url.Values{"kind": {"rollback"}}, func(c control.Change) bool { return c.Generation == 0 }},
		{"rollback to", url.Values{"kind": {"rollback"}, "generation": {"4"}}, func(c control.Change) bool { return c.Generation == 4 }},
	}
	for _, c := range cases {
		change, err := changeFromForm(c.form)
		if err != nil || !c.check(change) {
			t.Errorf("%s: %+v, %v", c.name, change, err)
		}
	}
	for name, form := range map[string]url.Values{
		"zero port":      {"kind": {"settings"}, "protocol": {"awg-in"}, "port": {"0"}},
		"text port":      {"kind": {"settings"}, "protocol": {"awg-in"}, "port": {"http"}},
		"bad generation": {"kind": {"rollback"}, "generation": {"-1"}},
	} {
		if _, err := changeFromForm(form); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func newFuncHarness(t *testing.T, f funcControl) (*harness, *http.Cookie, string) {
	t.Helper()
	h := newHarness(t)
	h.server.Control = f
	cookie, csrf := h.login()
	return h, cookie, csrf
}

func TestADaemonThatRefusesOrBreaksIsReportedNotHidden(t *testing.T) {
	refuse := funcControl(func(r control.Request) (control.Response, error) {
		switch r.Operation {
		case control.OpStatus:
			return control.Response{OK: true, Result: []byte(`{}`)}, nil
		}
		return control.Response{OK: false, Error: "plan refused: drift", Output: "diff here"}, nil
	})
	h, cookie, csrf := newFuncHarness(t, refuse)
	w := h.do("POST", "/prepare", url.Values{"csrf": {csrf}, "kind": {"image"}, "image": {"repo/core:2"}}, cookie, "")
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "plan refused: drift") || !strings.Contains(w.Body.String(), "diff here") {
		t.Errorf("prepare refused = %d %s", w.Code, w.Body)
	}
	w = h.do("POST", "/commit", url.Values{"csrf": {csrf}, "ticket": {"t"}}, cookie, "")
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "plan refused: drift") {
		t.Errorf("commit refused = %d %s", w.Code, w.Body)
	}

	broken := funcControl(func(r control.Request) (control.Response, error) {
		if r.Operation == control.OpStatus {
			return control.Response{OK: true, Result: []byte(`{}`)}, nil
		}
		return control.Response{}, errors.New("socket closed")
	})
	h, cookie, csrf = newFuncHarness(t, broken)
	w = h.do("POST", "/prepare", url.Values{"csrf": {csrf}, "kind": {"rollback"}}, cookie, "")
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "socket closed") {
		t.Errorf("prepare broken = %d %s", w.Code, w.Body)
	}
}

func TestATicketlessPlanIsABadGateway(t *testing.T) {
	noTicket := funcControl(func(r control.Request) (control.Response, error) {
		if r.Operation == control.OpPrepare {
			return control.Response{OK: true, Result: []byte(`{"id":""}`)}, nil
		}
		return control.Response{OK: true, Result: []byte(`{}`)}, nil
	})
	h, cookie, csrf := newFuncHarness(t, noTicket)
	w := h.do("POST", "/prepare", url.Values{"csrf": {csrf}, "kind": {"rollback"}}, cookie, "")
	if w.Code != http.StatusBadGateway {
		t.Errorf("= %d %s", w.Code, w.Body)
	}
}

func TestHomeShowsTheDaemonErrorInsteadOfEmptyStatus(t *testing.T) {
	down := funcControl(func(control.Request) (control.Response, error) {
		return control.Response{}, errors.New("daemon unreachable")
	})
	h := newHarness(t)
	h.server.Control = down
	token, _ := LoginToken(h.server.Key, h.now.Add(time.Minute))
	cookie := h.do("GET", "/login?token="+token, nil, nil, "").Result().Cookies()[0]
	w := h.do("GET", "/", nil, cookie, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "daemon unreachable") {
		t.Errorf("home = %d %s", w.Code, w.Body)
	}
}
