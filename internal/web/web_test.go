package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/control"
)

type fakeControl struct{ requests []control.Request }

func (f *fakeControl) Do(_ context.Context, request control.Request) (control.Response, error) {
	f.requests = append(f.requests, request)
	switch request.Operation {
	case control.OpStatus:
		result, _ := json.Marshal(map[string]any{"generation": 7, "tier": "a", "image": "repo/core:1"})
		return control.Response{OK: true, Result: result}, nil
	case control.OpPrepare:
		result, _ := json.Marshal(map[string]any{"id": "0123456789abcdef0123456789abcdef", "plan": map[string]any{
			"mode": "migrate", "actions": []map[string]any{{"id": "management-apply", "mutates": true, "summary": "apply the <diff>"}},
		}})
		return control.Response{OK: true, Result: result}, nil
	case control.OpCommit:
		result, _ := json.Marshal(map[string]string{"Transaction": "tx-1"})
		return control.Response{OK: true, Result: result, Output: "applied"}, nil
	}
	return control.Response{OK: true, Result: json.RawMessage(`[]`)}, nil
}

type harness struct {
	t      *testing.T
	server *Server
	ctl    *fakeControl
	h      http.Handler
	now    time.Time
}

func newHarness(t *testing.T) *harness {
	key := make([]byte, KeyLen)
	h := &harness{t: t, ctl: &fakeControl{}, now: time.Unix(1_800_000_000, 0)}
	h.server = &Server{Control: h.ctl, Key: key, Now: func() time.Time { return h.now }}
	h.h = h.server.Handler()
	return h
}

func (h *harness) do(method, target string, form url.Values, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, target, body)
	r.Host = "vpn.example"
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, r)
	return w
}

func (h *harness) login() (*http.Cookie, string) {
	h.t.Helper()
	token, err := LoginToken(h.server.Key, h.now.Add(10*time.Minute))
	if err != nil {
		h.t.Fatal(err)
	}
	w := h.do("GET", "/login?token="+token, nil, nil, "")
	if w.Code != http.StatusSeeOther {
		h.t.Fatalf("login = %d %s", w.Code, w.Body)
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		h.t.Fatalf("session cookie = %#v", cookie)
	}
	home := h.do("GET", "/", nil, cookie, "")
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(home.Body.String())
	if home.Code != http.StatusOK || csrf == nil {
		h.t.Fatalf("home = %d", home.Code)
	}
	return cookie, csrf[1]
}

func TestALoginLinkWorksOnceAndOnlyBeforeItExpires(t *testing.T) {
	h := newHarness(t)
	token, _ := LoginToken(h.server.Key, h.now.Add(time.Minute))
	if w := h.do("GET", "/login?token="+token, nil, nil, ""); w.Code != http.StatusSeeOther {
		t.Fatalf("first use = %d", w.Code)
	}
	if w := h.do("GET", "/login?token="+token, nil, nil, ""); w.Code != http.StatusForbidden {
		t.Fatalf("second use = %d", w.Code)
	}
	expired, _ := LoginToken(h.server.Key, h.now.Add(-time.Second))
	if w := h.do("GET", "/login?token="+expired, nil, nil, ""); w.Code != http.StatusForbidden {
		t.Fatalf("expired = %d", w.Code)
	}
	forged, _ := LoginToken([]byte("another key of thirty-two bytes!"), h.now.Add(time.Minute))
	if w := h.do("GET", "/login?token="+forged, nil, nil, ""); w.Code != http.StatusForbidden {
		t.Fatalf("forged = %d", w.Code)
	}
}

func TestNothingIsServedOrChangedWithoutASession(t *testing.T) {
	h := newHarness(t)
	if w := h.do("GET", "/", nil, nil, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("home without session = %d", w.Code)
	}
	if w := h.do("POST", "/commit", url.Values{"ticket": {"x"}}, nil, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("commit without session = %d", w.Code)
	}
	if len(h.ctl.requests) != 0 {
		t.Fatalf("the daemon was reached: %#v", h.ctl.requests)
	}
}

func TestFormsNeedTheirCSRFTokenAndTheSameOrigin(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.login()
	h.ctl.requests = nil
	change := url.Values{"kind": {"rollback"}}
	if w := h.do("POST", "/prepare", change, cookie, ""); w.Code != http.StatusForbidden {
		t.Fatalf("no csrf = %d", w.Code)
	}
	change.Set("csrf", csrf)
	if w := h.do("POST", "/prepare", change, cookie, "https://evil.example"); w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin = %d", w.Code)
	}
	if len(h.ctl.requests) != 0 {
		t.Fatalf("a rejected form reached the daemon: %#v", h.ctl.requests)
	}
}

func TestAChangeIsPlannedFirstAndCommittedByItsTicket(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.login()
	h.ctl.requests = nil
	w := h.do("POST", "/prepare", url.Values{"csrf": {csrf}, "kind": {"settings"}, "protocol": {"awg-in"}, "port": {"10870"}}, cookie, "https://vpn.example")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "0123456789abcdef0123456789abcdef") {
		t.Fatalf("plan page = %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "<diff>") || !strings.Contains(w.Body.String(), "&lt;diff&gt;") {
		t.Fatal("plan text from the daemon was not escaped")
	}
	if len(h.ctl.requests) != 1 || h.ctl.requests[0].Change.Ports["awg-in"] != 10870 {
		t.Fatalf("prepare request = %#v", h.ctl.requests)
	}
	w = h.do("POST", "/commit", url.Values{"csrf": {csrf}, "ticket": {"0123456789abcdef0123456789abcdef"}}, cookie, "https://vpn.example")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "tx-1") {
		t.Fatalf("commit page = %d %s", w.Code, w.Body)
	}
	last := h.ctl.requests[len(h.ctl.requests)-1]
	if last.Operation != control.OpCommit || last.Ticket != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("commit request = %#v", last)
	}
}

func TestMalformedChangesNeverReachTheDaemon(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.login()
	h.ctl.requests = nil
	for _, form := range []url.Values{
		{"kind": {"settings"}},
		{"kind": {"settings"}, "protocol": {"awg-in"}, "port": {"99999"}},
		{"kind": {"image"}},
		{"kind": {"rotate"}},
		{"kind": {"exec"}},
	} {
		form.Set("csrf", csrf)
		if w := h.do("POST", "/prepare", form, cookie, ""); w.Code != http.StatusBadRequest {
			t.Errorf("%v = %d", form, w.Code)
		}
	}
	if len(h.ctl.requests) != 0 {
		t.Fatalf("malformed changes reached the daemon: %#v", h.ctl.requests)
	}
}

func TestSessionsExpire(t *testing.T) {
	h := newHarness(t)
	cookie, _ := h.login()
	h.now = h.now.Add(9 * time.Hour)
	if w := h.do("GET", "/", nil, cookie, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired session = %d", w.Code)
	}
}
