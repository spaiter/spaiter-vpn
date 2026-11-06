package webapp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/clientcfg"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

const testToken = "123456:TEST-TOKEN-not-a-real-one"

func initFor(t *testing.T, id int64, at time.Time) string {
	t.Helper()
	user, _ := json.Marshal(map[string]any{"id": id, "first_name": "Test", "username": "tester"})
	v := url.Values{}
	v.Set("user", string(user))
	v.Set("auth_date", strconv.FormatInt(at.Unix(), 10))
	v.Set("query_id", "AAHdF6IQAAAAAN0XohDhrOrc")
	return Sign(v, testToken)
}

// TestVerifyAcceptsTelegramsSignatureAndNothingElse pins the check that is the
// whole of authentication: the published example from the Bot API docs must
// pass, a tampered field must fail, and an old signature must be refused.
func TestVerifyAcceptsTelegramsSignatureAndNothingElse(t *testing.T) {
	now := time.Now()
	data := initFor(t, 4242, now)
	user, err := Verify(data, testToken, now)
	if err != nil || user.ID != 4242 || user.Username != "tester" {
		t.Fatalf("a freshly signed string was refused: %v %+v", err, user)
	}

	// Values with reserved characters must survive the parse/sign round trip:
	// a name with a plus or a percent is signed as the parsed value.
	v := url.Values{}
	v.Set("user", `{"id":7,"first_name":"A+B %41 ü"}`)
	v.Set("auth_date", strconv.FormatInt(now.Unix(), 10))
	if _, err := Verify(Sign(v, testToken), testToken, now); err != nil {
		t.Errorf("reserved characters broke the signature: %v", err)
	}

	tampered := strings.Replace(data, "4242", "4243", 1)
	if _, err := Verify(tampered, testToken, now); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("a tampered user id passed: %v", err)
	}
	if _, err := Verify(data, "another:token", now); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("another bot's token passed: %v", err)
	}
	if _, err := Verify(initFor(t, 1, now.Add(-maxAge-time.Minute)), testToken, now); !errors.Is(err, ErrStale) {
		t.Errorf("a day-old signature passed: %v", err)
	}
	for _, bad := range []string{"", "hash=abc", "user=%7B%7D&hash=zz"} {
		if _, err := Verify(bad, testToken, now); err == nil {
			t.Errorf("%q passed", bad)
		}
	}
}

// --- fakes ---

type fakeMethods struct{ links map[string]string }

func (f fakeMethods) UserInbounds(context.Context) ([]manage.InboundRef, error) {
	return []manage.InboundRef{{Tag: "vless-reality-in", Type: "vless"}, {Tag: "shadowtls-in", Type: "shadowtls"}}, nil
}
func (f fakeMethods) OfferedEndpoints(context.Context) ([]clientcfg.Endpoint, error) {
	return []clientcfg.Endpoint{{Tag: "awg-in", Type: "awg"}}, nil
}
func (f fakeMethods) Link(_ context.Context, tag, uid string) (string, error) {
	return "vless://" + uid + "@example.invalid:443#" + tag, nil
}
func (f fakeMethods) JSONConfig(_ context.Context, tag, uid string) ([]byte, error) {
	return []byte(`{"outbounds":[{"tag":"` + tag + `","user":"` + uid + `"}]}`), nil
}
func (f fakeMethods) AWGConf(_ context.Context, tag, uid string) (string, error) {
	return "[Interface]\nPrivateKey = x\n# " + tag + " " + uid, nil
}
func (f fakeMethods) WARPChainConfig(context.Context, string) ([]byte, error) {
	return []byte(`{}`), nil
}
func (f fakeMethods) WDTTConfig(context.Context, string) ([]byte, error) { return []byte(`{}`), nil }
func (f fakeMethods) Bundle(context.Context, string, bool) ([]byte, error) {
	return []byte(`{"outbounds":[{},{},{}]}`), nil
}
func (f fakeMethods) Stats(_ context.Context, uid string) (manage.UserStat, bool, error) {
	if uid == "4242" {
		return manage.UserStat{User: uid, Upload: 10, Download: 20, ConnCount: 3, Active: 1}, true, nil
	}
	return manage.UserStat{}, false, nil
}
func (f fakeMethods) AllStats(context.Context) ([]manage.UserStat, error) {
	return []manage.UserStat{{User: "4242", Download: 20}}, nil
}
func (f fakeMethods) Accounts(context.Context) (map[string][]string, error) {
	return map[string][]string{"4242": {"vless-reality-in"}, "device": {"awg-in"}}, nil
}

type fakeAccess struct {
	admins, allowed, pending map[int64]bool
	registered               []int64
	decisions                []string
}

func (a *fakeAccess) IsAdmin(uid int64) bool   { return a.admins[uid] }
func (a *fakeAccess) IsAllowed(uid int64) bool { return a.allowed[uid] || a.admins[uid] }
func (a *fakeAccess) Register(u state.User)    { a.registered = append(a.registered, u.ID) }
func (a *fakeAccess) RequestAccess(uid int64)  { a.pending[uid] = true }
func (a *fakeAccess) Approve(uid int64) error {
	a.allowed[uid] = true
	delete(a.pending, uid)
	a.decisions = append(a.decisions, "approve")
	return nil
}
func (a *fakeAccess) Reject(uid int64) error {
	delete(a.pending, uid)
	a.decisions = append(a.decisions, "reject")
	return nil
}
func (a *fakeAccess) Revoke(uid int64) error {
	delete(a.allowed, uid)
	a.decisions = append(a.decisions, "revoke")
	return nil
}
func (a *fakeAccess) Pending() []int64 {
	var out []int64
	for id := range a.pending {
		out = append(out, id)
	}
	return out
}
func (a *fakeAccess) Whitelist() []int64 {
	var out []int64
	for id := range a.allowed {
		out = append(out, id)
	}
	return out
}
func (a *fakeAccess) DisplayName(uid int64) string { return "user " + strconv.FormatInt(uid, 10) }

type fakeStore struct {
	cache map[string][]byte
	subs  state.Subscriptions
}

func (s *fakeStore) SubscriptionToken(uid string) (string, error) { return "tok-" + uid, nil }
func (s *fakeStore) SetBundleCache(token string, b []byte) error  { s.cache[token] = b; return nil }
func (s *fakeStore) UpdateSubscriptions(fn func(state.Subscriptions) error) error {
	if s.subs == nil {
		s.subs = state.Subscriptions{}
	}
	return fn(s.subs)
}

func newServer(t *testing.T) (*Server, *fakeAccess, *fakeStore) {
	t.Helper()
	cfg := botcfg.ExampleConfig()
	access := &fakeAccess{
		admins: map[int64]bool{1: true}, allowed: map[int64]bool{4242: true}, pending: map[int64]bool{},
	}
	store := &fakeStore{cache: map[string][]byte{}}
	s := New(cfg, fakeMethods{}, access, store, testToken, slog.New(slog.DiscardHandler))
	return s, access, store
}

func call(t *testing.T, h http.Handler, method, path, init string, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if init != "" {
		req.Header.Set(initHeader, init)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec, out
}

// TestEveryAPICallNeedsTelegramsSignature: without a valid init string nothing
// but the page itself answers.
func TestEveryAPICallNeedsTelegramsSignature(t *testing.T) {
	s, _, _ := newServer(t)
	h := s.Handler()
	for _, path := range []string{"api/me", "api/methods", "api/admin/users", "api/admin/access"} {
		if rec, _ := call(t, h, "GET", Prefix+path, "", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without init data: %d", path, rec.Code)
		}
	}
	for _, path := range []string{"api/issue", "api/subscription", "api/qr", "api/access/request", "api/admin/decide"} {
		if rec, _ := call(t, h, "POST", Prefix+path, "garbage", "{}"); rec.Code != http.StatusUnauthorized {
			t.Errorf("POST %s with garbage init data: %d", path, rec.Code)
		}
	}
	rec, _ := call(t, h, "GET", Prefix, "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "telegram-web-app.js") {
		t.Errorf("the page did not serve: %d", rec.Code)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "telegram.org") {
		t.Errorf("CSP does not allow the Telegram bridge: %q", csp)
	}
	stale := initFor(t, 4242, time.Now().Add(-2*maxAge))
	if rec, _ := call(t, h, "GET", Prefix+"api/me", stale, ""); rec.Code != http.StatusForbidden {
		t.Errorf("a stale signature got %d, want 403", rec.Code)
	}
}

// TestAccessIsGatedLikeTheBot: a stranger sees who they are and can ask; a
// user gets methods; only an admin reaches the admin calls.
func TestAccessIsGatedLikeTheBot(t *testing.T) {
	s, access, _ := newServer(t)
	var asked []int64
	s.OnAccessRequest = func(_ context.Context, uid int64) { asked = append(asked, uid) }
	h := s.Handler()
	now := time.Now()
	stranger, user, admin := initFor(t, 99, now), initFor(t, 4242, now), initFor(t, 1, now)

	rec, me := call(t, h, "GET", Prefix+"api/me", stranger, "")
	if rec.Code != 200 || me["allowed"] != false || me["pending"] != false {
		t.Fatalf("stranger /me: %d %v", rec.Code, me)
	}
	if rec, _ := call(t, h, "GET", Prefix+"api/methods", stranger, ""); rec.Code != http.StatusForbidden {
		t.Errorf("a stranger listed methods: %d", rec.Code)
	}
	if rec, _ := call(t, h, "POST", Prefix+"api/access/request", stranger, ""); rec.Code != 200 || len(asked) != 1 || asked[0] != 99 {
		t.Errorf("the access request did not reach the admins: %d %v", rec.Code, asked)
	}
	if _, me := call(t, h, "GET", Prefix+"api/me", stranger, ""); me["pending"] != true {
		t.Errorf("the request is not shown as pending: %v", me)
	}
	if len(access.registered) == 0 || access.registered[0] != 99 {
		t.Errorf("the caller was not recorded in the registry: %v", access.registered)
	}

	rec, me = call(t, h, "GET", Prefix+"api/me", user, "")
	if rec.Code != 200 || me["allowed"] != true || me["admin"] != false || me["stats"] == nil {
		t.Fatalf("user /me: %d %v", rec.Code, me)
	}
	if rec, _ := call(t, h, "GET", Prefix+"api/admin/users", user, ""); rec.Code != http.StatusForbidden {
		t.Errorf("a user reached the admin list: %d", rec.Code)
	}
	if rec, _ := call(t, h, "POST", Prefix+"api/admin/decide", user, `{"id":99,"action":"approve"}`); rec.Code != http.StatusForbidden || len(access.decisions) != 0 {
		t.Errorf("a user approved someone: %d %v", rec.Code, access.decisions)
	}

	var told []int64
	s.Tell = func(_ context.Context, uid int64, _ string) { told = append(told, uid) }
	if rec, _ := call(t, h, "POST", Prefix+"api/admin/decide", admin, `{"id":99,"action":"approve"}`); rec.Code != 200 {
		t.Errorf("the admin could not approve: %d", rec.Code)
	}
	if !access.allowed[99] || len(told) != 1 || told[0] != 99 {
		t.Errorf("approval did not land or the user was not told: %v %v", access.allowed, told)
	}
	if rec, _ := call(t, h, "POST", Prefix+"api/admin/decide", admin, `{"id":99,"action":"explode"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown action was accepted: %d", rec.Code)
	}
	rec, _ = call(t, h, "GET", Prefix+"api/admin/users", admin, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"name":"4242"`) {
		t.Errorf("admin users: %d %s", rec.Code, rec.Body.String())
	}
}

// TestIssueMatchesTheBot: a link protocol returns the link, a JSON protocol
// returns the config with a one-time download ticket, and the kinds the bot
// uses are the kinds the app uses.
func TestIssueMatchesTheBot(t *testing.T) {
	s, _, store := newServer(t)
	h := s.Handler()
	user := initFor(t, 4242, time.Now())

	rec, methods := call(t, h, "GET", Prefix+"api/methods", user, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"tag":"awg-in"`) || !strings.Contains(rec.Body.String(), `"kind":"w"`) {
		t.Fatalf("methods: %d %s %v", rec.Code, rec.Body.String(), methods)
	}

	rec, out := call(t, h, "POST", Prefix+"api/issue", user, `{"kind":"i","tag":"vless-reality-in"}`)
	if rec.Code != 200 || out["kind"] != "link" || !strings.HasPrefix(out["text"].(string), "vless://4242@") || out["qr"] != true || out["ticket"] != nil {
		t.Fatalf("link issue: %d %v", rec.Code, out)
	}
	if out["label"] != "VLESS Reality" {
		t.Errorf("label was not the configured caption: %v", out["label"])
	}

	rec, out = call(t, h, "POST", Prefix+"api/issue", user, `{"kind":"i","tag":"shadowtls-in"}`)
	if rec.Code != 200 || out["kind"] != "json" || out["filename"] != "shadowtls-in-4242.json" {
		t.Fatalf("json issue: %d %v", rec.Code, out)
	}
	ticket, _ := out["ticket"].(string)
	if ticket == "" {
		t.Fatal("no download ticket for a file")
	}
	dl := httptest.NewRecorder()
	h.ServeHTTP(dl, httptest.NewRequest("GET", Prefix+"dl/"+ticket, nil))
	if dl.Code != 200 || !strings.Contains(dl.Header().Get("Content-Disposition"), "shadowtls-in-4242.json") || !strings.Contains(dl.Body.String(), `"user":"4242"`) {
		t.Errorf("download: %d %q %s", dl.Code, dl.Header().Get("Content-Disposition"), dl.Body.String())
	}
	again := httptest.NewRecorder()
	h.ServeHTTP(again, httptest.NewRequest("GET", Prefix+"dl/"+ticket, nil))
	if again.Code != http.StatusNotFound {
		t.Errorf("a ticket was usable twice: %d", again.Code)
	}

	rec, out = call(t, h, "POST", Prefix+"api/issue", user, `{"kind":"e","tag":"awg-in"}`)
	if rec.Code != 200 || out["kind"] != "conf" || out["filename"] != "amnezia-4242.conf" {
		t.Errorf("awg issue: %d %v", rec.Code, out)
	}
	for _, bad := range []string{`{"kind":"x","tag":"a"}`, `{"kind":"i","tag":"a/b"}`, `{"kind":"i"}`, `not json`} {
		if rec, _ := call(t, h, "POST", Prefix+"api/issue", user, bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%s was accepted: %d", bad, rec.Code)
		}
	}

	rec, out = call(t, h, "POST", Prefix+"api/subscription", user, "")
	if rec.Code != 200 || out["nodes"] != float64(3) || !strings.HasSuffix(out["cf"].(string), "/sub/tok-4242") {
		t.Fatalf("subscription: %d %v", rec.Code, out)
	}
	if _, ok := store.cache["tok-4242"]; !ok {
		t.Error("the bundle cache was not written, so the first poll would 404")
	}

	rec, _ = call(t, h, "POST", Prefix+"api/qr", user, `{"text":"vless://x"}`)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/png" {
		t.Errorf("qr: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec, _ := call(t, h, "POST", Prefix+"api/qr", user, `{"text":"`+strings.Repeat("x", qrLimit+1)+`"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("an oversized QR was attempted: %d", rec.Code)
	}
}

// TestURLFollowsTheSubscriptionHost: the app rides on the Cloudflare host by
// default, an explicit URL wins, and Disabled turns it off.
func TestURLFollowsTheSubscriptionHost(t *testing.T) {
	cfg := botcfg.ExampleConfig()
	if got := URL(cfg); got != "https://sub.example.com/app/" {
		t.Errorf("default URL = %q", got)
	}
	cfg.WebApp.URL = "https://app.example.net/x/"
	if got := URL(cfg); got != "https://app.example.net/x/" {
		t.Errorf("explicit URL = %q", got)
	}
	cfg.WebApp.URL = ""
	cfg.WebApp.Disabled = true
	if got := URL(cfg); got != "" {
		t.Errorf("disabled still has URL %q", got)
	}
	cfg.WebApp.Disabled = false
	cfg.Subscription.HostCF = ""
	if got := URL(cfg); got != "" {
		t.Errorf("no CF host still has URL %q", got)
	}
}
