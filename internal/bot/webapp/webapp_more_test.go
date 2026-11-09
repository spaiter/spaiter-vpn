package webapp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/clientcfg"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

// brokenMethods is the fake service with chosen calls made to fail.
type brokenMethods struct {
	fakeMethods
	fail map[string]bool
}

func (b brokenMethods) err(name string) error {
	if b.fail[name] {
		return errors.New(name + " is down")
	}
	return nil
}
func (b brokenMethods) UserInbounds(ctx context.Context) ([]manage.InboundRef, error) {
	if err := b.err("UserInbounds"); err != nil {
		return nil, err
	}
	return b.fakeMethods.UserInbounds(ctx)
}
func (b brokenMethods) OfferedEndpoints(ctx context.Context) ([]clientcfg.Endpoint, error) {
	if err := b.err("OfferedEndpoints"); err != nil {
		return nil, err
	}
	return b.fakeMethods.OfferedEndpoints(ctx)
}
func (b brokenMethods) Link(ctx context.Context, tag, uid string) (string, error) {
	if err := b.err("Link"); err != nil {
		return "", err
	}
	return b.fakeMethods.Link(ctx, tag, uid)
}
func (b brokenMethods) JSONConfig(ctx context.Context, tag, uid string) ([]byte, error) {
	if err := b.err("JSONConfig"); err != nil {
		return nil, err
	}
	return b.fakeMethods.JSONConfig(ctx, tag, uid)
}
func (b brokenMethods) AWGConf(ctx context.Context, tag, uid string) (string, error) {
	if err := b.err("AWGConf"); err != nil {
		return "", err
	}
	return b.fakeMethods.AWGConf(ctx, tag, uid)
}
func (b brokenMethods) WARPChainConfig(ctx context.Context, uid string) ([]byte, error) {
	if err := b.err("WARPChainConfig"); err != nil {
		return nil, err
	}
	return b.fakeMethods.WARPChainConfig(ctx, uid)
}
func (b brokenMethods) WDTTConfig(ctx context.Context, uid string) ([]byte, error) {
	if err := b.err("WDTTConfig"); err != nil {
		return nil, err
	}
	return b.fakeMethods.WDTTConfig(ctx, uid)
}
func (b brokenMethods) Bundle(ctx context.Context, uid string, p bool) ([]byte, error) {
	if err := b.err("Bundle"); err != nil {
		return nil, err
	}
	return b.fakeMethods.Bundle(ctx, uid, p)
}
func (b brokenMethods) AllStats(ctx context.Context) ([]manage.UserStat, error) {
	if err := b.err("AllStats"); err != nil {
		return nil, err
	}
	return b.fakeMethods.AllStats(ctx)
}
func (b brokenMethods) Accounts(ctx context.Context) (map[string][]string, error) {
	if err := b.err("Accounts"); err != nil {
		return nil, err
	}
	return b.fakeMethods.Accounts(ctx)
}

type brokenStore struct {
	*fakeStore
	failToken, failCache bool
}

func (s brokenStore) SubscriptionToken(uid string) (string, error) {
	if s.failToken {
		return "", errors.New("token store is down")
	}
	return s.fakeStore.SubscriptionToken(uid)
}
func (s brokenStore) SetBundleCache(token string, b []byte) error {
	if s.failCache {
		return errors.New("cache is read-only")
	}
	return s.fakeStore.SetBundleCache(token, b)
}

func TestAServiceThatFailsIsABadGatewayNotASilentEmptyAnswer(t *testing.T) {
	user := initFor(t, 4242, time.Now())
	admin := initFor(t, 1, time.Now())
	cases := []struct {
		fail, method, path, body, as string
		want                         int
	}{
		{"UserInbounds", "GET", "api/methods", "", user, http.StatusBadGateway},
		{"OfferedEndpoints", "GET", "api/methods", "", user, http.StatusBadGateway},
		{"Link", "POST", "api/issue", `{"kind":"i","tag":"vless-reality-in"}`, user, http.StatusBadGateway},
		{"JSONConfig", "POST", "api/issue", `{"kind":"i","tag":"shadowtls-in"}`, user, http.StatusBadGateway},
		{"AWGConf", "POST", "api/issue", `{"kind":"e","tag":"awg-in"}`, user, http.StatusBadGateway},
		{"WARPChainConfig", "POST", "api/issue", `{"kind":"w","tag":"warp"}`, user, http.StatusBadGateway},
		{"WDTTConfig", "POST", "api/issue", `{"kind":"v","tag":"wdtt"}`, user, http.StatusBadGateway},
		{"Bundle", "POST", "api/subscription", "", user, http.StatusBadGateway},
		{"Accounts", "GET", "api/admin/users", "", admin, http.StatusBadGateway},
		{"AllStats", "GET", "api/admin/users", "", admin, http.StatusBadGateway},
	}
	for _, c := range cases {
		s, _, _ := newServer(t)
		s.svc = brokenMethods{fail: map[string]bool{c.fail: true}}
		rec, out := call(t, s.Handler(), c.method, Prefix+c.path, c.as, c.body)
		if rec.Code != c.want || !strings.Contains(rec.Body.String(), c.fail+" is down") {
			t.Errorf("%s failing: %d %v", c.fail, rec.Code, out)
		}
	}
}

func TestWARPAndWDTTFilesGetTicketsAndTheButtonLabels(t *testing.T) {
	s, _, _ := newServer(t)
	h := s.Handler()
	user := initFor(t, 4242, time.Now())
	for _, c := range []struct{ kind, tag, file string }{{"w", "warp", "warp-4242.json"}, {"v", "wdtt", "wdtt-4242.json"}} {
		rec, out := call(t, h, "POST", Prefix+"api/issue", user, `{"kind":"`+c.kind+`","tag":"`+c.tag+`"}`)
		if rec.Code != 200 || out["filename"] != c.file || out["ticket"] == nil || out["kind"] != "json" {
			t.Errorf("%s: %d %v", c.kind, rec.Code, out)
		}
	}
}

func TestSubscriptionStoreFailuresAreServerErrors(t *testing.T) {
	user := initFor(t, 4242, time.Now())
	for name, store := range map[string]brokenStore{
		"token": {failToken: true},
		"cache": {failCache: true},
	} {
		s, _, base := newServer(t)
		store.fakeStore = base
		s.store = store
		rec, _ := call(t, s.Handler(), "POST", Prefix+"api/subscription", user, "")
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
}

func TestSubscriptionAdoptsTheHashOnlyForAKnownToken(t *testing.T) {
	s, _, store := newServer(t)
	user := initFor(t, 4242, time.Now())
	store.subs = state.Subscriptions{"tok-4242": {UID: "4242"}}
	if rec, _ := call(t, s.Handler(), "POST", Prefix+"api/subscription", user, ""); rec.Code != 200 {
		t.Fatalf("%d", rec.Code)
	}
	if store.subs["tok-4242"].LastHash == "" {
		t.Error("the hash was not adopted, so the refresh loop would announce the user's own request")
	}
	// An unknown token is left unrecorded.
	s2, _, store2 := newServer(t)
	if rec, _ := call(t, s2.Handler(), "POST", Prefix+"api/subscription", user, ""); rec.Code != 200 {
		t.Fatal("subscription failed")
	}
	if len(store2.subs) != 0 {
		t.Errorf("a token that was never issued was created: %v", store2.subs)
	}
}

func TestAdminAccessListsPendingAndWhitelistAndDecisionsValidate(t *testing.T) {
	s, access, _ := newServer(t)
	h := s.Handler()
	admin := initFor(t, 1, time.Now())
	access.pending[77] = true

	rec, out := call(t, h, "GET", Prefix+"api/admin/access", admin, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"display":"user 77"`) || !strings.Contains(rec.Body.String(), `"display":"user 4242"`) {
		t.Fatalf("access list: %d %v", rec.Code, out)
	}

	for _, body := range []string{`not json`, `{}`, `{"id":0,"action":"approve"}`} {
		if rec, _ := call(t, h, "POST", Prefix+"api/admin/decide", admin, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%q: %d", body, rec.Code)
		}
	}

	var told []string
	s.Tell = func(_ context.Context, uid int64, text string) { told = append(told, text) }
	if rec, _ := call(t, h, "POST", Prefix+"api/admin/decide", admin, `{"id":77,"action":"reject"}`); rec.Code != 200 {
		t.Errorf("reject: %d", rec.Code)
	}
	if access.pending[77] {
		t.Error("the rejected request is still pending")
	}
	before := len(told)
	if rec, _ := call(t, h, "POST", Prefix+"api/admin/decide", admin, `{"id":4242,"action":"revoke"}`); rec.Code != 200 || access.allowed[4242] {
		t.Errorf("revoke: %d %v", rec.Code, access.allowed)
	}
	if len(told) != before {
		t.Error("a revoked user was sent a notice; revoking is silent")
	}
}

func TestRequestAccessFromSomeoneAlreadyAllowedChangesNothing(t *testing.T) {
	s, access, _ := newServer(t)
	rec, out := call(t, s.Handler(), "POST", Prefix+"api/access/request", initFor(t, 4242, time.Now()), "")
	if rec.Code != 200 || out["allowed"] != true || access.pending[4242] {
		t.Errorf("%d %v pending=%v", rec.Code, out, access.pending)
	}
}

func TestLogoutEndsABrowserSessionAndClearsTheCookie(t *testing.T) {
	s, _, _ := newServer(t)
	h := s.Handler()
	now := s.now()
	link, err := s.LoginLink(4242, now)
	if err != nil {
		t.Skipf("no public URL in the example config: %v", err)
	}
	token := link[strings.Index(link, "=")+1:]
	req := httptest.NewRequest("POST", Prefix+"api/session", strings.NewReader(`{"login":"`+token+`"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	cookies := rec.Result().Cookies()
	if rec.Code != 200 || len(cookies) != 1 {
		t.Fatalf("session: %d %v", rec.Code, cookies)
	}
	cookie := cookies[0]

	me := func() int {
		r := httptest.NewRequest("GET", Prefix+"api/me", nil)
		r.AddCookie(cookie)
		r.Header.Set("X-Requested-With", requestedWith)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if me() != 200 {
		t.Fatalf("the session does not work: %d", me())
	}
	out := httptest.NewRequest("POST", Prefix+"api/logout", nil)
	out.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, out)
	cleared := w.Result().Cookies()
	if w.Code != 200 || len(cleared) != 1 || cleared[0].MaxAge >= 0 || cleared[0].Value != "" {
		t.Errorf("logout: %d %+v", w.Code, cleared)
	}
	if me() == 200 {
		t.Error("the session still works after logout")
	}
	// Logging out with no cookie is fine.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", Prefix+"api/logout", nil))
	if w.Code != 200 {
		t.Errorf("logout without a cookie: %d", w.Code)
	}
}

func TestLoginLinksAreRefusedWhenForgedExpiredOrWithoutAURL(t *testing.T) {
	s, _, _ := newServer(t)
	now := s.now()
	if _, err := s.consumeLogin("!!!", now); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("malformed: %v", err)
	}
	link, err := s.LoginLink(4242, now)
	if err != nil {
		t.Skipf("no public URL in the example config: %v", err)
	}
	token := link[strings.Index(link, "=")+1:]

	other, _, _ := newServer(t)
	other.token = "999:another-bot"
	if _, err := other.consumeLogin(token, now); err == nil || !strings.Contains(err.Error(), "not from this bot") {
		t.Errorf("another bot's link: %v", err)
	}
	if _, err := s.consumeLogin(token, now.Add(loginTTL+time.Minute)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired: %v", err)
	}
	if uid, err := s.consumeLogin(token, now); err != nil || uid != 4242 {
		t.Errorf("first use: %d %v", uid, err)
	}
	if _, err := s.consumeLogin(token, now); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("second use: %v", err)
	}

	bare := New(botcfg.Config{}, fakeMethods{}, nil, nil, testToken, nil)
	if _, err := bare.LoginLink(1, now); err == nil || !strings.Contains(err.Error(), "no public URL") {
		t.Errorf("no URL: %v", err)
	}
}

func TestSessionStoreExpiresAndForgets(t *testing.T) {
	st := newSessionStore()
	now := time.Now()
	id := st.open(7, now)
	if uid, ok := st.lookup(id, now); !ok || uid != 7 {
		t.Errorf("lookup = %d %v", uid, ok)
	}
	if _, ok := st.lookup(id, now.Add(sessionTTL+time.Minute)); ok {
		t.Error("an expired session was accepted")
	}
	st.open(8, now.Add(sessionTTL+time.Hour)) // opening prunes the expired one
	if len(st.sessions) != 1 {
		t.Errorf("sessions = %d, want the expired one pruned", len(st.sessions))
	}
	st.close(id)
	if _, ok := st.lookup("nope", now); ok {
		t.Error("an unknown session was accepted")
	}
	if !st.burn("n", now) || st.burn("n", now) {
		t.Error("a nonce can be used once")
	}
	if !st.burn("n", now.Add(loginTTL+time.Minute)) {
		t.Error("an old nonce was not forgotten")
	}
}

func TestIsHTTPSTrustsTheTunnelHeaderAndTLS(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if isHTTPS(r) {
		t.Error("plain http reported as https")
	}
	r.Header.Set("X-Forwarded-Proto", "HTTPS")
	if !isHTTPS(r) {
		t.Error("the tunnel header was ignored")
	}
	tls := httptest.NewRequest("GET", "https://x/", nil)
	if !isHTTPS(tls) {
		t.Error("TLS was ignored")
	}
}

func TestExpiredTicketsAreGoneAndNamesAreShortened(t *testing.T) {
	store := newTicketStore(time.Nanosecond)
	id := store.put(1, "f", []byte("x"))
	time.Sleep(2 * time.Millisecond)
	if _, ok := store.take(id); ok {
		t.Error("an expired ticket was honoured")
	}
	if _, ok := store.take("unknown"); ok {
		t.Error("an unknown ticket was honoured")
	}
	if shortProfileName("1234567890") != "amnezia-7890" || shortProfileName("12") != "amnezia-12" {
		t.Error("shortProfileName")
	}
	if countNodes([]byte("nope")) != 0 || countNodes([]byte(`{"outbounds":[{},{}]}`)) != 2 {
		t.Error("countNodes")
	}
}
