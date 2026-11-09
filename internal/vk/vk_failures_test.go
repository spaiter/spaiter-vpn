package vk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

const badURL = "http://bad\x7fhost"

// truncatedServer promises more bytes than it sends and drops the connection.
func truncatedServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Write([]byte("short"))
		w.(http.Flusher).Flush()
		hj, _, _ := w.(http.Hijacker).Hijack()
		hj.Close()
	}))
	t.Cleanup(s.Close)
	return s
}

func textServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

func deadURL(t *testing.T) string {
	t.Helper()
	s := httptest.NewServer(http.NotFoundHandler())
	url := s.URL
	s.Close()
	return url
}

func TestSignInReportsEachWayVKCanFailToAnswer(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		host string
		want string
	}{
		"bad address": {badURL, ""},
		"unreachable": {deadURL(t), "reach VK"},
		"truncated":   {truncatedServer(t).URL, "read VK response"},
		"not json":    {textServer(t, "<html>").URL, "decode VK response"},
		"refusal":     {textServer(t, `{"error":"invalid_scope","error_type":"scope"}`).URL, "VK refused the sign-in: scope"},
		"nothing":     {textServer(t, `{}`).URL, "no token and no error"},
	}
	for name, tc := range cases {
		c := &Client{OAuthHost: tc.host}
		_, _, err := c.Login(ctx, "u", "p")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSubmitCodeNeedsAChallengeAndPassesFailuresOn(t *testing.T) {
	c := &Client{OAuthHost: deadURL(t)}
	if _, err := c.SubmitCode(context.Background(), nil, "123"); err == nil {
		t.Error("a nil challenge was accepted")
	}
	if _, err := c.SubmitCode(context.Background(), &Challenge{}, "123"); err == nil || !strings.Contains(err.Error(), "reach VK") {
		t.Errorf("transport failure: %v", err)
	}
}

func TestUserIDsMayArriveAsJSONNumbers(t *testing.T) {
	if got := toString(jsonNumber("42")); got != "42" {
		t.Errorf("json.Number = %q", got)
	}
}

func TestCallTokenMintingReportsEachWayVKCanFailToAnswer(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		host string
		want string
	}{
		"bad address": {badURL, "build"},
		"unreachable": {deadURL(t), "reach VK"},
		"truncated":   {truncatedServer(t).URL, "read VK response"},
		"not json":    {textServer(t, "<html>").URL, "decode getCallToken"},
	}
	for name, tc := range cases {
		c := &Client{APIHost: tc.host}
		_, err := c.MintCallToken(ctx, "vk1.a.X")
		if err == nil || (tc.want != "build" && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMintedTokensDefaultTheCallsHostAndHonourAnAPIVersion(t *testing.T) {
	var version atomic.Value
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		version.Store(r.URL.Query().Get("v"))
		w.Write([]byte(`{"response":{"token":"T"}}`))
	}))
	defer s.Close()
	c := &Client{APIHost: s.URL, Version: "9.99"}
	ct, err := c.MintCallToken(context.Background(), "vk1.a.X")
	if err != nil || ct.APIBaseURL != "https://calls.okcdn.ru" {
		t.Fatalf("token = %+v, %v", ct, err)
	}
	if version.Load() != "9.99" {
		t.Errorf("v = %v", version.Load())
	}
}

func TestACaptureWithAnAbsurdExpiryIsRefused(t *testing.T) {
	capture := []byte(`{"response":{"access_token":"vk1.a.AAA","expires_in":99999999999999999999999,"user_id":1`)
	if _, err := ExtractAccessToken(capture); err == nil || !strings.Contains(err.Error(), "expires_in") {
		t.Errorf("error = %v", err)
	}
}

func TestOKClientReportsEachWayOkcdnCanFailToAnswer(t *testing.T) {
	ctx := context.Background()
	for name, host := range map[string]string{
		"bad address": badURL,
		"unreachable": deadURL(t),
		"truncated":   truncatedServer(t).URL,
		"not json":    textServer(t, "<html>").URL,
	} {
		c := &OKClient{Host: host}
		if _, err := c.AnonymLogin(ctx, "token"); err == nil {
			t.Errorf("%s: AnonymLogin succeeded", name)
		}
		if _, err := c.StartConversation(ctx, &Session{SessionKey: "k"}); err == nil {
			t.Errorf("%s: StartConversation succeeded", name)
		}
	}
}

func TestLiveCallSourceReportsEachStepThatCanFail(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("no pass today")

	src := &LiveCallSource{OK: &OKClient{Host: deadURL(t)}, Mint: &Client{}, AccessToken: func(context.Context) (string, error) { return "", boom }}
	if _, _, err := src.Open(ctx); !errors.Is(err, boom) {
		t.Errorf("access token: %v", err)
	}

	// okcdn rejects every call token, so the re-mint is tried and then fails.
	var mints atomic.Int32
	mint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mints.Add(1) > 1 {
			w.Write([]byte(`{"error":{"error_code":5,"error_msg":"dead"}}`))
			return
		}
		w.Write([]byte(`{"response":{"token":"T"}}`))
	}))
	defer mint.Close()
	stale := textServer(t, `{"error_msg":"outdated"}`)
	src = &LiveCallSource{OK: &OKClient{Host: stale.URL}, Mint: &Client{APIHost: mint.URL}, AccessToken: constAccess("vk1.a.X")}
	if _, _, err := src.Open(ctx); !errors.Is(err, ErrAccessTokenExpired) {
		t.Errorf("re-mint: %v", err)
	}

	// A hard okcdn failure (not a stale token) is returned as it is.
	src = &LiveCallSource{OK: &OKClient{Host: textServer(t, "<html>").URL}, Mint: mintOnly(t, "T", nil), AccessToken: constAccess("vk1.a.X")}
	if _, _, err := src.Open(ctx); err == nil {
		t.Error("garbage from okcdn was accepted")
	}

	// A login that works but a conversation that does not.
	ok := newOKServer(t, map[string]any{"session_key": "SK", "uid": 1}, map[string]any{"error_msg": "no"})
	src = &LiveCallSource{OK: ok.client(), Mint: mintOnly(t, "T", nil), AccessToken: constAccess("vk1.a.X")}
	if _, _, err := src.Open(ctx); err == nil {
		t.Error("an unusable conversation was accepted")
	}

	// A conversation but no socket.
	ok = newOKServer(t, map[string]any{"session_key": "SK", "uid": 1}, map[string]any{"join_link": "H", "token": "W", "id": "c"})
	src = &LiveCallSource{OK: ok.client(), Mint: mintOnly(t, "T", nil), AccessToken: constAccess("vk1.a.X"),
		Dial: func(context.Context, string) (CallConn, error) { return nil, boom }}
	if _, _, err := src.Open(ctx); !errors.Is(err, boom) {
		t.Errorf("dial: %v", err)
	}
}

func TestACachedCallTokenIsReusedUntilForced(t *testing.T) {
	var mints atomic.Int32
	src := &LiveCallSource{Mint: mintOnly(t, "T", &mints), AccessToken: constAccess("vk1.a.X")}
	for range 3 {
		if tok, err := src.ensureCallToken(context.Background(), false); err != nil || tok != "T" {
			t.Fatalf("token = %q, %v", tok, err)
		}
	}
	if mints.Load() != 1 {
		t.Errorf("minted %d times, want 1", mints.Load())
	}
	if _, err := src.ensureCallToken(context.Background(), true); err != nil || mints.Load() != 2 {
		t.Errorf("forced mint: %v (%d)", err, mints.Load())
	}
}

func TestOwnerSocketAnswersThePingWithAPongAndEndsWhenTheServerHangsUp(t *testing.T) {
	ponged := make(chan string, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		ctx := r.Context()
		conn.Write(ctx, websocket.MessageText, []byte("ping"))
		_, data, err := conn.Read(ctx)
		if err == nil {
			ponged <- string(data)
		}
		conn.Close(websocket.StatusNormalClosure, "")
	}))
	defer s.Close()

	src := &LiveCallSource{}
	conn, err := src.dial(context.Background(), "ws"+strings.TrimPrefix(s.URL, "http"))
	if err != nil {
		t.Fatal(err)
	}
	held := make(chan error, 1)
	go func() { held <- conn.Hold(context.Background()) }()
	select {
	case got := <-ponged:
		if got != "pong" {
			t.Errorf("answer = %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no pong")
	}
	select {
	case err := <-held:
		if err == nil {
			t.Error("Hold returned nil after the server hung up")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Hold never ended")
	}
	conn.Close()
}

type nopPub struct{}

func (nopPub) Publish(context.Context, []string) error { return nil }

func TestHolderWithoutACountHoldsFourCalls(t *testing.T) {
	var opened atomic.Int32
	src := countingSource{&opened}
	h := &Holder{Source: src, Pub: nopPub{}, Log: quietVK(), ReopenPause: time.Hour, ReloginPause: time.Hour}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	h.Run(ctx)
	if opened.Load() != 4 {
		t.Errorf("opened %d slots, want the default of 4", opened.Load())
	}
}

type countingSource struct{ n *atomic.Int32 }

func (c countingSource) Open(ctx context.Context) (string, CallConn, error) {
	c.n.Add(1)
	<-ctx.Done()
	return "", nil, ctx.Err()
}

func jsonNumber(s string) json.Number { return json.Number(s) }
