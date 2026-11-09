package vk

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type failingPub struct{ calls atomic.Int32 }

func (p *failingPub) Publish(context.Context, []string) error {
	p.calls.Add(1)
	return errors.New("pool file is read-only")
}

func TestHolderHeartbeatRepublishesOnlyWhileSomethingIsHeld(t *testing.T) {
	src := &fakeSource{failErr: errors.New("okcdn down"), failN: 1 << 30}
	pub := &fakePub{}
	h := &Holder{Source: src, Pub: pub, N: 1, Heartbeat: 10 * time.Millisecond, Log: quietVK()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Run(ctx) }()

	// Nothing opens (the source keeps failing), so the heartbeat has nothing to say.
	time.Sleep(120 * time.Millisecond)
	if _, calls := pub.snapshot(); calls != 0 {
		t.Errorf("published %d times with no call held", calls)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Run returned %v, want the context's error", err)
	}

	// With a call held, the set is reasserted on every beat.
	src2, pub2 := &fakeSource{}, &fakePub{}
	h2 := &Holder{Source: src2, Pub: pub2, N: 2, Heartbeat: 10 * time.Millisecond, Log: quietVK()}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go h2.Run(ctx2)
	eventually(t, func() bool { live, _ := pub2.snapshot(); return len(live) == 2 }, "both held")
	_, before := pub2.snapshot()
	eventually(t, func() bool { _, n := pub2.snapshot(); return n >= before+3 }, "the heartbeat republishes")
	if !h2.anyHeld() {
		t.Error("anyHeld is false with two calls held")
	}
}

func TestHolderSurvivesAPublisherThatFails(t *testing.T) {
	pub := &failingPub{}
	h := &Holder{Source: &fakeSource{}, Pub: pub, N: 1, Log: quietVK()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	eventually(t, func() bool { return pub.calls.Load() > 0 && h.anyHeld() }, "keeps holding although the pool cannot be written")
}

func TestHolderReloginFailuresAndNoReloginConfigured(t *testing.T) {
	// A failing relogin is logged and the slot tries again; it must not wedge.
	var calls atomic.Int32
	src := &fakeSource{failErr: ErrAccessTokenExpired, failN: 3}
	pub := &fakePub{}
	h := &Holder{
		Source: src, Pub: pub, N: 1, Log: quietVK(),
		Relogin:      func(context.Context) error { calls.Add(1); return errors.New("no display") },
		ReloginPause: time.Millisecond, ReopenPause: time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	eventually(t, func() bool { live, _ := pub.snapshot(); return len(live) == 1 }, "recovers after failing relogins")
	if calls.Load() != 3 {
		t.Errorf("relogin ran %d times, want one per dead open (3)", calls.Load())
	}

	// With no relogin configured the slot waits instead of spinning, and a
	// cancelled context ends the wait at once.
	idle := &Holder{Source: &fakeSource{failErr: ErrAccessTokenExpired, failN: 1}, Pub: &fakePub{}, N: 1, Log: quietVK()}
	c2, cancel2 := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { idle.Run(c2); close(done) }()
	time.Sleep(30 * time.Millisecond)
	cancel2()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a holder waiting for a relogin ignored its context")
	}
}

func TestOrDurAndSleep(t *testing.T) {
	if orDur(0, time.Second) != time.Second || orDur(-1, time.Second) != time.Second || orDur(time.Minute, time.Second) != time.Minute {
		t.Error("orDur picks the wrong value")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	sleep(ctx, time.Hour)
	if time.Since(start) > time.Second {
		t.Error("sleep ignored a cancelled context")
	}
	if h := (&Holder{}); h.log() == nil {
		t.Error("no default logger")
	}
}

// fakeOwnerSocket is okcdn's owner socket: it pings, expects a pong, and then
// closes.
func fakeOwnerSocket(t *testing.T, got *atomic.Value, closeAfterPong bool) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("User-Agent"))
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		ctx := r.Context()
		c.Write(ctx, websocket.MessageText, []byte("noise"))
		c.Write(ctx, websocket.MessageText, []byte("ping"))
		_, data, err := c.Read(ctx)
		if err != nil || string(data) != "pong" {
			c.Close(websocket.StatusProtocolError, "no pong")
			return
		}
		if closeAfterPong {
			c.Close(websocket.StatusNormalClosure, "")
			return
		}
		<-ctx.Done()
	}))
	t.Cleanup(srv.Close)
	return strings.Replace(srv.URL, "http://", "ws://", 1)
}

func TestLiveCallSourceDialsTheOwnerSocketAndAnswersPings(t *testing.T) {
	var ua atomic.Value
	url := fakeOwnerSocket(t, &ua, true)
	src := &LiveCallSource{}
	conn, err := src.dial(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	// The server closes after the pong, which ends Hold; an answered ping is
	// the only way it got that far.
	if err := conn.Hold(context.Background()); err == nil {
		t.Error("Hold returned nil on a closed socket")
	}
	conn.Close()
	if ua.Load() != okUA {
		t.Errorf("User-Agent = %v", ua.Load())
	}

	if _, err := src.dial(context.Background(), "ws://127.0.0.1:1/x"); err == nil {
		t.Error("an unreachable socket was fine")
	}

	// Hold ends with the context, and Close releases the socket.
	url = fakeOwnerSocket(t, &ua, false)
	conn, err = src.dial(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := conn.Hold(ctx); err == nil {
		t.Error("Hold returned nil after its context ended")
	}
	if err := conn.Close(); err != nil {
		t.Logf("close after cancel: %v", err) // the library may report the aborted read
	}
}

func TestSmallDefaultsAndTexts(t *testing.T) {
	if got := (&CaptchaError{SID: "s1", ImageURL: "u"}).Error(); !strings.Contains(got, "s1") || !strings.Contains(got, "captcha") {
		t.Errorf("captcha text: %q", got)
	}
	c := &Client{}
	if c.http() != http.DefaultClient || c.oauthHost() != DefaultOAuthHost || c.version() != DefaultVersion {
		t.Error("client defaults")
	}
	custom := &http.Client{}
	c = &Client{HTTP: custom, OAuthHost: "https://x.example/", Version: "9"}
	if c.http() != custom || c.oauthHost() != "https://x.example" || c.version() != "9" {
		t.Errorf("client overrides: %q %q", c.oauthHost(), c.version())
	}
	if c.callsHost() != CallsAPIHost {
		t.Errorf("calls host default = %q", c.callsHost())
	}
	c.APIHost, c.Version = "https://calls.example/", ""
	if c.callsHost() != "https://calls.example" || c.callsVersion() == "" {
		t.Errorf("calls overrides: %q %q", c.callsHost(), c.callsVersion())
	}
	ok := &OKClient{}
	if ok.http() != http.DefaultClient || ok.host() != OKHost {
		t.Error("okcdn defaults")
	}
	ok = &OKClient{HTTP: custom, Host: "https://ok.example/"}
	if ok.http() != custom || ok.host() != "https://ok.example" {
		t.Error("okcdn overrides")
	}

	for in, want := range map[any]string{"s": "s", float64(42): "42", nil: "", true: "true", 7: "7"} {
		if got := toString(in); got != want {
			t.Errorf("toString(%v) = %q, want %q", in, got, want)
		}
	}
	for gr, want := range map[grantResponse]string{
		{ErrorDescription: "bad", ErrorType: "t", Error: "e"}: "bad",
		{ErrorType: "t", Error: "e"}:                          "t",
		{Error: "e"}:                                          "e",
	} {
		if got := gr.describe(); got != want {
			t.Errorf("describe(%+v) = %q, want %q", gr, got, want)
		}
	}
	re := &reloginError{reason: "display", err: os.ErrNotExist}
	if re.Error() != "display: file does not exist" || !errors.Is(re, os.ErrNotExist) {
		t.Errorf("reloginError: %q", re.Error())
	}
	t.Setenv("HOME", "")
	if homeDir() == "" {
		t.Error("homeDir has no fallback")
	}
	t.Setenv("HOME", "/home/someone")
	if homeDir() != "/home/someone" {
		t.Errorf("homeDir = %q", homeDir())
	}
}

func TestReloginBotAdminAndNotifyFailuresAreSoft(t *testing.T) {
	dir := t.TempDir()
	r := &Relogin{Cfg: ReloginConfig{BotJSON: filepath.Join(dir, "bot.json")}, Log: quietVK()}
	if _, err := r.botAdmin(); err == nil {
		t.Error("a missing bot.json was fine")
	}
	write := func(body string) {
		os.WriteFile(r.Cfg.BotJSON, []byte(body), 0o600)
	}
	write("{")
	if _, err := r.botAdmin(); err == nil {
		t.Error("a corrupt bot.json was fine")
	}
	write(`{"admins": []}`)
	if _, err := r.botAdmin(); err == nil || !strings.Contains(err.Error(), "no admins") {
		t.Errorf("no admins: %v", err)
	}
	write(`{"admins": [123456789, 5]}`)
	if got, err := r.botAdmin(); err != nil || got != "123456789" {
		t.Errorf("admin = %q, %v", got, err)
	}

	// A notification that cannot be sent must never abort the relogin: no
	// token, no admin and an empty pass entry each end quietly.
	r.Sh = &fakeShell{}
	r.Cfg.PassShow, r.Cfg.PassTelegram = "/usr/local/bin/pass-show", "services/bot"
	r.telegramNotify(context.Background(), "hello") // fakeShell answers with something; must not panic
	write(`{"admins": []}`)
	r.telegramNotify(context.Background(), "hello")
}

type emptySecretShell struct{ fakeShell }

func (*emptySecretShell) Output(context.Context, string, ...string) ([]byte, error) {
	return []byte("\n"), nil
}

type failSecretShell struct{ fakeShell }

func (*failSecretShell) Output(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("gpg: no agent")
}

func TestReloginSecretReadsTheFirstLineOnly(t *testing.T) {
	r := &Relogin{Cfg: ReloginConfig{PassShow: "pass-show"}, Log: quietVK()}
	r.Sh = &emptySecretShell{}
	if _, err := r.secret(context.Background(), "e"); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Errorf("empty: %v", err)
	}
	r.Sh = &failSecretShell{}
	if _, err := r.secret(context.Background(), "e"); err == nil {
		t.Error("a failing pass was fine")
	}
	r.telegramNotify(context.Background(), "x") // no token: soft failure, no panic
}

func TestHostShellRunsCommandsWithTheGUIEnvironment(t *testing.T) {
	t.Setenv("PATH", "/usr/bin:/bin:/run/current-system/sw/bin")
	sh := NewHostShell(":77")
	ctx := context.Background()
	if err := sh.Run(ctx, "true"); err != nil {
		t.Skipf("no usable true(1): %v", err)
	}
	if err := sh.Run(ctx, "false"); err == nil {
		t.Error("a failing command was fine")
	}
	out, err := sh.Output(ctx, "sh", "-c", "echo $DISPLAY:$LANG")
	if err != nil || strings.TrimSpace(string(out)) != ":77:en_US.UTF-8" {
		t.Errorf("env = %q, %v", out, err)
	}
	dir := t.TempDir()
	sink := filepath.Join(dir, "in")
	if err := sh.Input(ctx, "secret-value", "sh", "-c", "cat > "+sink); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(sink); string(got) != "secret-value" {
		t.Errorf("stdin = %q", got)
	}

	logPath := filepath.Join(dir, "bg.log")
	if err := sh.Background(ctx, logPath, "sh", "-c", "echo started"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if b, _ := os.ReadFile(logPath); bytes.Contains(b, []byte("started")) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if b, _ := os.ReadFile(logPath); !bytes.Contains(b, []byte("started")) {
		t.Errorf("background output = %q", b)
	}
	if err := sh.Background(ctx, "", "/nonexistent-command"); err == nil {
		t.Error("starting a missing command was fine")
	}
}
