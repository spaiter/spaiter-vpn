package vk

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// breakingShell is the fake shell with chosen commands made to fail.
type breakingShell struct {
	*fakeShell
	fail func(name string, args []string) bool
}

func (b *breakingShell) err(name string, args []string) error {
	if b.fail != nil && b.fail(name, args) {
		return errors.New("simulated failure of " + name)
	}
	return nil
}

func (b *breakingShell) Run(ctx context.Context, name string, args ...string) error {
	if err := b.err(name, args); err != nil {
		return err
	}
	return b.fakeShell.Run(ctx, name, args...)
}

func (b *breakingShell) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := b.err(name, args); err != nil {
		return nil, err
	}
	return b.fakeShell.Output(ctx, name, args...)
}

func (b *breakingShell) Input(ctx context.Context, stdin, name string, args ...string) error {
	if err := b.err(name, args); err != nil {
		return err
	}
	return b.fakeShell.Input(ctx, stdin, name, args...)
}

func (b *breakingShell) Background(ctx context.Context, logPath, name string, args ...string) error {
	if err := b.err(name, args); err != nil {
		return err
	}
	return b.fakeShell.Background(ctx, logPath, name, args...)
}

func TestReloginNamesTheStepThatFailed(t *testing.T) {
	cases := []struct {
		reason string
		fail   func(string, []string) bool
		mut    func(*Relogin)
	}{
		{"display", func(n string, _ []string) bool { return n == "Xvfb" }, nil},
		{"display", func(n string, _ []string) bool { return n == "fluxbox" }, nil},
		{"display", func(n string, a []string) bool { return n == "xdotool" && len(a) > 0 && a[0] == "getdisplaygeometry" }, nil},
		{"app-launch", func(n string, _ []string) bool { return n == "dbus-run-session" }, nil},
		{"app-did-not-start", func(n string, a []string) bool { return n == "pgrep" }, func(r *Relogin) { r.Cfg.StartTimeout = 3 * time.Second }},
		{"vkid-did-not-open", func(n string, a []string) bool {
			return n == "xdotool" && len(a) > 2 && a[0] == "search" && a[2] == "VK ID"
		}, nil},
		{"store", func(n string, a []string) bool { return n == "pass" }, nil},
		{"holder-restart", func(n string, a []string) bool { return n == "sudo" && len(a) > 2 && a[1] == "systemctl" }, nil},
	}
	for _, c := range cases {
		sh := &breakingShell{fakeShell: &fakeShell{blueHex: "2787F5", capture: []byte(respCapture), pool: `{}`}, fail: c.fail}
		r, notes := testRelogin(t, sh.fakeShell)
		r.Sh = sh
		r.Cfg.StartTimeout = 50 * time.Second
		if c.mut != nil {
			c.mut(r)
		}
		r.Now = steppingClock()
		if c.reason == "vkid-did-not-open" {
			r.Cfg.StartTimeout = time.Hour // only the 20s VK ID wait may expire
		}
		err := r.Run(context.Background())
		var re *reloginError
		if !errors.As(err, &re) || re.reason != c.reason {
			t.Errorf("%s: err = %v", c.reason, err)
			continue
		}
		assertStatus(t, r, "failed:"+c.reason)
		if len(*notes) == 0 || !strings.Contains((*notes)[len(*notes)-1], c.reason) {
			t.Errorf("%s: the admin was not told: %v", c.reason, *notes)
		}
		// Whatever failed, the X stack and the app are reaped.
		assertRan(t, sh.fakeShell, "pkill", "-x", "Xvfb")
	}
}

// steppingClock advances a second per reading, so deadline loops end.
func steppingClock() func() time.Time {
	var mu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(time.Second)
		return now
	}
}

func TestReloginSliderCaptchaStopsAtOnceAndMissingCredentialsAreNamed(t *testing.T) {
	sh := &fakeShell{blueHex: "FFFFFF", capture: []byte(respCapture)}
	r, notes := testRelogin(t, sh)
	r.solveRobot = func(context.Context) robotOutcome { return robotSlider }
	err := r.Run(context.Background())
	var re *reloginError
	if !errors.As(err, &re) || re.reason != "captcha-slider" {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(strings.Join(*notes, "\n"), "слайдер") {
		t.Errorf("no slider note: %v", *notes)
	}

	broken := &breakingShell{
		fakeShell: &fakeShell{blueHex: "FFFFFF", capture: []byte(respCapture)},
		fail: func(n string, a []string) bool {
			return n == "sudo" && len(a) > 2 && strings.HasSuffix(a[2], "vk-login")
		},
	}
	r2, _ := testRelogin(t, broken.fakeShell)
	r2.Sh = broken
	r2.solveRobot = func(context.Context) robotOutcome { return robotProceed }
	if err := r2.Run(context.Background()); !errors.As(err, &re) || re.reason != "no-credentials" {
		t.Errorf("missing login: %v", err)
	}
	brokenPw := &breakingShell{
		fakeShell: &fakeShell{blueHex: "FFFFFF", capture: []byte(respCapture), codeSeq: []string{"123456"}},
		fail: func(n string, a []string) bool {
			return n == "sudo" && len(a) > 2 && strings.HasSuffix(a[2], "vk-password")
		},
	}
	r3, _ := testRelogin(t, brokenPw.fakeShell)
	r3.Sh = brokenPw
	r3.solveRobot = func(context.Context) robotOutcome { return robotUnavailable }
	if err := r3.Run(context.Background()); !errors.As(err, &re) || re.reason != "no-credentials" {
		t.Errorf("missing password: %v", err)
	}
	assertRan(t, brokenPw.fakeShell, "xdotool", "mousemove", "463", "538") // blind click fallback
}

func TestReloginCodeNeverArrivingIsATimeout(t *testing.T) {
	sh := &fakeShell{blueHex: "FFFFFF", capture: []byte(respCapture)}
	r, _ := testRelogin(t, sh)
	r.solveRobot = func(context.Context) robotOutcome { return robotProceed }
	r.Now = steppingClock()
	r.Cfg.CodeWait = 5 * time.Second
	var re *reloginError
	if err := r.Run(context.Background()); !errors.As(err, &re) || re.reason != "code-timeout" {
		t.Errorf("err = %v", err)
	}
}

func TestPoolLiveIsMinusOneWhenThePoolCannotBeRead(t *testing.T) {
	r, _ := testRelogin(t, &fakeShell{pool: `not json`})
	if got := r.poolLive(context.Background()); got != -1 {
		t.Errorf("bad json: %d", got)
	}
	r.Sh = &breakingShell{fakeShell: &fakeShell{}, fail: func(n string, _ []string) bool { return n == "sudo" }}
	if got := r.poolLive(context.Background()); got != -1 {
		t.Errorf("unreadable: %d", got)
	}
}

func TestInitFillsDefaultsAndExposesTheDebugPortToTheApp(t *testing.T) {
	t.Setenv("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-quic")
	r := &Relogin{Cfg: ReloginConfig{DebugPort: 9333}}
	r.init()
	if r.Sh == nil || r.Mint == nil || r.Log == nil || r.Now == nil || r.Notify == nil || r.sleep == nil || r.solveRobot == nil {
		t.Fatalf("init left a nil: %+v", r)
	}
	if r.Cfg.Coords != DefaultCoords() {
		t.Error("coordinates were not defaulted")
	}
	flags := os.Getenv("QTWEBENGINE_CHROMIUM_FLAGS")
	if !strings.Contains(flags, "--disable-quic") || !strings.Contains(flags, "--remote-debugging-port=9333") {
		t.Errorf("flags = %q", flags)
	}
	t.Setenv("QTWEBENGINE_CHROMIUM_FLAGS", "")
	(&Relogin{Cfg: ReloginConfig{DebugPort: 0}}).init()
	if os.Getenv("QTWEBENGINE_CHROMIUM_FLAGS") != "" {
		t.Error("a disabled debug port still changed the browser flags")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTelegramNotifyPostsToTheAdminAndNeverFails(t *testing.T) {
	dir := t.TempDir()
	botJSON := filepath.Join(dir, "bot.json")
	if err := os.WriteFile(botJSON, []byte(`{"admins":[777,888]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sh := &fakeShell{}
	r, _ := testRelogin(t, sh)
	r.Cfg.BotJSON = botJSON
	r.Log = quietVK()
	// The bot token comes from the fake pass-show; give it one.
	r.Sh = &tokenShell{fakeShell: sh}

	var got *http.Request
	var body string
	old := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		got = req
		data, _ := io.ReadAll(req.Body)
		body = string(data)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = old })

	r.telegramNotify(context.Background(), "hello *world*")
	if got == nil || !strings.Contains(got.URL.Path, "/botBOT-TOKEN/sendMessage") {
		t.Fatalf("request = %v", got)
	}
	for _, want := range []string{"chat_id=777", "parse_mode=Markdown", "text=hello+%2Aworld%2A"} {
		if !strings.Contains(body, want) {
			t.Errorf("body %q is missing %q", body, want)
		}
	}

	// Failure modes are logged and swallowed.
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })
	r.telegramNotify(context.Background(), "x")
	os.WriteFile(botJSON, []byte(`{"admins":[]}`), 0o600)
	r.telegramNotify(context.Background(), "x")
	os.WriteFile(botJSON, []byte(`nope`), 0o600)
	r.telegramNotify(context.Background(), "x")
	os.Remove(botJSON)
	r.telegramNotify(context.Background(), "x")
	r.Sh = &breakingShell{fakeShell: sh, fail: func(n string, _ []string) bool { return n == "sudo" }}
	r.telegramNotify(context.Background(), "x")
}

// tokenShell answers the bot-token pass entry.
type tokenShell struct{ *fakeShell }

func (t *tokenShell) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "sudo" && len(args) > 2 && strings.HasSuffix(args[2], "TELEGRAM_TOKEN") {
		return []byte("BOT-TOKEN\n"), nil
	}
	return t.fakeShell.Output(ctx, name, args...)
}
