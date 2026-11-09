package vk

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeShell answers the external tools the relogin flow shells out to, so the
// whole sign-in can be exercised with no display, no app and no frida.
type fakeShell struct {
	mu      sync.Mutex
	runs    [][]string
	inputs  []string
	blueHex string   // the pixel colour `import` reports
	capture []byte   // what the frida attach "captures" into the bin file
	codeSeq []string // successive answers for `sudo cat <code>`; "" means not yet
	codeIdx int
	pool    string // the pool JSON `sudo cat <poolfile>` returns
}

func (f *fakeShell) record(name string, args []string) {
	f.mu.Lock()
	f.runs = append(f.runs, append([]string{name}, args...))
	f.mu.Unlock()
}

func (f *fakeShell) Run(_ context.Context, name string, args ...string) error {
	f.record(name, args)
	return nil
}

func (f *fakeShell) Input(_ context.Context, stdin string, name string, args ...string) error {
	f.record(name, args)
	f.mu.Lock()
	f.inputs = append(f.inputs, stdin)
	f.mu.Unlock()
	return nil
}

func (f *fakeShell) Background(_ context.Context, _ string, name string, args ...string) error {
	f.record(name, args)
	if name == "uv" { // the frida attach: write the capture into the .bin arg
		for _, a := range args {
			if strings.HasSuffix(a, ".bin") {
				_ = os.WriteFile(a, f.capture, 0o600)
			}
		}
	}
	return nil
}

func (f *fakeShell) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	f.record(name, args)
	last := ""
	if len(args) > 0 {
		last = args[len(args)-1]
	}
	switch {
	case name == "pgrep":
		return []byte("99999\n"), nil
	case name == "xdotool" && len(args) >= 3 && args[0] == "search" && args[2] == "VK Calls":
		return []byte("16777232\n"), nil
	case name == "xdotool" && len(args) >= 3 && args[0] == "search" && args[2] == "VK ID":
		return []byte("18874370\n"), nil
	case name == "xdotool" && args[0] == "getwindowgeometry":
		return []byte("WIDTH=944\nHEIGHT=520\n"), nil
	case name == "xdotool" && args[0] == "getdisplaygeometry":
		return []byte("1440 900\n"), nil
	case name == "import":
		hex := f.blueHex
		if hex == "" {
			hex = "FFFFFF"
		}
		return []byte("0,0: (0,0,0)  #" + hex + "  srgb\n"), nil
	case name == "sudo" && len(args) >= 3 && args[1] == "/usr/local/bin/pass-show" && strings.HasSuffix(last, "vk-login"):
		return []byte("user@example.com\n"), nil
	case name == "sudo" && len(args) >= 3 && args[1] == "/usr/local/bin/pass-show" && strings.HasSuffix(last, "vk-password"):
		return []byte("pw\n"), nil
	case name == "sudo" && len(args) >= 3 && args[0] == "-n" && args[1] == "cat" && strings.HasSuffix(last, "/code"):
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.codeIdx >= len(f.codeSeq) {
			return nil, nil
		}
		v := f.codeSeq[f.codeIdx]
		f.codeIdx++
		if v == "" {
			return nil, nil
		}
		return []byte(v), nil
	case name == "sudo" && len(args) >= 3 && args[0] == "-n" && args[1] == "cat" && strings.HasSuffix(last, ".json"):
		return []byte(f.pool), nil
	default:
		return nil, nil
	}
}

// testRelogin wires a Relogin against the fake shell with a temp bridge dir, no
// real notifications and no real sleeps.
func testRelogin(t *testing.T, sh *fakeShell) (*Relogin, *[]string) {
	t.Helper()
	dir := t.TempDir()
	cfg := DefaultReloginConfig()
	cfg.RunDir = dir
	cfg.WorkDir = dir
	cfg.TokenWait = 2 * time.Second
	cfg.CodeWait = 2 * time.Second
	var notes []string
	r := &Relogin{
		Cfg:    cfg,
		Sh:     sh,
		Mint:   mintOnly(t, "$uumTEST", nil),
		Notify: func(_ context.Context, m string) { notes = append(notes, m) },
		sleep:  func(time.Duration) {},
	}
	return r, &notes
}

const respCapture = `prefix{"response":{"access_token":"vk1.a.G4uPexampleTokenABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789","expires_in":31536000,"user_id":1000000}}suffix`

func TestReloginCachedSessionNeedsNoCode(t *testing.T) {
	sh := &fakeShell{
		blueHex: "2787F5", // VK blue -> "the cached-session continue"
		capture: []byte(respCapture),
		pool:    `{"h1":{"status":"ok"},"h2":{"status":"ok"},"h3":{"status":"dead"}}`,
	}
	r, notes := testRelogin(t, sh)

	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	// The access token was stored in pass, token first.
	if len(sh.inputs) != 1 || !strings.HasPrefix(sh.inputs[0], "vk1.a.G4uP") {
		t.Fatalf("pass write = %q", sh.inputs)
	}
	assertRan(t, sh, "sudo", "systemctl", "restart", "spaiter-vk-holder.service")
	assertRan(t, sh, "xdotool", "mousemove", "524", "491") // clicked the cached-session continue
	// A cached session must not ask for a flash-call code.
	if clickedRobot := didRun(sh, "xdotool", "mousemove", "463", "538"); clickedRobot {
		t.Fatal("cached session should not click the robot checkbox")
	}
	assertStatus(t, r, "ok:2")
	if len(*notes) == 0 || !strings.Contains((*notes)[len(*notes)-1], "оживает") {
		t.Fatalf("missing success notification: %v", *notes)
	}
}

func TestReloginFullLoginEntersCode(t *testing.T) {
	sh := &fakeShell{
		blueHex: "FFFFFF",               // white -> the phone/email form, full login
		codeSeq: []string{"", "701966"}, // empty first, then the code
		capture: []byte(respCapture),
		pool:    `{"h1":{"status":"ok"}}`,
	}
	r, _ := testRelogin(t, sh)

	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	// Full path: typed the login, the robot, the code and the password.
	assertRan(t, sh, "xdotool", "mousemove", "463", "538") // robot checkbox
	assertRan(t, sh, "xdotool", "type", "--delay", "160", "701966")
	assertRan(t, sh, "xdotool", "type", "--delay", "45", "pw")
	assertStatus(t, r, "ok:1")
}

func TestReloginFailsWhenTokenNeverCaptured(t *testing.T) {
	sh := &fakeShell{
		blueHex: "2787F5",
		capture: []byte("no token here"),
		pool:    `{}`,
	}
	r, notes := testRelogin(t, sh)
	r.Cfg.TokenWait = 10 * time.Millisecond

	err := r.Run(context.Background())
	if err == nil {
		t.Fatal("expected a failure when no token is captured")
	}
	assertStatus(t, r, "failed:token-not-captured")
	if len(*notes) == 0 || !strings.Contains((*notes)[len(*notes)-1], "не удался") {
		t.Fatalf("missing failure notification: %v", *notes)
	}
}

func TestExtractTokenPrefersResponseOverBearer(t *testing.T) {
	r := &Relogin{Cfg: DefaultReloginConfig()}
	r.Cfg.DefaultUserID = "1000000" // the fallback id for a Bearer-only capture
	// Response form carries metadata, which wins over the fallback.
	at := r.extractToken([]byte(respCapture))
	if at == nil || at.UserID != "1000000" || at.ExpiresIn != 31536000 {
		t.Fatalf("response extract = %+v", at)
	}
	// Bearer-only falls back to the configured user id and a year.
	bearer := []byte("Authorization: Bearer vk1.a.onlyBearerTokenABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\r\n")
	at = r.extractToken(bearer)
	if at == nil || at.UserID != "1000000" || at.ExpiresIn != 31536000 {
		t.Fatalf("bearer extract = %+v", at)
	}
	if got := r.extractToken([]byte("nothing")); got != nil {
		t.Fatalf("expected nil for no token, got %+v", got)
	}
}

func TestPixelIsBlue(t *testing.T) {
	r := &Relogin{Cfg: DefaultReloginConfig(), Sh: &fakeShell{blueHex: "2787F5"}}
	if !r.pixelIsBlue(context.Background(), Point{1, 1}) {
		t.Fatal("2787F5 should read as blue")
	}
	r.Sh = &fakeShell{blueHex: "FFFFFF"}
	if r.pixelIsBlue(context.Background(), Point{1, 1}) {
		t.Fatal("white should not read as blue")
	}
	r.Sh = &fakeShell{blueHex: "E64646"} // red button
	if r.pixelIsBlue(context.Background(), Point{1, 1}) {
		t.Fatal("red should not read as blue")
	}
}

func TestDigitsOnlyAndShellVar(t *testing.T) {
	if got := digitsOnly(" 70 19 66\n"); got != "701966" {
		t.Fatalf("digitsOnly = %q", got)
	}
	if got := shellVar([]byte("X=1\nWIDTH=944\nHEIGHT=520\n"), "WIDTH"); got != 944 {
		t.Fatalf("shellVar = %d", got)
	}
	if got := shellVar([]byte("WIDTH=944\n"), "MISSING"); got != 0 {
		t.Fatalf("missing key should be 0, got %d", got)
	}
}

// --- helpers ---

// didRun reports whether any recorded command contains all the given tokens.
func didRun(sh *fakeShell, parts ...string) bool {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	for _, run := range sh.runs {
		joined := " " + strings.Join(run, " ") + " "
		all := true
		for _, p := range parts {
			if !strings.Contains(joined, " "+p+" ") {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func assertRan(t *testing.T, sh *fakeShell, parts ...string) {
	t.Helper()
	if !didRun(sh, parts...) {
		t.Fatalf("expected a command containing %v", parts)
	}
}

func assertStatus(t *testing.T, r *Relogin, want string) {
	t.Helper()
	raw, err := os.ReadFile(r.Cfg.WorkDir + "/status")
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if got := strings.TrimSpace(string(raw)); got != want {
		t.Fatalf("status = %q, want %q", got, want)
	}
}
