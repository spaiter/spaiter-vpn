package vk

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestMergeChromiumFlags(t *testing.T) {
	cases := []struct {
		name, existing, add, want string
	}{
		{"empty", "", "--remote-debugging-port=9222", "--remote-debugging-port=9222"},
		{"append", "--disable-quic", "--remote-debugging-port=9222", "--disable-quic --remote-debugging-port=9222"},
		{"already-set", "--remote-debugging-port=1", "--remote-debugging-port=9222", "--remote-debugging-port=1"},
		{"preserve-others", "--disable-quic --remote-debugging-port=1 --x", "--remote-debugging-port=9222", "--disable-quic --remote-debugging-port=1 --x"},
		{"spaces", "  --disable-quic  ", "--remote-debugging-port=9222", "--disable-quic --remote-debugging-port=9222"},
	}
	for _, c := range cases {
		if got := mergeChromiumFlags(c.existing, c.add); got != c.want {
			t.Errorf("%s: mergeChromiumFlags(%q,%q) = %q, want %q", c.name, c.existing, c.add, got, c.want)
		}
	}
}

func TestPickCaptchaTarget(t *testing.T) {
	notRobot := cdpTarget{Type: "page", URL: "https://id.vk.ru/not_robot_captcha?x=1", WebSocketDebuggerURL: "ws://a"}
	idPage := cdpTarget{Type: "page", URL: "https://id.vk.ru/auth", WebSocketDebuggerURL: "ws://b"}
	noWS := cdpTarget{Type: "page", URL: "https://id.vk.ru/captcha", WebSocketDebuggerURL: ""}
	other := cdpTarget{Type: "page", URL: "https://example.com", WebSocketDebuggerURL: "ws://c"}

	if got, ok := pickCaptchaTarget([]cdpTarget{idPage, notRobot}); !ok || got.WebSocketDebuggerURL != "ws://a" {
		t.Fatalf("captcha URL should win: ok=%v got=%+v", ok, got)
	}
	if got, ok := pickCaptchaTarget([]cdpTarget{other, idPage}); !ok || got.WebSocketDebuggerURL != "ws://b" {
		t.Fatalf("id.vk page should be the fallback: ok=%v got=%+v", ok, got)
	}
	if _, ok := pickCaptchaTarget([]cdpTarget{other}); ok {
		t.Fatal("a non-VK target must not be chosen")
	}
	if _, ok := pickCaptchaTarget([]cdpTarget{noWS}); ok {
		t.Fatal("a target without a debugger socket must be skipped")
	}
}

func TestRandomPointInRect(t *testing.T) {
	mid := func() float64 { return 0.5 }
	// label at (100,200) sized 200x32 -> centre of the 15-85% / 25-75% box.
	x, y, ok := randomPointInRect("100,200,200,32", mid)
	if !ok {
		t.Fatal("valid rect rejected")
	}
	if x < 100 || x > 300 || y < 200 || y > 232 {
		t.Fatalf("point (%v,%v) outside the label rect", x, y)
	}
	// f=0.5 lands at 50% of each sub-range: x=100+200*0.5=200, y=200+32*0.5=216.
	if int(x) != 200 || int(y) != 216 {
		t.Fatalf("deterministic point = (%v,%v), want (200,216)", x, y)
	}
	if _, _, ok := randomPointInRect("1,2,3", mid); ok {
		t.Fatal("malformed rect accepted")
	}
	if _, _, ok := randomPointInRect("0,0,0,0", mid); ok {
		t.Fatal("zero-size rect accepted")
	}
}

// A slider escalation must fail fast with its own reason and never reach the
// code wait, so the admin is called to VNC immediately.
func TestReloginSliderFailsFast(t *testing.T) {
	sh := &fakeShell{
		blueHex: "FFFFFF", // white -> the full-login path
		pool:    `{}`,
	}
	r, notes := testRelogin(t, sh)
	r.Cfg.CodeWait = time.Hour // prove we never wait for a code
	r.solveRobot = func(context.Context) robotOutcome { return robotSlider }

	err := r.Run(context.Background())
	if err == nil {
		t.Fatal("a slider captcha should fail the relogin")
	}
	assertStatus(t, r, "failed:captcha-slider")
	// The code is read via `sudo -n cat <code>`; the slider path returns before
	// the code wait, so that must never have run.
	for _, run := range sh.runs {
		if len(run) >= 4 && run[0] == "sudo" && run[2] == "cat" && strings.HasSuffix(run[3], "/code") {
			t.Fatal("slider path must not wait for a code")
		}
	}
	var sawSlider bool
	for _, n := range *notes {
		if strings.Contains(n, "слайдер") {
			sawSlider = true
		}
	}
	if !sawSlider {
		t.Fatalf("admin was not told about the slider: %v", *notes)
	}
}

// When the CDP solver passes the checkbox, the flow must NOT fall back to the
// blind xdotool click at the robot coordinates.
func TestReloginCDPPassSkipsBlindClick(t *testing.T) {
	sh := &fakeShell{
		blueHex: "FFFFFF",
		codeSeq: []string{"", "701966"},
		capture: []byte(respCapture),
		pool:    `{"h1":{"status":"ok"}}`,
	}
	r, _ := testRelogin(t, sh)
	r.solveRobot = func(context.Context) robotOutcome { return robotProceed }

	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if didRun(sh, "xdotool", "mousemove", "463", "538") {
		t.Fatal("a CDP-passed checkbox must not trigger the blind click")
	}
	assertRan(t, sh, "xdotool", "type", "--delay", "160", "701966")
	assertStatus(t, r, "ok:1")
}
