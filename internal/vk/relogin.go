package vk

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// relogin.go is the Go replacement for vc-relogin.sh: it refreshes the one-year
// VK Calls access token by driving the app's VK ID sign-in once, then captures
// the fresh token, stores it in pass and restarts the pool holder. Only the
// irreducible pieces shell out -- the X server, the app, xdotool and frida --
// because automating a closed Qt GUI has no Go bindings. Everything else (the
// step sequence, the token parse, the code bridge, the pass write, the restart)
// is Go and unit-tested through a fake Shell.
//
// Two hard-won rules are baked in:
//   - Launch the app PLAIN and frida-ATTACH to it. Spawning the app under frida
//     destabilises it on software GL: the pid churns every ~minute, which breaks
//     the silent-token deep-link handoff and triggers repeat flash-calls.
//   - Detect the cached-session screen (the "Continue as <account>" button) by its blue
//     button pixel and take it when present -- it finishes with no flash-call,
//     so no code is needed and the account sees one fewer auth.

//go:embed relogin_attach.py
var reloginAttachPy string

// bearerTokenRE finds the access token in a getCallToken request's Authorization
// header inside the captured TLS plaintext. The exchange response (parsed by
// ExtractAccessToken) carries expires_in and user_id too, so it is preferred;
// this is the fallback when only the Bearer header was seen.
var bearerTokenRE = regexp.MustCompile(`[Bb]earer\s+(vk1\.a\.[A-Za-z0-9._-]{40,})`)

// hexColorRE pulls the first #RRGGBB out of ImageMagick's one-pixel text dump.
var hexColorRE = regexp.MustCompile(`#([0-9A-Fa-f]{6})`)

// Shell runs external tools. The default implementation shells out with the GUI
// environment set; tests inject a fake to exercise the whole flow with no
// display, no app and no frida.
type Shell interface {
	Run(ctx context.Context, name string, args ...string) error
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
	// Input runs a command feeding stdin, for `pass insert` which reads the
	// secret from the pipe rather than an argument.
	Input(ctx context.Context, stdin string, name string, args ...string) error
	// Background starts a long-lived process detached, its output to logPath,
	// and returns without waiting. The flow reaps these by name on cleanup.
	Background(ctx context.Context, logPath string, name string, args ...string) error
}

// Point is an absolute screen coordinate for an xdotool click.
type Point struct{ X, Y int }

// ReloginCoords are the click targets on the VK ID flow, validated 2026-11-06.
// They are config so a UI shift can be fixed without a rebuild (via flags) and
// so tests can assert against them.
type ReloginCoords struct {
	SignInBrowser    Point // app welcome: "Sign in through browser"
	ContinueCached   Point // VK ID cached session: the "Continue as <account>" button
	EmailTab         Point // VK ID: the Email tab
	EmailField       Point // VK ID: the email input
	ContinueEmail    Point // VK ID: Continue after the email
	Robot            Point // VK ID: the "I'm not a robot" checkbox
	FirstCodeBox     Point // VK ID: first of six flash-call digit boxes
	PasswordField    Point // VK ID: the password input
	ContinuePassword Point // VK ID: Continue after the password
	CreateCall       Point // app home: "Create call" (forces a getCallToken)
}

// DefaultCoords are the coordinates observed on the 1440x900 headless display.
func DefaultCoords() ReloginCoords {
	return ReloginCoords{
		SignInBrowser:    Point{718, 472},
		ContinueCached:   Point{524, 491},
		EmailTab:         Point{779, 391},
		EmailField:       Point{703, 437},
		ContinueEmail:    Point{703, 525},
		Robot:            Point{463, 538},
		FirstCodeBox:     Point{410, 469},
		PasswordField:    Point{524, 457},
		ContinuePassword: Point{524, 551},
		CreateCall:       Point{497, 399},
	}
}

// ReloginConfig holds every path, name and timeout the flow needs. Defaults suit
// this host; the CLI exposes the ones worth overriding.
type ReloginConfig struct {
	Display  string // X display, ":99"
	AppBin   string // the app launcher, /usr/local/bin/vkcalls
	AppProc  string // process name to find and reap, "vkcalls"
	VncPass  string // x11vnc password file
	RunDir   string // scratch for logs and the capture harness
	WorkDir  string // bridge dir the bot shares: status + code files
	PoolFile string // wdtt/vk_hashes.json, to count live hashes at the end

	PassStoreDir    string // PASSWORD_STORE_DIR
	GnupgHome       string // GNUPGHOME
	PassShow        string // the sudo pass-show wrapper
	PassLogin       string // pass entry: VK login
	PassPassword    string // pass entry: VK password
	PassAccessToken string // pass entry: the one-year access token (written here)
	PassTelegram    string // pass entry: the bot token, for notifications
	BotJSON         string // bot.json, for admins[0]
	HolderService   string // systemd unit to restart on success
	DefaultUserID   string // user id to record if only the Bearer header is seen

	ScreenSize   string        // Xvfb geometry, "1440x900x24"
	StartTimeout time.Duration // how long to wait for the app window
	CodeWait     time.Duration // how long to wait for the admin's 6-digit code
	TokenWait    time.Duration // how long to wait for the token to appear in the capture
	CaptureSecs  int           // how long the frida attach runs

	Coords ReloginCoords
}

// homeDir returns the invoking user's home directory, which the path defaults
// are built from so no one host's layout is baked into the binary. It falls
// back to /root for a service with no HOME set.
func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	return "/root"
}

// DefaultReloginConfig returns the production configuration, with every path
// rooted at the invoking user's home directory. Flags override what differs.
func DefaultReloginConfig() ReloginConfig {
	home := homeDir()
	botData := filepath.Join(home, "appdata", "vpn-bot", "data")
	return ReloginConfig{
		Display:         ":99",
		AppBin:          "/usr/local/bin/vkcalls",
		AppProc:         "vkcalls",
		VncPass:         filepath.Join(home, "vcrun", "vncpass"),
		RunDir:          filepath.Join(home, "vcrun"),
		WorkDir:         filepath.Join(botData, "vk-relogin"),
		PoolFile:        filepath.Join(botData, "wdtt", "vk_hashes.json"),
		PassStoreDir:    filepath.Join(home, ".password-store"),
		GnupgHome:       filepath.Join(home, ".gnupg"),
		PassShow:        "/usr/local/bin/pass-show",
		PassLogin:       "services/vk-login",
		PassPassword:    "services/vk-password",
		PassAccessToken: "services/vk-calls-access-token",
		PassTelegram:    "stacks/vpn-bot/TELEGRAM_TOKEN",
		BotJSON:         filepath.Join(home, "appdata", "vpn-bot", "bot.json"),
		HolderService:   "spaiter-vk-holder.service",
		DefaultUserID:   "",
		ScreenSize:      "1440x900x24",
		StartTimeout:    50 * time.Second,
		CodeWait:        300 * time.Second,
		TokenWait:       40 * time.Second,
		CaptureSecs:     600,
		Coords:          DefaultCoords(),
	}
}

// Relogin drives one headless sign-in. Sh and Mint default to the real host
// Shell and a plain mint Client; Notify defaults to a Telegram message to the
// bot admin. Tests set all three.
type Relogin struct {
	Cfg    ReloginConfig
	Sh     Shell
	Mint   *Client
	Log    *slog.Logger
	Notify func(ctx context.Context, msg string)
	Now    func() time.Time
	sleep  func(time.Duration) // injectable so tests run without real waits
}

// reloginError wraps a failure with the short reason recorded in the status file
// and sent to the admin, so an operator sees where the flow stopped.
type reloginError struct {
	reason string
	err    error
}

func (e *reloginError) Error() string { return e.reason + ": " + e.err.Error() }
func (e *reloginError) Unwrap() error { return e.err }

// Run performs the whole relogin. On any failure it records the reason, tells
// the admin to finish over VNC, cleans up and returns a reloginError.
func (r *Relogin) Run(ctx context.Context) (err error) {
	r.init()
	defer func() {
		if err != nil {
			var re *reloginError
			reason := "failed"
			if errors.As(err, &re) {
				reason = re.reason
			}
			r.status("failed:" + reason)
			r.Notify(ctx, "⚠️ *VK релогин не удался*: `"+reason+"`. Пул WG-over-VK стоит — зайди по VNC и доведи вход вручную.")
		}
		r.stopAll(context.WithoutCancel(ctx))
	}()

	r.status("starting")
	r.Notify(ctx, "🔄 *VK токен умер* — запускаю повторный вход (Go). Скоро попрошу 6-значный код из звонка.")

	r.stopAll(ctx) // clear any stale session before starting a clean one
	if err := r.startDisplay(ctx); err != nil {
		return &reloginError{"display", err}
	}
	if err := r.launchApp(ctx); err != nil {
		return &reloginError{"app-launch", err}
	}
	pid, err := r.waitAppWindow(ctx)
	if err != nil {
		return &reloginError{"app-did-not-start", err}
	}
	r.sleep(4 * time.Second)

	// Attach frida to the stable, plain-launched app so the sign-in's whole TLS
	// stream -- the exchange response and the getCallToken Bearer -- is captured.
	capPath := filepath.Join(r.Cfg.RunDir, "relogin_capture.bin")
	_ = os.Remove(capPath)
	if err := r.attachCapture(ctx, pid, capPath); err != nil {
		r.Log.Warn("frida attach failed; the token capture may miss", "err", err)
	}

	if err := r.openVKID(ctx); err != nil {
		return &reloginError{"vkid-did-not-open", err}
	}

	if r.pixelIsBlue(ctx, r.Cfg.Coords.ContinueCached) {
		r.Log.Info("VK ID shows a cached session; continuing without a flash-call")
		r.click(ctx, r.Cfg.Coords.ContinueCached)
	} else {
		if err := r.fullLogin(ctx); err != nil {
			return err
		}
	}

	tok, err := r.awaitToken(ctx, capPath, r.Cfg.TokenWait)
	if err != nil {
		// A cached-session continue sometimes settles without a getCallToken;
		// force one from the app home, then look once more.
		r.Log.Info("no token yet; forcing a getCallToken from the app home")
		r.click(ctx, r.Cfg.Coords.CreateCall)
		r.sleep(6 * time.Second)
		tok, err = r.awaitToken(ctx, capPath, r.Cfg.TokenWait)
		if err != nil {
			return &reloginError{"token-not-captured", err}
		}
	}

	r.status("verifying")
	if err := r.verifyAndStore(ctx, tok); err != nil {
		return &reloginError{"store", err}
	}

	if err := r.restartHolder(ctx); err != nil {
		return &reloginError{"holder-restart", err}
	}
	live := r.poolLive(ctx)
	r.status(fmt.Sprintf("ok:%d", live))
	r.Notify(ctx, fmt.Sprintf("✅ *VK релогин готов* (Go). Пул WG-over-VK оживает: %d живых хешей.", live))
	r.Log.Info("relogin complete", "live_hashes", live, "user_id", tok.UserID, "expires_in", tok.ExpiresIn)
	return nil
}

// init fills in the real defaults for anything the caller left nil.
func (r *Relogin) init() {
	if r.Sh == nil {
		r.Sh = NewHostShell(r.Cfg.Display)
	}
	if r.Mint == nil {
		r.Mint = &Client{}
	}
	if r.Log == nil {
		r.Log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Notify == nil {
		r.Notify = r.telegramNotify
	}
	if r.sleep == nil {
		r.sleep = time.Sleep
	}
	if r.Cfg.Coords == (ReloginCoords{}) {
		r.Cfg.Coords = DefaultCoords()
	}
}

// startDisplay brings up Xvfb, a window manager and a VNC server, so an operator
// can take over if the automated flow stalls.
func (r *Relogin) startDisplay(ctx context.Context) error {
	_ = os.Remove("/tmp/.X" + strings.TrimPrefix(r.Cfg.Display, ":") + "-lock")
	log := func(n string) string { return filepath.Join(r.Cfg.RunDir, n) }
	if err := r.Sh.Background(ctx, log("xvfb.log"), "Xvfb", r.Cfg.Display, "-screen", "0", r.Cfg.ScreenSize, "-ac"); err != nil {
		return err
	}
	r.sleep(3 * time.Second)
	if err := r.Sh.Background(ctx, log("fluxbox.log"), "fluxbox"); err != nil {
		return err
	}
	r.sleep(time.Second)
	// x11vnc forks itself with -bg, so it is a foreground Run that returns.
	_ = r.Sh.Run(ctx, "x11vnc", "-display", r.Cfg.Display, "-rfbauth", r.Cfg.VncPass,
		"-localhost", "-rfbport", "5900", "-forever", "-shared", "-noxdamage", "-bg")
	r.sleep(time.Second)
	if _, err := r.Sh.Output(ctx, "xdotool", "getdisplaygeometry"); err != nil {
		return fmt.Errorf("display did not come up: %w", err)
	}
	return nil
}

// launchApp starts the app plainly (no frida) under its own dbus session.
func (r *Relogin) launchApp(ctx context.Context) error {
	return r.Sh.Background(ctx, filepath.Join(r.Cfg.RunDir, "vkcalls.log"),
		"dbus-run-session", "--", r.Cfg.AppBin)
}

// waitAppWindow waits for the app's main window and returns the app pid.
func (r *Relogin) waitAppWindow(ctx context.Context) (int, error) {
	deadline := r.Now().Add(r.Cfg.StartTimeout)
	for r.Now().Before(deadline) {
		if w := r.bigWindow(ctx); w != "" {
			pid, err := r.appPID(ctx)
			if err == nil && pid > 0 {
				return pid, nil
			}
		}
		r.sleep(2 * time.Second)
	}
	return 0, errors.New("the app window never appeared")
}

// appPID returns the pid of the running app, or 0.
func (r *Relogin) appPID(ctx context.Context) (int, error) {
	out, err := r.Sh.Output(ctx, "pgrep", "-x", r.Cfg.AppProc)
	if err != nil {
		return 0, err
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	return strconv.Atoi(line)
}

// bigWindow returns the id of the app's main (>500px wide) window, or "".
func (r *Relogin) bigWindow(ctx context.Context) string {
	out, err := r.Sh.Output(ctx, "xdotool", "search", "--name", "VK Calls")
	if err != nil {
		return ""
	}
	for _, id := range strings.Fields(string(out)) {
		geo, err := r.Sh.Output(ctx, "xdotool", "getwindowgeometry", "--shell", id)
		if err != nil {
			continue
		}
		if w := shellVar(geo, "WIDTH"); w > 500 {
			return id
		}
	}
	return ""
}

// openVKID clicks "Sign in through browser" and waits for the VK ID window.
func (r *Relogin) openVKID(ctx context.Context) error {
	if w := r.bigWindow(ctx); w != "" {
		_ = r.Sh.Run(ctx, "xdotool", "windowactivate", w)
		r.sleep(time.Second)
	}
	r.click(ctx, r.Cfg.Coords.SignInBrowser)
	deadline := r.Now().Add(20 * time.Second)
	for r.Now().Before(deadline) {
		if out, err := r.Sh.Output(ctx, "xdotool", "search", "--name", "VK ID"); err == nil && len(strings.Fields(string(out))) > 0 {
			r.sleep(2 * time.Second)
			return nil
		}
		r.sleep(time.Second)
	}
	return errors.New("the VK ID window never opened")
}

// fullLogin drives the email / captcha / flash-call / password path and blocks
// for the admin's code in the middle.
func (r *Relogin) fullLogin(ctx context.Context) error {
	login, err := r.secret(ctx, r.Cfg.PassLogin)
	if err != nil {
		return &reloginError{"no-credentials", err}
	}
	c := r.Cfg.Coords
	r.click(ctx, c.EmailTab)
	r.click(ctx, c.EmailField)
	r.sleep(400 * time.Millisecond)
	r.typeText(ctx, login, 40)
	_ = r.Sh.Run(ctx, "xdotool", "key", "Escape") // dismiss the autocomplete bubble
	r.sleep(500 * time.Millisecond)
	r.click(ctx, c.ContinueEmail)
	r.sleep(6 * time.Second)
	r.click(ctx, c.Robot)
	r.sleep(5 * time.Second)

	r.status("awaiting-code")
	r.Notify(ctx, "🔑 *Введи код VK*: пришли сюда 6 цифр из звонка (просто 6 цифр или `/vkcode 123456`).")
	code, err := r.waitCode(ctx)
	if err != nil {
		return &reloginError{"code-timeout", err}
	}

	r.status("verifying")
	r.click(ctx, c.FirstCodeBox)
	r.typeText(ctx, code, 160)
	r.sleep(6 * time.Second)

	password, err := r.secret(ctx, r.Cfg.PassPassword)
	if err != nil {
		return &reloginError{"no-credentials", err}
	}
	r.click(ctx, c.PasswordField)
	r.typeText(ctx, password, 45)
	r.sleep(600 * time.Millisecond)
	r.click(ctx, c.ContinuePassword)
	r.sleep(8 * time.Second)
	return nil
}

// attachCapture writes the embedded frida harness and runs it against the app
// pid, dumping TLS plaintext to capPath for the sign-in's duration.
func (r *Relogin) attachCapture(ctx context.Context, pid int, capPath string) error {
	harness := filepath.Join(r.Cfg.RunDir, "relogin_attach.py")
	if err := os.WriteFile(harness, []byte(reloginAttachPy), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(capPath, nil, 0o600); err != nil {
		return err
	}
	return r.Sh.Background(ctx, filepath.Join(r.Cfg.RunDir, "relogin_capture.log"),
		"uv", "run", "--with", "frida", "python3", harness, capPath, strconv.Itoa(pid), strconv.Itoa(r.Cfg.CaptureSecs))
}

// awaitToken polls the capture file until the access token appears, preferring
// the exchange response (which carries expires_in and user_id) and falling back
// to the Bearer header.
func (r *Relogin) awaitToken(ctx context.Context, capPath string, wait time.Duration) (*AccessToken, error) {
	deadline := r.Now().Add(wait)
	for r.Now().Before(deadline) {
		buf, err := os.ReadFile(capPath)
		if err == nil && len(buf) > 0 {
			if tok := r.extractToken(buf); tok != nil {
				return tok, nil
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r.sleep(2 * time.Second)
	}
	return nil, errors.New("the access token never appeared in the capture")
}

// extractToken returns the access token from a capture, or nil. The exchange
// response wins because it carries the metadata; a lone Bearer header is filled
// out with the configured user id and a one-year lifetime.
func (r *Relogin) extractToken(buf []byte) *AccessToken {
	if at, err := ExtractAccessToken(buf); err == nil {
		return at
	}
	if m := bearerTokenRE.FindSubmatch(buf); m != nil {
		return &AccessToken{Token: string(m[1]), UserID: r.Cfg.DefaultUserID, ExpiresIn: 31536000}
	}
	return nil
}

// verifyAndStore proves the token mints a call token, then writes it to pass in
// the layout the holder reads (the token on the first line, metadata below).
func (r *Relogin) verifyAndStore(ctx context.Context, tok *AccessToken) error {
	if _, err := r.Mint.MintCallToken(ctx, tok.Token); err != nil {
		return fmt.Errorf("the captured token does not mint: %w", err)
	}
	uid := tok.UserID
	if uid == "" {
		uid = r.Cfg.DefaultUserID
	}
	if uid == "" {
		uid = "-" // the capture's exchange response carries the real id
	}
	exp := tok.ExpiresIn
	if exp == 0 {
		exp = 31536000
	}
	body := fmt.Sprintf("%s\naccess_token_id: -\nuser_id: %s\nexpires_in: %d\nminted: %s\n"+
		"endpoint: GET https://api.vk.ru/method/messages.getCallToken?env=production&v=5.203&lang=3  (Authorization: Bearer <this>)\n"+
		"note: VK Calls silent-auth access token (app_id 7793118); mints okcdn-valid call_token headlessly.\n",
		tok.Token, uid, exp, r.Now().Format("2006-01-02"))
	err := r.Sh.Input(ctx, body, "pass", "insert", "-m", "-f", r.Cfg.PassAccessToken)
	if err != nil {
		return fmt.Errorf("write access token to pass: %w", err)
	}
	return nil
}

// restartHolder restarts the pool holder so it reads the fresh token.
func (r *Relogin) restartHolder(ctx context.Context) error {
	return r.Sh.Run(ctx, "sudo", "-n", "systemctl", "restart", r.Cfg.HolderService)
}

// poolLive counts the non-dead hashes in the pool file, for the success message.
func (r *Relogin) poolLive(ctx context.Context) int {
	out, err := r.Sh.Output(ctx, "sudo", "-n", "cat", r.Cfg.PoolFile)
	if err != nil {
		return -1
	}
	var pool map[string]struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(out, &pool) != nil {
		return -1
	}
	n := 0
	for _, v := range pool {
		if v.Status != "dead" {
			n++
		}
	}
	return n
}

// secret reads a one-line secret from pass through the sudo wrapper.
func (r *Relogin) secret(ctx context.Context, entry string) (string, error) {
	out, err := r.Sh.Output(ctx, "sudo", "-n", r.Cfg.PassShow, entry)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	if line == "" {
		return "", fmt.Errorf("pass entry %q is empty", entry)
	}
	return line, nil
}

// waitCode blocks for the admin's 6-digit code, which the bot writes (as root,
// 0600) into the shared bridge dir; it is read and removed through sudo.
func (r *Relogin) waitCode(ctx context.Context) (string, error) {
	codeFile := filepath.Join(r.Cfg.WorkDir, "code")
	_ = r.Sh.Run(ctx, "sudo", "-n", "rm", "-f", codeFile)
	deadline := r.Now().Add(r.Cfg.CodeWait)
	for r.Now().Before(deadline) {
		out, err := r.Sh.Output(ctx, "sudo", "-n", "cat", codeFile)
		if err == nil {
			if code := digitsOnly(string(out)); len(code) == 6 {
				_ = r.Sh.Run(ctx, "sudo", "-n", "rm", "-f", codeFile)
				return code, nil
			}
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		r.sleep(2 * time.Second)
	}
	return "", errors.New("the admin's code never arrived")
}

// status writes the one-word phase into the bridge file the bot reads.
func (r *Relogin) status(s string) {
	if r.Cfg.WorkDir == "" {
		return
	}
	_ = os.MkdirAll(r.Cfg.WorkDir, 0o755)
	tmp := filepath.Join(r.Cfg.WorkDir, "status.tmp")
	final := filepath.Join(r.Cfg.WorkDir, "status")
	if os.WriteFile(tmp, []byte(s+"\n"), 0o644) == nil {
		_ = os.Rename(tmp, final)
	}
	if r.Log != nil {
		r.Log.Info("relogin status", "status", s)
	}
}

// telegramNotify is the default notifier: a Markdown message to the bot admin,
// best-effort so a failed send never aborts the relogin.
func (r *Relogin) telegramNotify(ctx context.Context, msg string) {
	token, err := r.secret(ctx, r.Cfg.PassTelegram)
	if err != nil {
		r.Log.Warn("notify: no bot token", "err", err)
		return
	}
	admin, err := r.botAdmin()
	if err != nil {
		r.Log.Warn("notify: no admin", "err", err)
		return
	}
	form := url.Values{}
	form.Set("chat_id", admin)
	form.Set("parse_mode", "Markdown")
	form.Set("text", msg)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.telegram.org/bot"+token+"/sendMessage", strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cl := &http.Client{Timeout: 15 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		r.Log.Warn("notify: send failed", "err", err)
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// botAdmin reads admins[0] from bot.json.
func (r *Relogin) botAdmin() (string, error) {
	raw, err := os.ReadFile(r.Cfg.BotJSON)
	if err != nil {
		return "", err
	}
	var cfg struct {
		Admins []json.Number `json:"admins"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", err
	}
	if len(cfg.Admins) == 0 {
		return "", errors.New("bot.json has no admins")
	}
	return cfg.Admins[0].String(), nil
}

// click moves to a point and presses the left button, the way xdotool wants it
// for this Qt UI (move, down, up, with pauses).
func (r *Relogin) click(ctx context.Context, p Point) {
	x, y := strconv.Itoa(p.X), strconv.Itoa(p.Y)
	_ = r.Sh.Run(ctx, "xdotool", "mousemove", x, y)
	r.sleep(500 * time.Millisecond)
	_ = r.Sh.Run(ctx, "xdotool", "mousedown", "1")
	r.sleep(250 * time.Millisecond)
	_ = r.Sh.Run(ctx, "xdotool", "mouseup", "1")
	r.sleep(700 * time.Millisecond)
}

// typeText types with a per-key delay in milliseconds.
func (r *Relogin) typeText(ctx context.Context, text string, delayMS int) {
	_ = r.Sh.Run(ctx, "xdotool", "type", "--delay", strconv.Itoa(delayMS), text)
}

// pixelIsBlue reports whether the pixel at p is the VK blue of a primary button,
// which distinguishes the cached-session screen from the phone/email form.
func (r *Relogin) pixelIsBlue(ctx context.Context, p Point) bool {
	crop := fmt.Sprintf("1x1+%d+%d", p.X, p.Y)
	out, err := r.Sh.Output(ctx, "import", "-window", "root", "-crop", crop, "-depth", "8", "txt:-")
	if err != nil {
		return false
	}
	m := hexColorRE.FindSubmatch(out)
	if m == nil {
		return false
	}
	v, err := strconv.ParseInt(string(m[1]), 16, 64)
	if err != nil {
		return false
	}
	red := int((v >> 16) & 0xff)
	green := int((v >> 8) & 0xff)
	blue := int(v & 0xff)
	// VK primary blue is ~ (39,135,245): strongly blue, blue well above red.
	return blue > 180 && blue > red+60 && green < blue
}

// stopAll reaps the app, the browser, frida and the X stack by name. Errors are
// ignored: a missing process is the goal.
func (r *Relogin) stopAll(ctx context.Context) {
	for _, name := range []string{r.Cfg.AppProc, "chrome", "x11vnc", "fluxbox", "Xvfb"} {
		_ = r.Sh.Run(ctx, "pkill", "-x", name)
	}
	_ = r.Sh.Run(ctx, "pkill", "-f", "relogin_attach.py")
}

// digitsOnly keeps the digits of s.
func digitsOnly(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteByte(byte(c))
		}
	}
	return b.String()
}

// shellVar reads an integer VAR=... out of xdotool's --shell output.
func shellVar(shellOut []byte, key string) int {
	for _, line := range bytes.Split(shellOut, []byte("\n")) {
		if bytes.HasPrefix(line, []byte(key+"=")) {
			n, _ := strconv.Atoi(string(bytes.TrimPrefix(line, []byte(key+"="))))
			return n
		}
	}
	return 0
}

// --- the real Shell -------------------------------------------------------

// hostShell shells out with the GUI environment set on every command.
type hostShell struct {
	env []string
}

// NewHostShell returns a Shell whose commands see the given X display plus this
// host's user runtime, so xdotool, import and the app all find the session.
func NewHostShell(display string) Shell {
	home := homeDir()
	env := append(os.Environ(),
		"DISPLAY="+display,
		"XDG_RUNTIME_DIR=/run/user/1000",
		"LANG=en_US.UTF-8",
		"PASSWORD_STORE_DIR="+filepath.Join(home, ".password-store"),
		"GNUPGHOME="+filepath.Join(home, ".gnupg"),
	)
	return &hostShell{env: env}
}

func (h *hostShell) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = h.env
	return cmd.Run()
}

func (h *hostShell) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = h.env
	return cmd.Output()
}

func (h *hostShell) Input(ctx context.Context, stdin string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = h.env
	cmd.Stdin = strings.NewReader(stdin)
	return cmd.Run()
}

func (h *hostShell) Background(ctx context.Context, logPath string, name string, args ...string) error {
	cmd := exec.Command(name, args...) // not ctx: it must outlive the step
	cmd.Env = h.env
	if logPath != "" {
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644); err == nil {
			cmd.Stdout, cmd.Stderr = f, f
		}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // reap on its own; we kill by name on cleanup
	return nil
}
