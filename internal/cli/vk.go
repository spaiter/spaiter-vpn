package cli

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/vk"
)

// runVK dispatches the VK account subcommands. Only "login" exists: it signs in
// to the account whose calls carry the WG-over-VK pool.
func runVK(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: vk login", ErrUsage)
	}
	switch args[0] {
	case "login":
		return runVKLogin(ctx, out, args[1:])
	case "mint":
		return runVKMint(ctx, out, args[1:])
	case "holder":
		return runVKHolder(ctx, out, args[1:])
	case "relogin":
		return runVKRelogin(ctx, out, args[1:])
	default:
		return fmt.Errorf("%w: unknown vk subcommand %q", ErrUsage, args[0])
	}
}

// runVKHolder keeps the WG-over-VK pool alive: it holds N okcdn calls open and
// publishes their join links, re-minting the call token headlessly from the
// stored access token and asking for a relogin only when that token dies. It is
// the Go replacement for vc-holder.py, run as a host service.
func runVKHolder(ctx context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("vk holder", out)
	home, _ := os.UserHomeDir()
	dataDir := fs.String("data-dir", filepath.Join(home, "appdata", "vpn-bot", "data"), "the bot data directory that holds wdtt/vk_hashes.json")
	n := fs.Int("n", 4, "how many calls to hold open")
	heartbeat := fs.Duration("heartbeat", 90*time.Second, "republish the live set this often")
	passEntry := fs.String("pass-entry", "services/vk-calls-access-token", "pass entry holding the one-year access token")
	reloginCmd := fs.String("relogin", "", "override the relogin helper run when the access token dies; empty self-execs `vk relogin`")
	wsHost := fs.String("ws-host", "", "override the okcdn owner-socket host (tests)")
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn vk holder [flags]\n\n")
		fmt.Fprintf(out, "Holds N WG-over-VK calls open and publishes their join links. Re-mints the\n")
		fmt.Fprintf(out, "call token headlessly; runs the relogin helper only when the access token dies.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := state.New(*dataDir)
	if err != nil {
		return fmt.Errorf("open data dir: %w", err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	source := &vk.LiveCallSource{
		OK:          &vk.OKClient{},
		Mint:        &vk.Client{},
		AccessToken: passAccessToken(*passEntry),
		WSHost:      *wsHost,
	}
	relogin := reloginSelfRunner(log)
	if strings.TrimSpace(*reloginCmd) != "" {
		relogin = reloginRunner(*reloginCmd, log)
	}
	holder := &vk.Holder{
		Source:    source,
		Pub:       &storePublisher{store: store, name: "vkcalls-server"},
		Relogin:   relogin,
		N:         *n,
		Heartbeat: *heartbeat,
		Log:       log,
	}
	log.Info("vk holder starting", "n", *n, "data_dir", *dataDir)
	return holder.Run(ctx)
}

// storePublisher writes the holder's live join links into the shared pool,
// replacing its own previous entries each time so a dropped call disappears.
type storePublisher struct {
	store *state.Store
	name  string
}

func (p *storePublisher) Publish(_ context.Context, live []string) error {
	now := state.Now()
	return p.store.UpdateVKHashes(func(fresh state.VKHashes) error {
		for hash, entry := range fresh {
			if entry.ByName == p.name {
				delete(fresh, hash)
			}
		}
		for _, hash := range live {
			added := fresh[hash].Added
			if added == "" {
				added = now
			}
			fresh[hash] = state.VKHash{
				Added: added, Status: "ok", Checked: now,
				Detail: "vkcalls-holder ws2", ByName: p.name,
			}
		}
		return nil
	})
}

// passAccessToken reads the one-year access token from pass. The pass-show
// wrapper runs as the store owner under sudo, so this works from a service
// started as any user.
func passAccessToken(entry string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		raw, err := exec.CommandContext(ctx, "sudo", "-n", "/usr/local/bin/pass-show", entry).Output()
		if err != nil {
			return "", fmt.Errorf("read access token from pass %q: %w", entry, err)
		}
		line := strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
		if line == "" {
			return "", fmt.Errorf("pass entry %q is empty", entry)
		}
		return line, nil
	}
}

// reloginRunner runs the GUI relogin helper. That helper drives the VK Calls app
// to fetch a fresh one-year token and notifies the admin through the bot for the
// verification code; it is the one piece that cannot be Go, because it automates
// a GUI. An empty path disables it (the holder then just waits).
func reloginRunner(path string, log *slog.Logger) func(context.Context) error {
	return func(ctx context.Context) error {
		if strings.TrimSpace(path) == "" {
			return errors.New("no relogin helper configured")
		}
		cmd := exec.CommandContext(ctx, "bash", path)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		return cmd.Run()
	}
}

// reloginSelfRunner runs this same binary's `vk relogin` to refresh the access
// token. It is the default the holder uses, so the once-a-year sign-in is the
// Go command, not a shell script.
func reloginSelfRunner(log *slog.Logger) func(context.Context) error {
	return func(ctx context.Context) error {
		self, err := os.Executable()
		if err != nil {
			return fmt.Errorf("find own binary for relogin: %w", err)
		}
		log.Info("running vk relogin to refresh the access token")
		cmd := exec.CommandContext(ctx, self, "vk", "relogin")
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		return cmd.Run()
	}
}

// runVKRelogin refreshes the one-year access token by driving the VK Calls app's
// sign-in once (plain launch + frida attach), capturing the fresh token, storing
// it in pass and restarting the pool holder. It is the Go replacement for
// vc-relogin.sh. The verification code is delivered through the bot's /vkcode.
func runVKRelogin(ctx context.Context, out io.Writer, args []string) error {
	cfg := vk.DefaultReloginConfig()
	fs := newFlagSet("vk relogin", out)
	fs.StringVar(&cfg.Display, "display", cfg.Display, "X display to drive")
	fs.StringVar(&cfg.AppBin, "app", cfg.AppBin, "the VK Calls launcher")
	fs.StringVar(&cfg.WorkDir, "work-dir", cfg.WorkDir, "bridge dir shared with the bot (status + code)")
	fs.StringVar(&cfg.PassAccessToken, "pass-entry", cfg.PassAccessToken, "pass entry to write the fresh token to")
	fs.StringVar(&cfg.HolderService, "holder-service", cfg.HolderService, "holder unit to restart on success")
	fs.DurationVar(&cfg.CodeWait, "code-wait", cfg.CodeWait, "how long to wait for the admin's 6-digit code")
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn vk relogin [flags]\n\n")
		fmt.Fprintf(out, "Refreshes the one-year VK Calls access token by driving the app sign-in once,\n")
		fmt.Fprintf(out, "then stores it in pass and restarts the pool holder. The 6-digit verification\n")
		fmt.Fprintf(out, "code is asked for through the Telegram bot (/vkcode). Replaces vc-relogin.sh.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	r := &vk.Relogin{Cfg: cfg, Log: log}
	if err := r.Run(ctx); err != nil {
		return err
	}
	fmt.Fprintln(out, "vk relogin: access token refreshed and holder restarted")
	return nil
}

// runVKMint turns a stored access token into a fresh okcdn call token with no
// browser and no GUI -- the headless half of keeping the WG-over-VK pool alive.
//
// The access token is read from stdin, never a flag: it is a year-long bearer
// credential, and an argument lands in /proc and the shell history. The usual
// caller is `pass show services/vk-calls-access-token | spaiter-vpn vk mint`.
// A dead access token exits 2 so a wrapper can tell "mint this again later"
// (transient) from "a human must sign in again" (expired).
func runVKMint(ctx context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("vk mint", out)
	version := fs.String("api-version", vk.CallsAPIVersion, "getCallToken API version")
	host := fs.String("api-host", vk.CallsAPIHost, "call API host")
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: pass show services/vk-calls-access-token | spaiter-vpn vk mint\n\n")
		fmt.Fprintf(out, "Reads a VK Calls access token from stdin (first line) and prints the\n")
		fmt.Fprintf(out, "okcdn call token as JSON: {\"call_token\":\"...\",\"api_base_url\":\"...\"}.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	access, err := firstLine(os.Stdin)
	if err != nil {
		return fmt.Errorf("read access token from stdin: %w", err)
	}
	if access == "" {
		return fmt.Errorf("no access token on stdin")
	}

	client := &vk.Client{APIHost: strings.TrimSpace(*host), Version: strings.TrimSpace(*version)}
	ct, err := client.MintCallToken(ctx, access)
	if err != nil {
		if errors.Is(err, vk.ErrAccessTokenExpired) {
			warn("the access token is expired or invalid; a fresh sign-in is needed")
		}
		return err
	}

	blob, err := json.MarshalIndent(struct {
		CallToken  string `json:"call_token"`
		APIBaseURL string `json:"api_base_url"`
	}{ct.Token, ct.APIBaseURL}, "", "  ")
	if err != nil {
		return err
	}
	_, err = out.Write(append(blob, '\n'))
	return err
}

// firstLine reads the first line from r and trims it, so a token piped with a
// trailing newline (or extra metadata lines) comes back clean.
func firstLine(r io.Reader) (string, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// runVKLogin signs in to a VK account interactively and writes the resulting
// token.
//
// The password and the application secret are read from the terminal without
// echo, never from flags: an argument is readable through /proc for the life of
// the process and lands in shell history. The login and the code are ordinary
// prompts. On a second factor it asks for the code and finishes; on a captcha
// it reports the image URL and stops, because solving one needs a person.
func runVKLogin(_ context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("vk login", out)
	appID := fs.String("app-id", "", "VK application id (asked for if empty)")
	login := fs.String("login", "", "VK login: phone or email (asked for if empty)")
	deviceID := fs.String("device-id", "", "device id to tie the session to (a random one is made if empty)")
	version := fs.String("api-version", vk.DefaultVersion, "VK API version")
	outPath := fs.String("o", "", "write the token JSON here, mode 0600 (default: stdout)")
	mint := fs.Bool("mint", false, "also mint an okcdn call token from the access token and include it")
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn vk login [flags]\n\n")
		fmt.Fprintf(out, "Signs in to a VK account with a login, a password and a verification code,\n")
		fmt.Fprintf(out, "and writes the access token. The password and the application secret are\n")
		fmt.Fprintf(out, "read from the terminal without echo, not from flags.\n\n")
		fmt.Fprintf(out, "With -mint it also calls messages.getCallToken, proving the whole\n")
		fmt.Fprintf(out, "call-token path runs headless from a direct-auth token with no browser.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("vk login needs a terminal to ask for the password and code")
	}
	defer tty.Close()
	in := bufio.NewReader(tty)

	id := strings.TrimSpace(*appID)
	if id == "" {
		if id, err = promptLine(tty, in, "VK application id: "); err != nil {
			return err
		}
	}
	secret, err := readPassphrase("VK application secret: ")
	if err != nil {
		return err
	}
	user := strings.TrimSpace(*login)
	if user == "" {
		if user, err = promptLine(tty, in, "VK login (phone or email): "); err != nil {
			return err
		}
	}
	password, err := readPassphrase("VK password: ")
	if err != nil {
		return err
	}

	device := strings.TrimSpace(*deviceID)
	if device == "" {
		device = randomDeviceID()
	}

	client := &vk.Client{
		AppID:    id,
		Secret:   strings.TrimSpace(secret),
		DeviceID: device,
		Version:  *version,
	}

	token, challenge, err := client.Login(context.Background(), user, password)
	if err != nil {
		return describeVKError(err)
	}
	if challenge != nil {
		where := challenge.Hint
		if challenge.Via != "" {
			where = fmt.Sprintf("%s (%s)", where, challenge.Via)
		}
		fmt.Fprintf(tty, "VK sent a code to %s.\n", where)
		for {
			code, err := promptLine(tty, in, "Code: ")
			if err != nil {
				return err
			}
			token, err = client.SubmitCode(context.Background(), challenge, code)
			if errors.Is(err, vk.ErrWrongCode) {
				fmt.Fprintln(tty, "VK rejected that code; try again.")
				continue
			}
			if err != nil {
				return describeVKError(err)
			}
			break
		}
	}

	record := struct {
		AccessToken string `json:"access_token"`
		UserID      string `json:"user_id"`
		DeviceID    string `json:"device_id"`
		CallToken   string `json:"call_token,omitempty"`
		APIBaseURL  string `json:"api_base_url,omitempty"`
	}{AccessToken: token.Access, UserID: token.UserID, DeviceID: device}

	// -mint answers the open question: does a direct-auth token (not one from
	// the VK ID browser flow) satisfy messages.getCallToken? If it does, the
	// whole relogin is this one Go command and the GUI drops out entirely.
	if *mint {
		ct, err := (&vk.Client{}).MintCallToken(context.Background(), token.Access)
		if err != nil {
			fmt.Fprintf(tty, "signed in, but the call-token mint failed: %v\n", err)
			return err
		}
		record.CallToken = ct.Token
		record.APIBaseURL = ct.APIBaseURL
	}

	blob, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	blob = append(blob, '\n')

	if *outPath == "" {
		fmt.Fprintf(tty, "signed in as user %s\n", token.UserID)
		_, err = out.Write(blob)
		return err
	}
	if err := os.WriteFile(*outPath, blob, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", *outPath, err)
	}
	fmt.Fprintf(out, "signed in as user %s; token written to %s\n", token.UserID, *outPath)
	return nil
}

// describeVKError turns the typed sign-in failures into operator-facing text.
func describeVKError(err error) error {
	var captcha *vk.CaptchaError
	switch {
	case errors.As(err, &captcha):
		return fmt.Errorf("VK demanded a captcha; open %s, then run vk login again", captcha.ImageURL)
	case errors.Is(err, vk.ErrInvalidCredentials):
		return fmt.Errorf("VK rejected the login or password")
	default:
		return err
	}
}

// promptLine writes a prompt to the terminal and reads one trimmed line back.
func promptLine(tty io.Writer, in *bufio.Reader, prompt string) (string, error) {
	fmt.Fprint(tty, prompt)
	line, err := in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func randomDeviceID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "spaiter-vpn"
	}
	return hex.EncodeToString(b)
}
