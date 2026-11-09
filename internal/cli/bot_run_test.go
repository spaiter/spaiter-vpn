package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/servicetest"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

var quietLog = slog.New(slog.DiscardHandler)

// fakeCore answers the slice of the core's management API the bot touches
// while it is being assembled and started.
func fakeCore(t *testing.T) (controller string, applies *int) {
	t.Helper()
	var mu sync.Mutex
	count := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"version":"x"}`) })
	mux.HandleFunc("/manage/apply", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		count++
		mu.Unlock()
		fmt.Fprint(w, `{"message":"ok","inbounds":{"reloaded":["a"],"recreated":["b"],"added":["c"],"removed":["d"]},"endpoints":{"reloaded":["e"]}}`)
	})
	mux.HandleFunc("/manage/inbounds", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"tag":"hy","type":"hysteria2"},{"tag":"odd","type":"vless"}]`)
	})
	mux.HandleFunc("/manage/inbounds/hy", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"type":"hysteria2","tag":"hy","listen_port":10862,"tls":{"enabled":true,"server_name":"x.example"}}`)
	})
	mux.HandleFunc("/manage/inbounds/odd", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `not json`) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), &count
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

// botFiles writes a core config and a bot.json beside each other.
func botFiles(t *testing.T, controller string, tweak func(*botcfg.Config)) (cfgPath string, cfg botcfg.Config) {
	t.Helper()
	dir := t.TempDir()
	corePath := filepath.Join(dir, "core.json")
	core := fmt.Sprintf(`{"experimental":{"clash_api":{"external_controller":%q,"secret":"s"}}}`, controller)
	if err := os.WriteFile(corePath, []byte(core), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = botcfg.ExampleConfig()
	cfg.Core.ConfigPath = corePath
	cfg.Paths.DataDir = filepath.Join(dir, "data")
	cfg.Subscription.Port = freePort(t)
	cfg.Monitor.Disabled = true
	if tweak != nil {
		tweak(&cfg)
	}
	data, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cfgPath = filepath.Join(dir, "bot.json")
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, cfg
}

func TestBotCheckConfigReportsWithoutTouchingAnything(t *testing.T) {
	path, cfg := botFiles(t, "127.0.0.1:1", nil)
	t.Setenv("TELEGRAM_TOKEN", "")
	var out bytes.Buffer
	if err := runBot(context.Background(), &out, []string{"-config", path, "-check-config", "-sub-port", "12345"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{cfg.Core.ConfigPath, "vpn.example.com", ":12345", "TELEGRAM_TOKEN is not set"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("lacks %q:\n%s", want, out.String())
		}
	}
	if _, err := os.Stat(cfg.Paths.DataDir); err == nil {
		t.Error("-check-config created the data directory")
	}
	if err := runBot(context.Background(), &out, []string{"-config", path, "-nope"}); err == nil {
		t.Error("an unknown flag was accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte(`{"typo_key": 1}`), 0o600)
	if err := runBot(context.Background(), &out, []string{"-config", bad}); err == nil {
		t.Error("a config with an unknown key was accepted")
	}
}

func TestBotNeedsATokenUnlessTelegramIsOff(t *testing.T) {
	path, _ := botFiles(t, "127.0.0.1:1", nil)
	t.Setenv("TELEGRAM_TOKEN", "")
	err := runBot(context.Background(), &bytes.Buffer{}, []string{"-config", path})
	if !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), "-no-telegram") {
		t.Errorf("err = %v", err)
	}
}

func TestBotAdoptAndCompareOnAnEmptyStore(t *testing.T) {
	path, _ := botFiles(t, "127.0.0.1:1", nil)
	var out bytes.Buffer
	if err := runBot(context.Background(), &out, []string{"-config", path, "-adopt-hashes"}); err != nil ||
		!strings.Contains(out.String(), "adopted 0 subscription hash(es) without notifying anyone") {
		t.Errorf("%v\n%s", err, out.String())
	}
	out.Reset()
	if err := runBot(context.Background(), &out, []string{"-config", path, "-compare"}); err != nil ||
		!strings.Contains(out.String(), "no subscriptions to compare") {
		t.Errorf("%v\n%s", err, out.String())
	}
}

func TestBuildBotReachesTheCoreTheConfigNames(t *testing.T) {
	_, cfg := botFiles(t, "127.0.0.1:1", nil)
	parts, err := buildBot(cfg, quietLog)
	if err != nil {
		t.Fatal(err)
	}
	if parts.monitor != nil {
		t.Error("a disabled monitor was built")
	}
	if parts.store == nil || parts.svc == nil || parts.refresher == nil || parts.face == nil {
		t.Errorf("parts incomplete: %+v", parts)
	}

	cfg.Core.ConfigPath = filepath.Join(t.TempDir(), "missing.json")
	if _, err := buildBot(cfg, quietLog); err == nil || !strings.Contains(err.Error(), "reach the core") {
		t.Errorf("missing core config: %v", err)
	}

	// A credentials file takes precedence over the core's own config.
	creds := filepath.Join(t.TempDir(), "creds.json")
	os.WriteFile(creds, []byte(`{"controller":"127.0.0.1:1","secret":"s"}`), 0o600)
	cfg.Core.ManagementPath = creds
	if _, err := buildBot(cfg, quietLog); err != nil {
		t.Errorf("credentials file: %v", err)
	}
	cfg.Core.ManagementPath = filepath.Join(t.TempDir(), "gone")
	if _, err := buildBot(cfg, quietLog); err == nil {
		t.Error("a missing credentials file was ignored")
	}
}

func TestBuildBotWiresTheMonitorAndTheWebLogin(t *testing.T) {
	_, cfg := botFiles(t, "127.0.0.1:1", func(c *botcfg.Config) {
		c.Monitor.Disabled = false
		c.Monitor.Disks = []string{"/"}
		c.Monitor.World = []botcfg.MonitorTarget{{Name: "w", Host: "198.51.100.1", Port: 443}}
		c.Monitor.Egress = []botcfg.MonitorEgress{{Name: "e", Socks: "127.0.0.1:1080"}}
		c.Web.URL = "https://vpn.example.net/"
		c.Web.KeyPath = filepath.Join(t.TempDir(), "web.key")
	})
	parts, err := buildBot(cfg, quietLog)
	if err != nil {
		t.Fatal(err)
	}
	if parts.monitor == nil {
		t.Fatal("an enabled monitor was not built")
	}
}

func TestCoreInboundsReadsPortsAndSkipsWhatItCannotParse(t *testing.T) {
	controller, _ := fakeCore(t)
	api, err := manage.New(controller, "s")
	if err != nil {
		t.Fatal(err)
	}
	ports, err := coreInbounds(api)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 1 || ports[0].Tag != "hy" || ports[0].Port != 10862 {
		t.Errorf("ports = %+v", ports)
	}
	dead, _ := manage.New("127.0.0.1:1", "s")
	if _, err := coreInbounds(dead)(context.Background()); err == nil {
		t.Error("an unreachable core was not an error")
	}
}

func TestApplyAdapterTranslatesTheCoresAnswer(t *testing.T) {
	controller, applies := fakeCore(t)
	api, _ := manage.New(controller, "s")
	adapter := applyAdapter{api}
	if err := adapter.Version(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := adapter.Apply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if *applies != 1 || got.Inbounds.Reloaded[0] != "a" || got.Inbounds.Recreated[0] != "b" ||
		got.Inbounds.Added[0] != "c" || got.Inbounds.Removed[0] != "d" || got.Endpoints.Reloaded[0] != "e" {
		t.Errorf("translated wrongly: %+v", got)
	}
	dead, _ := manage.New("127.0.0.1:1", "s")
	if _, err := (applyAdapter{dead}).Apply(context.Background()); err == nil {
		t.Error("an unreachable core applied")
	}
	if err := (applyAdapter{dead}).Version(context.Background()); err == nil {
		t.Error("an unreachable core answered")
	}
}

type recordingNotifier struct {
	mu     sync.Mutex
	users  []string
	admins []string
}

func (r *recordingNotifier) Notify(_ context.Context, uid, text string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users = append(r.users, uid+":"+text)
	return nil
}

func (r *recordingNotifier) NotifyAdmins(_ context.Context, text string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.admins = append(r.admins, text)
	return nil
}

func TestDeferredNotifierDropsUntilTelegramExists(t *testing.T) {
	d := &deferredNotifier{log: quietLog}
	ctx := context.Background()
	if err := d.Notify(ctx, "1", "x"); err != nil {
		t.Errorf("dropping was an error: %v", err)
	}
	if err := d.NotifyAdmins(ctx, "x"); err != nil {
		t.Errorf("dropping was an error: %v", err)
	}
	rec := &recordingNotifier{}
	d.set(rec)
	d.Notify(ctx, "1", "hi")
	d.NotifyAdmins(ctx, "alert")
	if len(rec.users) != 1 || rec.users[0] != "1:hi" || len(rec.admins) != 1 || rec.admins[0] != "alert" {
		t.Errorf("not forwarded: %+v", rec)
	}
}

func TestBotServicesRunWithoutTelegramAndStopOnCancel(t *testing.T) {
	controller, _ := fakeCore(t)
	_, cfg := botFiles(t, controller, func(c *botcfg.Config) { c.Monitor.Disabled = false; c.Monitor.Disks = []string{"/"} })
	parts, err := buildBot(cfg, quietLog)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var out syncBuffer
	done := make(chan error, 1)
	go func() { done <- runBotServices(ctx, &out, cfg, parts, "", true, quietLog) }()

	// The subscription server really listens on the configured port.
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Subscription.Port)
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the subscription server never listened on %s", addr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "Telegram disabled") {
		t.Errorf("out = %q", out.String())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("a cancelled bot returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the bot did not stop")
	}
}

func TestBotServicesStopWhenThePortIsTaken(t *testing.T) {
	_, cfg := botFiles(t, "127.0.0.1:1", nil)
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Subscription.Port))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	parts, err := buildBot(cfg, quietLog)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- runBotServices(context.Background(), &bytes.Buffer{}, cfg, parts, "", true, quietLog) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "subscription server stopped") {
			t.Errorf("err = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a dead subscription server did not stop the bot")
	}
}

// fakeTelegramAPI answers the Bot API well enough for the client to start,
// announce itself and poll.
func fakeTelegramAPI(t *testing.T) (url string, methods func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		mu.Lock()
		seen = append(seen, method)
		mu.Unlock()
		var result any = true
		switch method {
		case "getMe":
			result = map[string]any{"id": 1, "is_bot": true, "first_name": "bot", "username": "bot"}
		case "getUpdates":
			time.Sleep(50 * time.Millisecond)
			result = []any{}
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func TestBotServicesAnswerTelegramAndMountTheMiniApp(t *testing.T) {
	controller, _ := fakeCore(t)
	api, methods := fakeTelegramAPI(t)
	_, cfg := botFiles(t, controller, func(c *botcfg.Config) { c.TelegramAPIURL = api })
	parts, err := buildBot(cfg, quietLog)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var out syncBuffer
	done := make(chan error, 1)
	go func() { done <- runBotServices(ctx, &out, cfg, parts, "123:token", false, quietLog) }()

	deadline := time.Now().Add(8 * time.Second)
	has := func(m string) bool {
		for _, s := range methods() {
			if s == m {
				return true
			}
		}
		return false
	}
	for !(has("getUpdates") && has("setMyCommands")) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !has("getUpdates") || !has("setMyCommands") {
		t.Errorf("the client did not start and announce itself; saw %v", methods())
	}
	if !strings.Contains(out.String(), "answering Telegram") {
		t.Errorf("out = %q", out.String())
	}
	// The Mini App rides on the subscription port.
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/app/", cfg.Subscription.Port))
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Error("the Mini App was not mounted")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("err = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the bot did not stop")
	}

	// A token the API rejects is an error that names the Telegram client.
	cfg.TelegramAPIURL = "http://127.0.0.1:1"
	if err := runBotServices(context.Background(), &bytes.Buffer{}, cfg, parts, "bad", false, quietLog); err == nil ||
		!strings.Contains(err.Error(), "Telegram client") {
		t.Errorf("err = %v", err)
	}
}

func TestBotGuideNeedsAUserAndAFile(t *testing.T) {
	var out bytes.Buffer
	ctx := context.Background()
	for _, args := range [][]string{nil, {"-user", "alice"}, {"-o", "x.html"}, {"-user", "a", "-o", "x", "stray"}} {
		if err := runBotGuide(ctx, &out, args); !errors.Is(err, ErrUsage) {
			t.Errorf("%v: %v", args, err)
		}
	}
	path, _ := botFiles(t, "127.0.0.1:1", nil)
	// The core is unreachable: the build of the guide fails rather than writing an empty one.
	target := filepath.Join(t.TempDir(), "guide.html")
	err := runBotGuide(ctx, &out, []string{"-config", path, "-user", "alice", "-o", target})
	if err == nil {
		t.Error("a guide was written for an unreachable core")
	}
	if _, statErr := os.Stat(target); statErr == nil {
		t.Error("a guide file exists after the failure")
	}
}

func TestRunBotRoutesItsSubcommands(t *testing.T) {
	var out bytes.Buffer
	if err := runBot(context.Background(), &out, []string{"guide"}); !errors.Is(err, ErrUsage) {
		t.Errorf("guide: %v", err)
	}
	if err := runBot(context.Background(), &out, []string{"claim-code", "-data-dir", t.TempDir()}); err != nil {
		t.Errorf("claim-code: %v", err)
	}
}

// guideSetup points a bot.json at the fixture's fake core, served over HTTP.
func guideSetup(t *testing.T) (cfgPath string, fx *servicetest.Fixture) {
	t.Helper()
	fx = servicetest.New(t)
	dir := t.TempDir()
	_, _, corePath := fx.Serve(t, dir)
	cfg := fx.Config
	cfg.Core.ConfigPath = corePath
	cfg.Paths.DataDir = fx.Store.Dir()
	cfg.Monitor.Disabled = true
	data, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cfgPath = filepath.Join(dir, "bot.json")
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, fx
}

func TestBotGuideProvisionsAUserAndWritesTheGuide(t *testing.T) {
	path, fx := guideSetup(t)
	dir := t.TempDir()
	guide := filepath.Join(dir, "guide.html")
	bundle := filepath.Join(dir, "bundle.json")
	var out bytes.Buffer
	err := runBotGuide(context.Background(), &out, []string{"-config", path, "-user", "alice", "-o", guide, "-bundle-out", bundle})
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "wrote "+guide) || !strings.Contains(out.String(), "for alice") {
		t.Errorf("out = %q", out.String())
	}
	for _, p := range []string{guide, bundle} {
		if m := mode(t, p); m != 0o600 {
			t.Errorf("%s is %v: it holds credentials", p, m)
		}
	}
	html, _ := os.ReadFile(guide)
	if !strings.Contains(string(html), "<html") || !strings.Contains(string(html), "alice") {
		t.Errorf("guide is not a page for alice:\n%.300s", html)
	}
	var doc map[string]any
	data, _ := os.ReadFile(bundle)
	if json.Unmarshal(data, &doc) != nil || doc["outbounds"] == nil {
		t.Errorf("bundle is not a client config:\n%.300s", data)
	}
	// The user really exists on the core now, and it was applied once, as one batch.
	adds, _, _ := fx.API.Counts()
	if adds == 0 {
		t.Error("nothing was provisioned on the core")
	}
	if got := fx.API.HTTPApplies(); got != 1 {
		t.Errorf("the core was asked to apply %d times, want one batch", got)
	}

	// Run again: the user is already there, so nothing is added twice.
	before := adds
	if err := runBotGuide(context.Background(), &out, []string{"-config", path, "-user", "alice", "-o", filepath.Join(dir, "again.html")}); err != nil {
		t.Fatal(err)
	}
	if after, _, _ := fx.API.Counts(); after != before {
		t.Errorf("a second guide added %d more users", after-before)
	}
}

func TestBotGuideNeedsTheCoreToBeReachable(t *testing.T) {
	path, _ := guideSetup(t)
	cfg, _ := botcfg.Load(path)
	data, _ := os.ReadFile(cfg.Core.ConfigPath)
	os.WriteFile(cfg.Core.ConfigPath, bytes.ReplaceAll(data, []byte(`"secret":"fixture-secret"`), []byte(`"secret":"wrong"`)), 0o600)
	target := filepath.Join(t.TempDir(), "guide.html")
	err := runBotGuide(context.Background(), &bytes.Buffer{}, []string{"-config", path, "-user", "alice", "-o", target})
	if err == nil {
		t.Error("a guide was built against a core that refuses us")
	}
	if _, statErr := os.Stat(target); statErr == nil {
		t.Error("a guide file exists after the failure")
	}
}
