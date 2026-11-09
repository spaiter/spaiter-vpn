package cli

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/web"
)

func trafficDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "user_stats.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	today := time.Now().Format("2006-01-02")
	old := time.Now().AddDate(0, 0, -20).Format("2006-01-02")
	for _, s := range []string{
		`CREATE TABLE user_stats_daily (user TEXT, date TEXT, upload INTEGER, download INTEGER, conn_count INTEGER)`,
		`CREATE TABLE user_resources_daily (user TEXT, date TEXT, resource TEXT, upload INTEGER, download INTEGER, conn_count INTEGER)`,
		`INSERT INTO user_stats_daily VALUES ('alice','` + today + `', 1024, 1048576, 10)`,
		`INSERT INTO user_stats_daily VALUES ('bob','` + today + `', 2048, 4194304, 5)`,
		`INSERT INTO user_stats_daily VALUES ('bob','` + old + `', 999999999, 999999999, 99)`,
		`INSERT INTO user_resources_daily VALUES ('alice','` + today + `', 'example.org', 10, 5000, 2)`,
		`INSERT INTO user_resources_daily VALUES ('alice','` + today + `', 'cdn.example', 10, 9000, 3)`,
		`INSERT INTO user_resources_daily VALUES ('alice','` + old + `', 'ancient.example', 1, 1, 1)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestStatsTotalsRankByDownloadAndIgnoreOldDays(t *testing.T) {
	var out bytes.Buffer
	if err := runStats(context.Background(), &out, []string{"-db", trafficDB(t), "-days", "7"}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if strings.Index(s, "bob") > strings.Index(s, "alice") || !strings.Contains(s, "total") {
		t.Errorf("not ranked by download:\n%s", s)
	}
	// 5 MiB of downloads in the window; the 40-day-old row must not leak in.
	if !strings.Contains(s, "5.0 MiB") || strings.Contains(s, "GiB") {
		t.Errorf("window wrong:\n%s", s)
	}
	out.Reset()
	if err := runStats(context.Background(), &out, []string{"-db", trafficDB(t), "-days", "1"}); err != nil || !strings.Contains(out.String(), "last 1 days") {
		t.Errorf("%v\n%s", err, out.String())
	}
}

func TestStatsUserResourcesTopN(t *testing.T) {
	db := trafficDB(t)
	var out bytes.Buffer
	if err := runStats(context.Background(), &out, []string{"-db", db, "-user", "alice", "-days", "7"}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if strings.Index(s, "cdn.example") > strings.Index(s, "example.org") || strings.Contains(s, "ancient") {
		t.Errorf("order or window wrong:\n%s", s)
	}
	out.Reset()
	runStats(context.Background(), &out, []string{"-db", db, "-user", "alice", "-top", "1"})
	if strings.Contains(out.String(), "example.org") || !strings.Contains(out.String(), "top 1 destinations") {
		t.Errorf("top ignored:\n%s", out.String())
	}
	out.Reset()
	if err := runStats(context.Background(), &out, []string{"-db", db, "-user", "nobody"}); err != nil ||
		!strings.Contains(out.String(), `No traffic recorded for "nobody"`) {
		t.Errorf("%v\n%s", err, out.String())
	}
}

func TestStatsEmptyAndMissingDatabase(t *testing.T) {
	var out bytes.Buffer
	if err := runStats(context.Background(), &out, []string{"-db", statsDB(t, false)}); err != nil || !strings.Contains(out.String(), "No traffic recorded since") {
		t.Errorf("%v\n%s", err, out.String())
	}
	if err := runStats(context.Background(), &out, []string{"-dir", t.TempDir()}); err == nil || !strings.Contains(err.Error(), "no stats database") {
		t.Errorf("err = %v", err)
	}
}

func TestClientsWritesPrivateBundlesPerUser(t *testing.T) {
	sb := fakeSingBox(t, "exit 0")
	dir := filepath.Join(t.TempDir(), "sb")
	if out, err := runInitCapture(t, initArgs(dir, sb)...); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var out bytes.Buffer
	if err := runClients(context.Background(), &out, []string{"-dir", dir, "-host", "vpn.example.net", "-sing-box", sb}); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "sing-box check: ok") || !strings.Contains(out.String(), "127.0.0.1:") {
		t.Errorf("out:\n%s", out.String())
	}
	for _, user := range []string{"alice", "bob"} {
		ud := filepath.Join(dir, "clients", user)
		if m := mode(t, ud); m != 0o700 {
			t.Errorf("%s is %v", ud, m)
		}
		entries, _ := os.ReadDir(ud)
		names := map[string]bool{}
		for _, e := range entries {
			names[e.Name()] = true
			if m := mode(t, filepath.Join(ud, e.Name())); m != 0o600 {
				t.Errorf("%s/%s is %v: it is a credential", user, e.Name(), m)
			}
		}
		if !names["sing-box.json"] || !names["urls.txt"] || !names["subscription.txt"] {
			t.Errorf("%s has %v", user, names)
		}
	}
	urls, _ := os.ReadFile(filepath.Join(dir, "clients", "alice", "urls.txt"))
	if !strings.Contains(string(urls), "vpn.example.net") {
		t.Errorf("urls do not carry the host:\n%s", urls)
	}

	// -out redirects; a validator that refuses stops anything being written.
	bad := fakeSingBox(t, "echo nope >&2; exit 1")
	other := filepath.Join(t.TempDir(), "elsewhere")
	err := runClients(context.Background(), &out, []string{"-dir", dir, "-host", "h", "-sing-box", bad, "-out", other})
	if err == nil || !strings.Contains(err.Error(), "is not usable") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(other); statErr == nil {
		t.Error("unvalidated client configs were written")
	}
	if err := runClients(context.Background(), &out, []string{"-dir", dir, "-host", "h", "-skip-check", "-out", other}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(other, "alice", "sing-box.json")); err != nil {
		t.Error(err)
	}
}

func TestClientsRejectsBadInput(t *testing.T) {
	var out bytes.Buffer
	ctx := context.Background()
	if err := runClients(ctx, &out, nil); !errors.Is(err, ErrUsage) {
		t.Errorf("no host: %v", err)
	}
	if err := runClients(ctx, &out, []string{"-host", "h", "-cdn-port", "70000"}); !errors.Is(err, ErrUsage) {
		t.Errorf("cdn port: %v", err)
	}
	if err := runClients(ctx, &out, []string{"-host", "h", "-dir", t.TempDir()}); err == nil || !strings.Contains(err.Error(), "read") {
		t.Errorf("no secrets: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "s.json")
	os.WriteFile(bad, []byte("{"), 0o600)
	if err := runClients(ctx, &out, []string{"-host", "h", "-secrets", bad}); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("bad secrets: %v", err)
	}
	// No validator available: say how to proceed rather than skipping silently.
	sb := fakeSingBox(t, "exit 0")
	dir := filepath.Join(t.TempDir(), "sb")
	if o, err := runInitCapture(t, initArgs(dir, sb)...); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	t.Setenv("PATH", t.TempDir())
	if err := runClients(ctx, &out, []string{"-host", "h", "-dir", dir}); err == nil || !strings.Contains(err.Error(), "-skip-check") {
		t.Errorf("no validator: %v", err)
	}
}

func TestWebKeyIsCreatedOnceAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web.key")
	var out bytes.Buffer
	if err := runWeb(context.Background(), &out, []string{"key", "-key", path}); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, path); m != 0o600 {
		t.Errorf("key is %v", m)
	}
	first, _ := os.ReadFile(path)
	if err := runWeb(context.Background(), &out, []string{"key", "-key", path}); err == nil || !strings.Contains(err.Error(), "never replaced") {
		t.Errorf("an existing key was replaced: %v", err)
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(first, again) {
		t.Error("the key changed")
	}
	// A symlink is not followed to somewhere else.
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(filepath.Join(t.TempDir(), "target"), link)
	if err := runWeb(context.Background(), &out, []string{"key", "-key", link}); err == nil {
		t.Error("a dangling symlink was followed")
	}
	// The group option only widens the mode when asked, to 0640.
	grp := filepath.Join(t.TempDir(), "g.key")
	if err := runWeb(context.Background(), &out, []string{"key", "-key", grp, "-group", strconv.Itoa(os.Getgid())}); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, grp); m != 0o640 {
		t.Errorf("group key is %v", m)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestWebLoginLinkIsSignedByTheKeyAndBounded(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "web.key")
	var out bytes.Buffer
	if err := runWeb(context.Background(), &out, []string{"key", "-key", keyPath}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runWeb(context.Background(), &out, []string{"login-link", "-key", keyPath, "-url", "https://vpn.example.net/"}); err != nil {
		t.Fatal(err)
	}
	link := strings.TrimSpace(out.String())
	if !strings.HasPrefix(link, "https://vpn.example.net/login?token=") {
		t.Fatalf("link = %q", link)
	}

	key, _ := web.LoadKey(keyPath)
	srv := httptest.NewServer((&web.Server{Key: key}).Handler())
	defer srv.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(srv.URL + "/login?token=" + strings.TrimPrefix(link, "https://vpn.example.net/login?token="))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 || len(resp.Cookies()) == 0 {
		t.Errorf("the server did not accept the link: %d, cookies %v", resp.StatusCode, resp.Cookies())
	}

	for _, ttl := range []string{"0s", "25h", "-1m"} {
		if err := runWeb(context.Background(), &out, []string{"login-link", "-key", keyPath, "-ttl", ttl}); !errors.Is(err, ErrUsage) {
			t.Errorf("ttl %s: %v", ttl, err)
		}
	}
	if err := runWeb(context.Background(), &out, []string{"login-link", "-key", filepath.Join(t.TempDir(), "none")}); err == nil {
		t.Error("no key was not an error")
	}
	open := filepath.Join(t.TempDir(), "open.key")
	os.WriteFile(open, []byte(strings.Repeat("ab", 32)), 0o644)
	if err := runWeb(context.Background(), &out, []string{"login-link", "-key", open}); err == nil {
		t.Error("a world-readable key was used")
	}
}

func TestWebDispatchAndServeGuards(t *testing.T) {
	var out bytes.Buffer
	ctx := context.Background()
	if err := runWeb(ctx, &out, nil); !errors.Is(err, ErrUsage) {
		t.Errorf("no args: %v", err)
	}
	if err := runWeb(ctx, &out, []string{"-h"}); err != nil {
		t.Errorf("-h: %v", err)
	}
	if err := runWeb(ctx, &out, []string{"nope"}); !errors.Is(err, ErrUsage) {
		t.Errorf("unknown: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("serve refuses root")
	}
	if err := runWeb(ctx, &out, []string{"serve", "-listen", "nonsense"}); !errors.Is(err, ErrUsage) {
		t.Errorf("bad listen: %v", err)
	}
	if err := runWeb(ctx, &out, []string{"serve", "-listen", "0.0.0.0:0"}); !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), "-secure-cookie") {
		t.Errorf("public listen without HTTPS: %v", err)
	}
	if err := runWeb(ctx, &out, []string{"serve", "-key", filepath.Join(t.TempDir(), "none")}); err == nil {
		t.Error("serving without a key")
	}
}

func TestWebServeStartsAndStopsWithItsContext(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("serve refuses root")
	}
	keyPath := filepath.Join(t.TempDir(), "web.key")
	var out bytes.Buffer
	if err := runWeb(context.Background(), &out, []string{"key", "-key", keyPath}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var log syncBuffer
	go func() {
		done <- runWeb(ctx, &log, []string{"serve", "-listen", "127.0.0.1:0", "-key", keyPath, "-socket", "/nonexistent"})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(log.String(), "listening on") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
}

func TestDDNSArgumentGuards(t *testing.T) {
	var out bytes.Buffer
	ctx := context.Background()
	if err := runDDNS(ctx, &out, nil); !errors.Is(err, ErrUsage) || !strings.Contains(out.String(), "cloudflare") {
		t.Errorf("usage: %v\n%s", err, out.String())
	}
	if err := runDDNS(ctx, &out, []string{"stop"}); !errors.Is(err, ErrUsage) {
		t.Errorf("wrong verb: %v", err)
	}
	if err := runDDNS(ctx, &out, []string{"run", "-provider", "duckdns", "-host", "a"}); !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), "never goes on the command line") {
		t.Errorf("no token file: %v", err)
	}
	if err := runDDNS(ctx, &out, []string{"run", "-token-file", filepath.Join(t.TempDir(), "none")}); err == nil || !strings.Contains(err.Error(), "read the token") {
		t.Errorf("unreadable token: %v", err)
	}
	token := filepath.Join(t.TempDir(), "token")
	os.WriteFile(token, []byte("secret\n"), 0o600)
	if err := runDDNS(ctx, &out, []string{"run", "-token-file", token, "-provider", "nope", "-host", "a"}); err == nil || !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("unknown provider: %v", err)
	}
	if err := runDDNS(ctx, &out, []string{"run", "-token-file", token, "-provider", "duckdns"}); err == nil || !strings.Contains(err.Error(), "no host") {
		t.Errorf("no host: %v", err)
	}
	if err := runDDNS(ctx, &out, []string{"run", "-token-file", token, "-provider", "dyndns2", "-username", "u", "-server", "https://dyn.example", "-host", "a", "-ipv6"}); err == nil || !strings.Contains(err.Error(), "IPv4 records only") {
		t.Errorf("ipv6 on duckdns: %v", err)
	}
	if strings.Contains(out.String(), "secret") {
		t.Error("the token reached the output")
	}
}
