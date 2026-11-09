package exporter

import (
	"database/sql"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildDB creates the accounting schema and runs the extra statements.
func buildDB(t *testing.T, extra ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "user_stats.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range append([]string{
		`CREATE TABLE user_stats_daily (user TEXT, date TEXT, upload INTEGER, download INTEGER, conn_count INTEGER)`,
		`CREATE TABLE user_resources_daily (user TEXT, date TEXT, resource TEXT, upload INTEGER, download INTEGER, conn_count INTEGER)`,
		`CREATE TABLE user_inbounds_daily (user TEXT, date TEXT, inbound TEXT, upload INTEGER, download INTEGER, conn_count INTEGER, bulk_conns INTEGER, max_download INTEGER)`,
	}, extra...) {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	return path
}

func TestCollectDeclaresEveryFamilyBeforeAnySampleAndServesTheData(t *testing.T) {
	today := time.Now().Format("2006-01-02")
	old := time.Now().AddDate(0, 0, -60).Format("2006-01-02")
	db := buildDB(t,
		`INSERT INTO user_stats_daily VALUES ('alice', '`+today+`', 10, 20, 3)`,
		`INSERT INTO user_stats_daily VALUES ('say "hi"\n', '`+today+`', 1, 2, 3)`,
		`INSERT INTO user_stats_daily VALUES ('alice', '`+old+`', 99, 99, 99)`,
		`INSERT INTO user_resources_daily VALUES ('alice', '`+today+`', 'www.google.com', 5, 50, 2)`,
		`INSERT INTO user_resources_daily VALUES ('alice', '`+today+`', 'telegram.org', 1, 500, 1)`,
	)
	log := filepath.Join(t.TempDir(), "sing-box.log")
	os.WriteFile(log, []byte("XDP blocked 1.2.3.4 user=alice for 10m0s (total: 4)\n"), 0o600)
	opts := Defaults()
	opts.DatabasePath, opts.LogPath = db, log
	out := New(opts).Collect()

	firstSample := strings.Index(out, "singbox_user_upload_bytes{")
	lastHelp := strings.LastIndex(out[:firstSample], "# TYPE")
	if firstSample < 0 || lastHelp < 0 {
		t.Fatalf("no samples:\n%s", out)
	}
	for _, f := range sqliteFamilies {
		i := strings.Index(out, "# HELP "+f.name+" ")
		if i < 0 || i > firstSample {
			t.Errorf("%s is not declared before the first sample", f.name)
		}
	}
	for _, want := range []string{
		`singbox_user_upload_bytes{user="alice"} 10`,
		`singbox_user_download_bytes{user="alice"} 20`,
		`singbox_user_connections{user="alice"} 3`,
		// A hostile name stays inside its label value instead of breaking the line.
		`singbox_user_upload_bytes{user="say \"hi\"\\n"} 1`,
		`singbox_daily_upload_bytes{user="alice",date="` + today + `"} 10`,
		`singbox_daily_resource_download_bytes{user="alice",date="` + today + `",resource="www.google.com"} 50`,
		`singbox_monthly_service_download_bytes{user="alice",service="Google",resource="www.google.com"} 50`,
		"singbox_xdp_blocks_total 1",
		"singbox_xdp_blocked_ips_current 4",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// History is windowed: a row from 60 days ago is outside the 31-day window.
	if strings.Contains(out, old) {
		t.Errorf("a row older than HistoryDays was exported:\n%s", out)
	}
	// The monthly list is ordered by download, largest first.
	tg := strings.Index(out, `singbox_monthly_service_download_bytes{user="alice",service="Telegram"`)
	gg := strings.Index(out, `singbox_monthly_service_download_bytes{user="alice",service="Google"`)
	if tg < 0 || gg < 0 || tg > gg {
		t.Errorf("top resources are not ordered by download (telegram at %d, google at %d)", tg, gg)
	}
	for _, line := range strings.Split(out, "\n") {
		if line != "" && !strings.HasPrefix(line, "#") && strings.Count(line, `"`)%2 != 0 && !strings.Contains(line, `\"`) {
			t.Errorf("a line with unbalanced quotes: %q", line)
		}
	}
}

func TestServiceTopNLimitsTheMonthlyList(t *testing.T) {
	today := time.Now().Format("2006-01-02")
	db := buildDB(t,
		`INSERT INTO user_resources_daily VALUES ('a', '`+today+`', 'r1.example', 0, 30, 1)`,
		`INSERT INTO user_resources_daily VALUES ('a', '`+today+`', 'r2.example', 0, 20, 1)`,
		`INSERT INTO user_resources_daily VALUES ('a', '`+today+`', 'r3.example', 0, 10, 1)`,
	)
	opts := Defaults()
	opts.DatabasePath, opts.ServiceTopN = db, 2
	out := strings.Join(New(opts).sqliteMetrics(), "\n")
	if n := strings.Count(out, "singbox_monthly_service_download_bytes{"); n != 2 {
		t.Errorf("%d monthly series, want 2:\n%s", n, out)
	}
	if strings.Contains(out, "monthly_service_download_bytes{user=\"a\",service=\"r3.example\"") {
		t.Errorf("the smallest resource made the list:\n%s", out)
	}
}

func TestACorruptOrMissingDatabaseIsACommentNotAFailedScrape(t *testing.T) {
	opts := Defaults()
	opts.DatabasePath = filepath.Join(t.TempDir(), "absent.db")
	opts.LogPath = filepath.Join(t.TempDir(), "absent.log")
	out := New(opts).Collect()
	if !strings.Contains(out, "# sqlite error:") {
		t.Errorf("a missing database was not reported:\n%s", out)
	}
	// The declarations and the XDP series are still served.
	if !strings.Contains(out, "# TYPE singbox_user_upload_bytes gauge") || !strings.Contains(out, "singbox_xdp_blocks_total 0") {
		t.Errorf("a missing database emptied the whole scrape:\n%s", out)
	}
	// And the scrape must not have created the database it was asked to read.
	if _, err := os.Stat(opts.DatabasePath); err == nil {
		t.Error("a scrape created the accounting database (it opens read-only)")
	}

	// A core without the per-inbound table still serves the rest.
	path := filepath.Join(t.TempDir(), "old.db")
	db, _ := sql.Open("sqlite", path)
	db.Exec(`CREATE TABLE user_stats_daily (user TEXT, date TEXT, upload INTEGER, download INTEGER, conn_count INTEGER)`)
	db.Exec(`CREATE TABLE user_resources_daily (user TEXT, date TEXT, resource TEXT, upload INTEGER, download INTEGER, conn_count INTEGER)`)
	db.Exec(`INSERT INTO user_stats_daily VALUES ('a', '` + time.Now().Format("2006-01-02") + `', 1, 2, 3)`)
	db.Close()
	opts.DatabasePath = path
	got := strings.Join(New(opts).sqliteMetrics(), "\n")
	if !strings.Contains(got, `singbox_user_upload_bytes{user="a"} 1`) || !strings.Contains(got, "per-inbound accounting unavailable") {
		t.Errorf("old core:\n%s", got)
	}
}

func TestScrapesCannotWriteToTheAccountingDatabase(t *testing.T) {
	db := buildDB(t)
	before, _ := os.ReadFile(db)
	opts := Defaults()
	opts.DatabasePath = db
	New(opts).Collect()
	after, _ := os.ReadFile(db)
	if string(before) != string(after) {
		t.Error("collecting changed the database file")
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestRunServesMetricsAndStopsWhenAsked(t *testing.T) {
	opts := Defaults()
	opts.DatabasePath = buildDB(t)
	opts.LogPath = filepath.Join(t.TempDir(), "none.log")
	opts.Listen = freePort(t)
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- New(opts).Run(stop) }()

	var resp *http.Response
	var err error
	for i := 0; i < 100; i++ {
		resp, err = http.Get("http://" + opts.Listen + "/metrics")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain; version=0.0.4") ||
		!strings.Contains(string(body), "# TYPE singbox_user_upload_bytes gauge") {
		t.Errorf("metrics: %d %q %q", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	other, err := http.Get("http://" + opts.Listen + "/other")
	if err != nil {
		t.Fatal(err)
	}
	other.Body.Close()
	if other.StatusCode != http.StatusNotFound {
		t.Errorf("/other = %d", other.StatusCode)
	}

	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("a clean stop returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after stop")
	}
}

func TestRunReportsAPortThatIsTaken(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	opts := Defaults()
	opts.Listen = l.Addr().String()
	opts.LogPath = filepath.Join(t.TempDir(), "none.log")
	stop := make(chan struct{})
	defer close(stop)
	if err := New(opts).Run(stop); err == nil {
		t.Error("serving on an occupied port reported success")
	}
}

func TestXDPLoopStopsPromptly(t *testing.T) {
	c := newXDPCounter(filepath.Join(t.TempDir(), "none.log"))
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { c.loop(stop); close(done) }()
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop ignored stop")
	}
}

// rewriteTransport sends the resolver's https://ipinfo.io requests to a test
// server, so the lookup can be exercised without the network.
type rewriteTransport struct{ target *url.URL }

func (r rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = r.target.Scheme, r.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func TestIPInfoOrgStripsTheASNAndBoundsTheBody(t *testing.T) {
	var asked string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		io.WriteString(w, "AS15169 Google LLC\n"+strings.Repeat("x", 1000))
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	r := newServiceResolver(true, time.Second)
	r.client = &http.Client{Transport: rewriteTransport{target}, Timeout: time.Second}

	got := r.ipInfoOrg("203.0.113.9")
	if asked != "/203.0.113.9/org" {
		t.Errorf("asked %q", asked)
	}
	if !strings.HasPrefix(got, "Google LLC") || strings.Contains(got, "AS15169") {
		t.Errorf("org = %q", got)
	}
	if len(got) > 200 {
		t.Errorf("the body was not bounded: %d bytes", len(got))
	}

	// A failing lookup yields nothing, so the label falls back to the resource.
	server.Close()
	if got := r.ipInfoOrg("203.0.113.9"); got != "" {
		t.Errorf("a failed lookup returned %q", got)
	}
	if label := r.Label("203.0.113.9"); label != "203.0.113.9" {
		t.Errorf("fallback label = %q", label)
	}
}
