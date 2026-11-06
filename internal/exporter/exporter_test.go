package exporter

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFamilyNamesAndOrderAreFrozen is the compatibility contract. These names
// and this order are what the Grafana dashboards were built against, so a
// rename does not break loudly — it empties a panel and says nothing. The
// literal strings are repeated here on purpose: a test that derived them from
// the same slice the code uses would pass through any rename.
func TestFamilyNamesAndOrderAreFrozen(t *testing.T) {
	wantSQLite := []string{
		"singbox_user_upload_bytes",
		"singbox_user_download_bytes",
		"singbox_user_connections",
		"singbox_daily_upload_bytes",
		"singbox_daily_download_bytes",
		"singbox_daily_connections",
		"singbox_daily_resource_upload_bytes",
		"singbox_daily_resource_download_bytes",
		"singbox_daily_resource_connections",
		"singbox_monthly_service_upload_bytes",
		"singbox_monthly_service_download_bytes",
		"singbox_monthly_service_connections",
		"singbox_inbound_users",
		"singbox_inbound_download_bytes",
		"singbox_inbound_connections",
		"singbox_inbound_bulk_connections",
		"singbox_inbound_largest_connection_bytes",
	}
	if len(sqliteFamilies) != len(wantSQLite) {
		t.Fatalf("%d SQLite families, want %d", len(sqliteFamilies), len(wantSQLite))
	}
	for i, want := range wantSQLite {
		if sqliteFamilies[i].name != want {
			t.Errorf("family %d is %q, want %q", i, sqliteFamilies[i].name, want)
		}
		if sqliteFamilies[i].help == "" {
			t.Errorf("%s has no help text", want)
		}
	}

	wantXDP := []string{
		"singbox_xdp_blocks_total",
		"singbox_xdp_blocks_by_user_total",
		"singbox_xdp_blocked_ips_current",
	}
	for i, want := range wantXDP {
		if xdpFamilies[i].name != want {
			t.Errorf("xdp family %d is %q, want %q", i, xdpFamilies[i].name, want)
		}
	}
}

// TestEscapeLabelCoversWhatTheOriginalMissed. The exporter being replaced
// escaped only the double quote in one of its four queries. It never showed
// because user names are digits and words — but a name with a backslash would
// have produced a line no Prometheus parser accepts, and the failure would have
// been the whole scrape, not one series.
func TestEscapeLabel(t *testing.T) {
	cases := map[string]string{
		`plain`:       `plain`,
		`has"quote`:   `has\"quote`,
		`back\slash`:  `back\\slash`,
		"new\nline":   `new\nline`,
		`both"\mixed`: `both\"\\mixed`,
	}
	for in, want := range cases {
		if got := escapeLabel(in); got != want {
			t.Errorf("escapeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestServiceFromNameMatchesTheSuffixTable(t *testing.T) {
	cases := map[string]string{
		"lb-in-f14.1e100.net":             "Google",
		"1e100.net":                       "Google",
		"something.googleusercontent.com": "Google Cloud",
		"www.google.com":                  "Google",
		"one.one.one.one":                 "Cloudflare DNS",
		"edge.scdn.co":                    "Spotify",
		// Not in the table: falls back to the last two labels.
		"cdn.example.co.uk": "co.uk",
		// A reverse name that is just an encoded address says nothing.
		"203-0-113-5.provider.example": "",
		"198.51.100.62":                "",
	}
	for in, want := range cases {
		if got := serviceFromName(in); got != want {
			t.Errorf("serviceFromName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestServiceFromIPPrefix(t *testing.T) {
	cases := map[string]string{
		"149.154.167.51": "Telegram",
		"157.240.1.35":   "Meta",
		"142.251.0.1":    "Google",
		"1.1.1.1":        "Cloudflare DNS",
		"2606:4700::1":   "Cloudflare",
		"203.0.113.1":    "",
		"not-an-ip":      "",
	}
	for in, want := range cases {
		if got := serviceFromIPPrefix(in); got != want {
			t.Errorf("serviceFromIPPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestIPInfoIsOffUnlessAsked guards the one deliberate departure from the
// original. The addresses being resolved are the destinations this server's
// users connected to, so a default-on lookup means the server reports where its
// users went to a third party.
func TestIPInfoIsOffUnlessAsked(t *testing.T) {
	if Defaults().ServiceLookupIPInfo {
		t.Fatal("the ipinfo.io lookup is enabled by default")
	}
	// With it off the resolver must not even build a request, and the label
	// falls back to the resource — which is what the original did whenever a
	// lookup failed, so no series changes shape.
	r := newServiceResolver(false, 10*time.Millisecond)
	if got := r.ipInfoOrg("203.0.113.9"); got != "" {
		t.Errorf("a disabled resolver returned %q", got)
	}
	if got := r.Label("203.0.113.9"); got != "203.0.113.9" {
		t.Errorf("fallback label is %q, want the resource itself", got)
	}
}

// TestXDPCounterCountsEachBanOnceAndAttributesIt uses the real log line format.
func TestXDPCounterCountsEachBanOnceAndAttributesIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sing-box.log")
	const lines = "" +
		"+0000 2026-10-23 12:28:31 INFO service/xdp-blocker[xdp]: XDP blocked 203.0.113.66 user=100000006 for 10m0s (total: 1)\n" +
		"+0000 2026-10-23 12:29:02 INFO service/xdp-blocker[xdp]: XDP blocked 203.0.113.7 for 10m0s (total: 2)\n" +
		"+0000 2026-10-23 12:38:31 INFO service/xdp-blocker[xdp]: XDP unblocked 203.0.113.66 (total: 1)\n"
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	c := newXDPCounter(path)
	c.poll()
	got := strings.Join(c.metrics(), "\n")

	for _, want := range []string{
		"singbox_xdp_blocks_total 2",
		`singbox_xdp_blocks_by_user_total{user="-"} 1`,
		`singbox_xdp_blocks_by_user_total{user="100000006"} 1`,
		// The current count comes from the last (total: N), which the unblock
		// line also carries.
		"singbox_xdp_blocked_ips_current 1",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}

	// Polling again must not double-count: the offset has advanced.
	c.poll()
	if !strings.Contains(strings.Join(c.metrics(), "\n"), "singbox_xdp_blocks_total 2") {
		t.Errorf("a second poll re-counted the same lines:\n%s", strings.Join(c.metrics(), "\n"))
	}
}

// TestXDPCounterSurvivesCopytruncate is the rotation case that actually
// happens here: the generated logrotate config uses copytruncate, so the inode
// stays the same and the size drops. A reader watching only the inode would sit
// past the end of the truncated file and never report another ban.
func TestXDPCounterSurvivesCopytruncate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sing-box.log")
	first := "x\nXDP blocked 1.2.3.4 user=a for 10m0s (total: 1)\n"
	if err := os.WriteFile(path, []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newXDPCounter(path)
	c.poll()

	// copytruncate: same file, truncated, then new content appended.
	if err := os.WriteFile(path, []byte("XDP blocked 5.6.7.8 user=b for 10m0s (total: 1)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.poll()

	got := strings.Join(c.metrics(), "\n")
	if !strings.Contains(got, "singbox_xdp_blocks_total 2") {
		t.Errorf("a ban after copytruncate was missed:\n%s", got)
	}
	if !strings.Contains(got, `singbox_xdp_blocks_by_user_total{user="b"} 1`) {
		t.Errorf("the post-rotation ban was not attributed:\n%s", got)
	}
}

func TestEnsurePrimedMakesASingleCollectHonest(t *testing.T) {
	// The bug this guards was real: `metrics -once` collected before the
	// polling goroutine had run and reported zero bans while the log held six.
	dir := t.TempDir()
	path := filepath.Join(dir, "sing-box.log")
	if err := os.WriteFile(path, []byte("XDP blocked 1.2.3.4 user=a for 10m0s (total: 3)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newXDPCounter(path)
	c.ensurePrimed()
	if !strings.Contains(strings.Join(c.metrics(), "\n"), "singbox_xdp_blocks_total 1") {
		t.Error("a collection without a prior poll reported no bans")
	}
}

func TestDefaultsMatchThePythonExporter(t *testing.T) {
	d := Defaults()
	if d.DatabasePath != "/data/user_stats.db" || d.LogPath != "/data/sing-box.log" {
		t.Errorf("paths drifted from the original: %+v", d)
	}
	if d.Listen != ":9102" {
		t.Errorf("listen address is %q, want :9102 — the scrape config targets that port", d.Listen)
	}
	if d.HistoryDays != 31 || d.ServiceTopN != 100 {
		t.Errorf("history/top-n drifted: %d/%d, want 31/100", d.HistoryDays, d.ServiceTopN)
	}
	if d.ServiceLookupTimeout != 600*time.Millisecond {
		t.Errorf("lookup timeout is %v, want 600ms", d.ServiceLookupTimeout)
	}
}

func TestInboundMetrics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user_stats.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	today := time.Now().Format("2006-01-02")
	for _, statement := range []string{
		`CREATE TABLE user_stats_daily (user TEXT, date TEXT, upload INTEGER, download INTEGER, conn_count INTEGER)`,
		`CREATE TABLE user_resources_daily (user TEXT, date TEXT, resource TEXT, upload INTEGER, download INTEGER, conn_count INTEGER)`,
		`CREATE TABLE user_inbounds_daily (user TEXT, date TEXT, inbound TEXT, upload INTEGER, download INTEGER, conn_count INTEGER, bulk_conns INTEGER, max_download INTEGER)`,
		`INSERT INTO user_inbounds_daily VALUES ('a', '` + today + `', 'vless-xhttp-in', 0, 300, 3, 1, 200)`,
		`INSERT INTO user_inbounds_daily VALUES ('b', '` + today + `', 'vless-xhttp-in', 0, 100, 1, 0, 100)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	opts := Defaults()
	opts.DatabasePath = path
	got := strings.Join(New(opts).sqliteMetrics(), "\n")
	for _, want := range []string{
		`singbox_inbound_users{inbound="vless-xhttp-in"} 2`,
		`singbox_inbound_download_bytes{inbound="vless-xhttp-in"} 400`,
		`singbox_inbound_bulk_connections{inbound="vless-xhttp-in"} 1`,
		`singbox_inbound_largest_connection_bytes{inbound="vless-xhttp-in"} 200`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in:\n%s", want, got)
		}
	}
}
