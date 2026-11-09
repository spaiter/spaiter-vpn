package cli

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/control"
)

func backendIn(t *testing.T) (*controlBackend, discover.Layout) {
	t.Helper()
	dir := t.TempDir()
	// No docker on PATH: the backend must report that, not hang or panic.
	t.Setenv("PATH", t.TempDir())
	layout := discover.DefaultLayout()
	layout.ConfigRoot, layout.DataRoot = dir+"/etc", dir+"/var"
	return &controlBackend{layout: layout}, layout
}

func writeDesired(t *testing.T, layout discover.Layout, desired state.State) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(layout.DesiredPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(desired, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.DesiredPath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestControlStatusOfAnEmptyHostSaysWhyThereAreNoServices(t *testing.T) {
	b, _ := backendIn(t)
	got, err := b.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	status := got.(controlStatus)
	if status.DesiredDigest != "" || status.Generation != 0 || status.Services != nil {
		t.Errorf("status = %+v, want nothing known", status)
	}
	if status.ServicesError == "" {
		t.Error("a host without docker reported no reason")
	}
}

func TestControlStatusReportsTheDesiredState(t *testing.T) {
	b, layout := backendIn(t)
	desired := state.Default([]string{"owner", "guest"})
	writeDesired(t, layout, desired)
	got, err := b.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	status := got.(controlStatus)
	if status.DesiredDigest == "" || status.SeedUsers != 2 || status.Image != desired.Deployment.Image || status.Tier == "" {
		t.Errorf("status = %+v", status)
	}
}

func TestControlGenerationsOfAFreshHostAreEmpty(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the transaction manager owns its directory as root")
	}
	b, _ := backendIn(t)
	got, err := b.Generations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if text, _ := json.Marshal(got); strings.Trim(string(text), "[]null") != "" {
		t.Errorf("generations = %s", text)
	}
}

func TestControlOperationsWithoutDesiredStateRefuse(t *testing.T) {
	b, _ := backendIn(t)
	ctx := context.Background()
	var out bytes.Buffer
	if _, err := b.Preflight(ctx, &out); err == nil {
		t.Error("preflight without a desired state passed")
	}
	if _, err := b.Prepare(ctx, control.Change{Kind: control.ChangeImage, Image: "x:1"}, &out); err == nil || !strings.Contains(err.Error(), "read current desired state") {
		t.Errorf("prepare: %v", err)
	}
	if _, err := b.Prepare(ctx, control.Change{Kind: control.ChangeRollback}, &out); err == nil {
		t.Error("a rollback with no generations was prepared")
	}
	if err := b.SelfTest(ctx, &out); err == nil {
		t.Error("a selftest with no config passed")
	}
}

func TestControlPrepareRefusesAnUnknownProtocolBeforePlanning(t *testing.T) {
	b, layout := backendIn(t)
	writeDesired(t, layout, state.Default([]string{"owner"}))
	_, err := b.Prepare(context.Background(), control.Change{Kind: control.ChangeSettings, Ports: map[string]uint16{"ssh": 22}}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "unknown protocol") {
		t.Errorf("err = %v", err)
	}
}

func TestControlSubcommandsReachTheDaemonSocket(t *testing.T) {
	// Nothing listens: every client subcommand must fail with the connection
	// error rather than succeed, and the argument checks must come first.
	socket := filepath.Join(t.TempDir(), "none.sock")
	ctx := context.Background()
	var out bytes.Buffer
	for _, args := range [][]string{
		{"status", "-socket", socket}, {"generations", "-socket", socket}, {"preflight", "-socket", socket},
		{"selftest", "-socket", socket}, {"commit", "-socket", socket, "abc"}, {"cancel", "-socket", socket, "abc"},
		{"prepare", "-socket", socket, "-image", "repo/core:2"},
		{"prepare", "-socket", socket, "-port", "awg-in=10870", "-mtu", "awg-in=1280", "-enable", "mieru-in", "-disable", "snell-in"},
		{"prepare", "-socket", socket, "-rotate", "alice,bob"},
		{"prepare", "-socket", socket, "-rollback", "-generation", "3"},
	} {
		if err := runControl(ctx, &out, args); err == nil {
			t.Errorf("%v succeeded against a missing socket", args)
		}
	}
	for _, args := range [][]string{
		{"commit", "-socket", socket},
		{"prepare", "-socket", socket, "-port", "awg-in"},
		{"prepare", "-socket", socket, "-port", "awg-in=99999"},
		{"prepare", "-socket", socket, "-mtu", "awg-in=x"},
		{"prepare", "-socket", socket},
		{"nonsense"},
		{},
	} {
		if err := runControl(ctx, &out, args); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
	out.Reset()
	if err := runControl(ctx, &out, []string{"unit"}); err != nil || !strings.Contains(out.String(), "[Service]") {
		t.Errorf("unit: %v\n%s", err, out.String())
	}
}

func TestControlServeRefusesNonRootAndBadFlags(t *testing.T) {
	var out bytes.Buffer
	if err := runControlServe(context.Background(), &out, []string{"stray"}); err == nil {
		t.Error("stray argument accepted")
	}
	if os.Geteuid() != 0 {
		if err := runControlServe(context.Background(), &out, nil); err == nil || !strings.Contains(err.Error(), "as root") {
			t.Errorf("non-root: %v", err)
		}
	}
}

func TestMetricsServesTheCoresAccountingAndStopsOnCancel(t *testing.T) {
	db := buildStatsDB(t)
	dir := filepath.Dir(db)
	var once bytes.Buffer
	if err := runMetrics(context.Background(), &once, []string{"-dir", dir, "-once"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(once.String(), "# TYPE") {
		t.Errorf("scrape has no metric families:\n%s", once.String())
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- runMetrics(ctx, &lockedWriter{w: &out}, []string{"-dir", dir, "-listen", addr, "-service-lookup-ipinfo"})
	}()
	var body string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body = string(data)
		break
	}
	if !strings.Contains(body, "# TYPE") {
		t.Errorf("served body = %q", body)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the exporter did not stop on cancel")
	}
	if !strings.Contains(out.String(), "serving /metrics on "+addr) {
		t.Errorf("startup banner missing:\n%s", out.String())
	}
}

func TestMetricsRejectsBadFlags(t *testing.T) {
	var out bytes.Buffer
	if err := runMetrics(context.Background(), &out, []string{"-history-days", "x"}); err == nil {
		t.Error("a bad flag was accepted")
	}
}

// lockedWriter lets the test read the banner while the command still runs.
type lockedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func buildStatsDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "user_stats.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range []string{
		`CREATE TABLE user_stats_daily (user TEXT, date TEXT, upload INTEGER, download INTEGER, conn_count INTEGER)`,
		`CREATE TABLE user_resources_daily (user TEXT, date TEXT, resource TEXT, upload INTEGER, download INTEGER, conn_count INTEGER)`,
		`CREATE TABLE user_inbounds_daily (user TEXT, date TEXT, inbound TEXT, upload INTEGER, download INTEGER, conn_count INTEGER, bulk_conns INTEGER, max_download INTEGER)`,
		`INSERT INTO user_stats_daily VALUES ('alice', '` + time.Now().Format("2006-01-02") + `', 10, 20, 3)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return path
}
