package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeNotifier struct {
	mu   sync.Mutex
	sent []string
	err  error
}

func (f *fakeNotifier) NotifyAdmins(_ context.Context, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, text)
	return nil
}

func (f *fakeNotifier) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.sent
	f.sent = nil
	return out
}

// clock is a settable now.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }
func at(h, m int) time.Time              { return time.Date(2026, 11, 7, h, m, 0, 0, time.UTC) }
func switchable(s *Status) func(context.Context) Result {
	return func(context.Context) Result { return Result{Status: *s, Detail: "d_x"} }
}

func newTestMonitor(t *testing.T, cfg Config, checks []Check, n *fakeNotifier, c *clock) *Monitor {
	t.Helper()
	if cfg.Location == nil {
		cfg.Location = time.UTC
	}
	m := New(cfg, filepath.Join(t.TempDir(), "monitor.json"), checks, nil, n, nil)
	m.now = c.now
	return m
}

func TestTrackerThresholdAndUnknown(t *testing.T) {
	tr := newTracker(3)
	c := Check{Key: "k", Label: "L"}
	now := at(12, 0)
	seq := []struct {
		s    Status
		want string // "", "down", "up"
	}{
		{Fail, ""}, {Fail, ""}, {Unknown, ""}, {Fail, "down"}, {Fail, ""},
		{Unknown, ""}, {OK, "up"}, {OK, ""}, {Fail, ""}, {OK, ""}, {Fail, ""}, {Fail, ""},
	}
	for i, step := range seq {
		ev, ok := tr.observe(now, c, Result{Status: step.s})
		got := ""
		if ok {
			got = map[bool]string{true: "down", false: "up"}[ev.Down]
		}
		if got != step.want {
			t.Fatalf("step %d (%v): got %q, want %q", i, step.s, got, step.want)
		}
	}
	if len(tr.st.Queue) != 2 || len(tr.st.Incidents) != 2 {
		t.Fatalf("queue %d incidents %d, want 2 and 2", len(tr.st.Queue), len(tr.st.Incidents))
	}
}

func TestCheckThresholdOverride(t *testing.T) {
	tr := newTracker(5)
	c := Check{Key: "k", Label: "L", Threshold: 1}
	if _, ok := tr.observe(at(1, 0), c, Result{Status: Fail}); !ok {
		t.Fatal("a threshold of 1 should alert on the first failure")
	}
}

func TestQuietHours(t *testing.T) {
	cases := []struct {
		from, to, hour int
		want           bool
	}{
		{0, 7, 0, true}, {0, 7, 6, true}, {0, 7, 7, false}, {0, 7, 23, false},
		{22, 7, 23, true}, {22, 7, 3, true}, {22, 7, 12, false},
		{5, 5, 5, false},
	}
	for _, c := range cases {
		m := &Monitor{cfg: Config{QuietFrom: c.from, QuietTo: c.to}}
		if got := m.quiet(at(c.hour, 30)); got != c.want {
			t.Errorf("quiet %d-%d at %d: got %v", c.from, c.to, c.hour, got)
		}
	}
}

func TestDigestFirstAlertImmediateThenBatched(t *testing.T) {
	status := Fail
	n := &fakeNotifier{}
	c := &clock{t: at(12, 0)}
	m := newTestMonitor(t, Config{Threshold: 2, DigestEvery: time.Hour}, []Check{
		{Key: "a", Label: "vless_in :443", Group: GroupInbounds, Run: switchable(&status)},
	}, n, c)
	ctx := context.Background()

	m.Tick(ctx)
	if got := n.take(); len(got) != 0 {
		t.Fatalf("one failure must not alert: %v", got)
	}
	c.advance(30 * time.Second)
	m.Tick(ctx)
	got := n.take()
	if len(got) != 1 || !strings.Contains(got[0], "🔴") || !strings.Contains(got[0], `vless\_in`) {
		t.Fatalf("expected an immediate escaped down alert, got %q", got)
	}

	// Flapping within the hour is collected, not sent.
	for range 3 {
		status = OK
		c.advance(time.Minute)
		m.Tick(ctx)
		status = Fail
		c.advance(time.Minute)
		m.Tick(ctx)
		c.advance(time.Minute)
		m.Tick(ctx)
	}
	if got := n.take(); len(got) != 0 {
		t.Fatalf("alerts inside the digest window: %q", got)
	}
	c.advance(time.Hour)
	status = OK
	m.Tick(ctx)
	got = n.take()
	if len(got) != 1 || !strings.Contains(got[0], "событий") || !strings.Contains(got[0], "сейчас в норме") {
		t.Fatalf("expected one digest ending in recovery, got %q", got)
	}
}

func TestDigestWaitsOutQuietHours(t *testing.T) {
	status := Fail
	n := &fakeNotifier{}
	c := &clock{t: at(3, 0)}
	m := newTestMonitor(t, Config{Threshold: 1, QuietFrom: 0, QuietTo: 7}, []Check{
		{Key: "a", Label: "A", Run: switchable(&status)},
	}, n, c)
	m.Tick(context.Background())
	if got := n.take(); len(got) != 0 {
		t.Fatalf("sent during quiet hours: %q", got)
	}
	c.t = at(7, 1)
	m.Tick(context.Background())
	if got := n.take(); len(got) != 1 {
		t.Fatalf("expected the held alert at 07:01, got %q", got)
	}
}

func TestFailedSendKeepsQueue(t *testing.T) {
	status := Fail
	n := &fakeNotifier{err: fmt.Errorf("telegram down")}
	c := &clock{t: at(12, 0)}
	m := newTestMonitor(t, Config{Threshold: 1}, []Check{{Key: "a", Label: "A", Run: switchable(&status)}}, n, c)
	m.Tick(context.Background())
	if len(m.tr.st.Queue) != 1 {
		t.Fatalf("queue lost after a failed send: %d", len(m.tr.st.Queue))
	}
	n.err = nil
	c.advance(time.Minute)
	m.Tick(context.Background())
	if got := n.take(); len(got) != 1 {
		t.Fatalf("expected the retry to deliver, got %q", got)
	}
}

func TestReportPrimedThenSentOncePerTime(t *testing.T) {
	n := &fakeNotifier{}
	c := &clock{t: at(23, 0)}
	status := OK
	m := newTestMonitor(t, Config{ReportTimes: []string{"10:00", "22:00"}}, []Check{
		{Key: "r", Label: "Память", Group: GroupResources, Run: switchable(&status)},
	}, n, c)
	m.primeReport()
	m.Tick(context.Background())
	if got := n.take(); len(got) != 0 {
		t.Fatalf("a restart at 23:00 must not send the 22:00 report: %q", got)
	}
	c.t = at(10, 0).Add(24 * time.Hour)
	m.Tick(context.Background())
	got := n.take()
	if len(got) != 1 || !strings.Contains(got[0], "Сводка") || !strings.Contains(got[0], "Сбоев не было") {
		t.Fatalf("expected the 10:00 report, got %q", got)
	}
	c.advance(time.Minute)
	m.Tick(context.Background())
	if got := n.take(); len(got) != 0 {
		t.Fatalf("report sent twice: %q", got)
	}
}

func TestSlowCheckRunsOnItsOwnCadence(t *testing.T) {
	runs := 0
	c := &clock{t: at(12, 0)}
	m := newTestMonitor(t, Config{}, []Check{{
		Key: "w", Label: "W", Every: 10 * time.Minute,
		Run: func(context.Context) Result { runs++; return Result{Status: OK} },
	}}, &fakeNotifier{}, c)
	for range 5 {
		m.Tick(context.Background())
		c.advance(time.Minute)
	}
	if runs != 1 {
		t.Fatalf("ran %d times in 5 minutes, want 1", runs)
	}
	c.advance(10 * time.Minute)
	m.Tick(context.Background())
	if runs != 2 {
		t.Fatalf("did not run again after its interval: %d", runs)
	}
}

func TestInboundsFollowCoreAndSurviveItsOutage(t *testing.T) {
	root := t.TempDir()
	writeProcNet(t, root, map[string]string{
		"tcp": "  0: 00000000:01BB 00000000:0000 0A 0 0\n  1: 0100007F:1F90 00000000:0000 01 0 0\n",
		"udp": "  0: 00000000:4E20 00000000:0000 07 0 0\n",
	})
	ports := []Port{{"vless-in", 443}, {"hy2-in", 20000}, {"dead-in", 8080}, {"tun-in", 0}, {"skip-in", 1}}
	var coreErr error
	n := &fakeNotifier{}
	c := &clock{t: at(12, 0)}
	m := New(Config{Threshold: 1, Location: time.UTC, SkipInbounds: []string{"skip-in"}},
		filepath.Join(t.TempDir(), "m.json"), nil,
		func(context.Context) ([]Port, error) { return ports, coreErr }, n, nil)
	m.now = c.now
	m.listeners = Listeners{Root: root}

	m.Tick(context.Background())
	st := m.tr.st.Checks
	if len(st) != 3 {
		t.Fatalf("watched %d inbounds, want 3 (port 0 and skipped ignored): %v", len(st), keys(st))
	}
	if st["in:vless-in"].Down || st["in:hy2-in"].Down || !st["in:dead-in"].Down {
		t.Fatalf("wrong verdicts: vless %v hy2 %v dead %v", st["in:vless-in"].Down, st["in:hy2-in"].Down, st["in:dead-in"].Down)
	}

	// The core's API goes away: nothing is forgotten.
	coreErr = fmt.Errorf("connection refused")
	ports = nil
	c.advance(time.Minute)
	m.Tick(context.Background())
	if len(m.tr.st.Checks) != 3 {
		t.Fatalf("inbounds forgotten while the core was unreachable: %v", keys(m.tr.st.Checks))
	}

	// The core is back without dead-in: it is dropped and reported as such.
	coreErr = nil
	ports = []Port{{"vless-in", 443}, {"hy2-in", 20000}}
	c.advance(2 * time.Hour)
	n.take()
	m.Tick(context.Background())
	if _, ok := m.tr.st.Checks["in:dead-in"]; ok {
		t.Fatal("removed inbound is still watched")
	}
	got := strings.Join(n.take(), "\n")
	if !strings.Contains(got, "проверка убрана") {
		t.Fatalf("removal of a down check was not reported: %q", got)
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.json")
	status := Fail
	checks := []Check{{Key: "a", Label: "A", Run: switchable(&status)}}
	n := &fakeNotifier{}
	c := &clock{t: at(3, 0)}
	m := New(Config{Threshold: 2, Location: time.UTC, QuietTo: 7}, path, checks, nil, n, nil)
	m.now = c.now
	m.Tick(context.Background())

	m2 := New(Config{Threshold: 2, Location: time.UTC, QuietTo: 7}, path, checks, nil, n, nil)
	m2.now = c.now
	m2.Tick(context.Background())
	if !m2.tr.st.Checks["a"].Down || len(m2.tr.st.Queue) != 1 {
		t.Fatalf("failure count or queue did not survive the restart: %+v", m2.tr.st)
	}
}

func TestStatusPage(t *testing.T) {
	status := Fail
	c := &clock{t: at(12, 0)}
	m := newTestMonitor(t, Config{Threshold: 3}, []Check{
		{Key: "core", Label: "API ядра", Group: GroupCore, Run: func(context.Context) Result {
			return Result{Status: OK, Latency: 12 * time.Millisecond}
		}},
		{Key: "w", Label: "bhv", Group: GroupWorld, Run: switchable(&status)},
	}, &fakeNotifier{}, c)
	if !strings.Contains(m.Status(), "ещё не прошли") {
		t.Fatal("status before the first tick should say so")
	}
	m.Tick(context.Background())
	s := m.Status()
	for _, want := range []string{"🟢 API ядра", "12 мс", "🟡 bhv", `d\_x`, "Ядро", "Доступность снаружи"} {
		if !strings.Contains(s, want) {
			t.Errorf("status lacks %q:\n%s", want, s)
		}
	}
}

func TestListenersParse(t *testing.T) {
	root := t.TempDir()
	writeProcNet(t, root, map[string]string{
		"tcp":  "  0: 00000000:0016 00000000:0000 0A\n  1: 00000000:0050 01020304:C000 01\n",
		"tcp6": "  0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A\n",
		"udp6": "  0: 00000000000000000000000000000000:2A3B 00000000000000000000000000000000:0000 07\n",
	})
	tcp, udp, err := Listeners{Root: root}.Ports()
	if err != nil {
		t.Fatal(err)
	}
	if !tcp[22] || !tcp[443] || tcp[80] || !udp[0x2A3B] {
		t.Fatalf("tcp %v udp %v", tcp, udp)
	}
	if _, _, err := (Listeners{Root: t.TempDir()}).Ports(); err == nil {
		t.Fatal("no tables should be an error")
	}
}

func TestResources(t *testing.T) {
	root := t.TempDir()
	must(t, os.WriteFile(filepath.Join(root, "meminfo"),
		[]byte("MemTotal:       1000000 kB\nMemFree: 1 kB\nMemAvailable:    50000 kB\n"), 0o644))
	ct := filepath.Join(root, "sys", "net", "netfilter")
	must(t, os.MkdirAll(ct, 0o755))
	must(t, os.WriteFile(filepath.Join(ct, "nf_conntrack_count"), []byte("100\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(ct, "nf_conntrack_max"), []byte("1000\n"), 0o644))

	r := Resources{Root: root, Limits: Limits{MemPct: 90, DiskPct: 101, ConntrackPct: 80}, Disks: []string{root}}
	checks := r.Checks()
	if len(checks) != 3 {
		t.Fatalf("got %d checks", len(checks))
	}
	got := map[string]Result{}
	for _, c := range checks {
		got[c.Key] = c.Run(context.Background())
	}
	if got["res:mem"].Status != Fail || !strings.Contains(got["res:mem"].Detail, "95%") {
		t.Errorf("mem: %+v", got["res:mem"])
	}
	if got["res:conntrack"].Status != OK || got["res:conntrack"].Detail != "100 / 1000 (10%)" {
		t.Errorf("conntrack: %+v", got["res:conntrack"])
	}
	if got["res:disk:"+root].Status != OK {
		t.Errorf("disk: %+v", got["res:disk:"+root])
	}
	if len((Resources{}).Checks()) != 0 {
		t.Error("zero limits should disable every resource check")
	}
}

func TestWorldProbe(t *testing.T) {
	results := []string{
		`{"n1":null,"n2":null,"n3":null}`,
		`{"n1":[{"time":0.1,"address":"1.2.3.4"}],"n2":[{"error":"Connection timed out"}],"n3":null}`,
		`{"n1":[{"time":0.1,"address":"1.2.3.4"}],"n2":[{"error":"Connection timed out"}],"n3":[{"time":0.2}]}`,
	}
	allFail := `{"n1":[{"error":"x"}],"n2":[{"error":"x"}],"n3":[null]}`
	var mu sync.Mutex
	call := 0
	failing := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasPrefix(r.URL.Path, "/check-tcp"):
			if r.URL.Query().Get("host") != "example.org:443" {
				http.Error(w, "bad host", 400)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"request_id": "abc",
				"nodes": map[string]any{"n1": []string{}, "n2": []string{}, "n3": []string{}}})
		case r.URL.Path == "/check-result/abc":
			if failing {
				fmt.Fprint(w, allFail)
				return
			}
			fmt.Fprint(w, results[min(call, len(results)-1)])
			call++
		}
	}))
	defer srv.Close()
	w := World{BaseURL: srv.URL, Poll: time.Millisecond, Wait: 2 * time.Second}

	r := w.Probe(context.Background(), "example.org", 443)
	if r.Status != OK || r.Detail != "2/3 узлов" {
		t.Fatalf("partial success: %+v", r)
	}
	failing = true
	if r := w.Probe(context.Background(), "example.org", 443); r.Status != Fail || r.Detail != "0/3 узлов" {
		t.Fatalf("all failing: %+v", r)
	}
	w.BaseURL = "http://127.0.0.1:1"
	if r := w.Probe(context.Background(), "example.org", 443); r.Status != Unknown {
		t.Fatalf("an unreachable service must be Unknown, got %+v", r)
	}
}

func TestEgressUnreachableProxyFails(t *testing.T) {
	r := Egress{Socks: "127.0.0.1:1", Timeout: time.Second}.Probe(context.Background())
	if r.Status != Fail {
		t.Fatalf("got %+v", r)
	}
}

func TestHumanBytes(t *testing.T) {
	for v, want := range map[uint64]string{512: "512 Б", 2048: "2 КБ", 5 << 20: "5 МБ", 3 << 30: "3.0 ГБ"} {
		if got := HumanBytes(v); got != want {
			t.Errorf("%d: %q, want %q", v, got, want)
		}
	}
}

func writeProcNet(t *testing.T, root string, tables map[string]string) {
	t.Helper()
	dir := filepath.Join(root, "net")
	must(t, os.MkdirAll(dir, 0o755))
	for name, body := range tables {
		must(t, os.WriteFile(filepath.Join(dir, name), []byte("  sl  local_address rem_address   st\n"+body), 0o644))
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
