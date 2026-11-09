package monitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDefaultsAreFilledAndAnEmptyStatePathMeansNoPersistence(t *testing.T) {
	m := New(Config{}, "", nil, nil, &fakeNotifier{}, nil)
	if m.cfg.Interval != 30*time.Second || m.cfg.DigestEvery != time.Hour || m.cfg.Location != time.Local {
		t.Errorf("defaults = %+v", m.cfg)
	}
	m.save() // nothing to write to, and no panic
	m.load()
}

func TestRunTicksUntilTheContextEnds(t *testing.T) {
	ticks := 0
	var mu sync.Mutex
	check := Check{Key: "a", Label: "a", Group: GroupCore, Run: func(context.Context) Result {
		mu.Lock()
		ticks++
		mu.Unlock()
		return Result{Status: OK}
	}}
	m := New(Config{Interval: time.Millisecond, Location: time.UTC}, "", []Check{check}, nil, &fakeNotifier{}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := m.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Run = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if ticks < 2 {
		t.Errorf("only %d ticks", ticks)
	}
}

func TestACancelledTickRecordsNothing(t *testing.T) {
	c := &clock{t: at(12, 0)}
	status := Fail
	m := newTestMonitor(t, Config{Threshold: 1}, []Check{{Key: "a", Label: "a", Group: GroupCore, Run: switchable(&status)}}, &fakeNotifier{}, c)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.Tick(ctx)
	if len(m.tr.st.Checks) != 0 {
		t.Errorf("a cancelled round was recorded: %v", keys(m.tr.st.Checks))
	}
}

func TestUnusableStateFilesAreReportedAndNeverFatal(t *testing.T) {
	dir := t.TempDir()
	n := &fakeNotifier{}

	corrupt := filepath.Join(dir, "corrupt.json")
	must(t, os.WriteFile(corrupt, []byte("{"), 0o600))
	if m := New(Config{Location: time.UTC}, corrupt, nil, nil, n, nil); m.tr.st.Checks == nil {
		t.Error("a corrupt state left the tracker without a map")
	}

	// A directory where the file should be cannot be read.
	asDir := filepath.Join(dir, "asdir.json")
	must(t, os.Mkdir(asDir, 0o755))
	New(Config{Location: time.UTC}, asDir, nil, nil, n, nil)

	// A state with no checks key still gets a usable map.
	empty := filepath.Join(dir, "empty.json")
	must(t, os.WriteFile(empty, []byte(`{"last_report":"x"}`), 0o600))
	if m := New(Config{Location: time.UTC}, empty, nil, nil, n, nil); m.tr.st.Checks == nil {
		t.Error("no checks map after loading a state without one")
	}

	// Saving into a directory that is not there is logged, not fatal.
	m := New(Config{Location: time.UTC}, filepath.Join(dir, "gone", "m.json"), nil, nil, n, nil)
	m.save()
}

func TestAFailedDailyReportIsRetriedNotMarkedSent(t *testing.T) {
	c := &clock{t: at(9, 0)}
	n := &fakeNotifier{err: errors.New("telegram down")}
	m := newTestMonitor(t, Config{Threshold: 1, ReportTimes: []string{"09:00"}}, nil, n, c)
	m.report(context.Background())
	if m.tr.st.LastReport != "" {
		t.Errorf("a failed report was marked as sent: %q", m.tr.st.LastReport)
	}
}

func TestProcFilesThatAreMissingOrMalformedGiveUnknownNotAGuess(t *testing.T) {
	// Listeners: nothing under the root, then a directory in place of a table.
	if _, _, err := (Listeners{Root: t.TempDir()}).Ports(); err == nil {
		t.Error("an empty proc was accepted")
	}
	broken := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(broken, "net", "tcp"), 0o755))
	if _, _, err := (Listeners{Root: broken}).Ports(); err == nil {
		t.Error("an unreadable table was accepted")
	}
	// Malformed lines and ports are skipped.
	root := t.TempDir()
	writeProcNet(t, root, map[string]string{
		"tcp": "short\n  0: nocolon 00000000:0000 0A 0 0\n  1: 00000000:ZZZZ 00000000:0000 0A 0 0\n  2: 00000000:0050 00000000:0000 0A 0 0\n",
	})
	tcp, _, err := (Listeners{Root: root}).Ports()
	if err != nil || len(tcp) != 1 || !tcp[0x50] {
		t.Errorf("ports = %v, %v", tcp, err)
	}
	if (Listeners{}).Root != "" {
		t.Error("zero Root")
	}
	if got := (Resources{}).root(); got != "/proc" {
		t.Errorf("default root = %q", got)
	}

	r := Resources{Root: t.TempDir(), Limits: Limits{MemPct: 90, DiskPct: 90, ConntrackPct: 90}}
	if got := r.mem(); got.Status != Unknown {
		t.Errorf("no meminfo: %+v", got)
	}
	must(t, os.WriteFile(filepath.Join(r.Root, "meminfo"), []byte("garbage\nEmpty:\nMemFree: 1 kB\n"), 0o644))
	if got := r.mem(); got.Status != Unknown || !strings.Contains(got.Detail, "MemTotal") {
		t.Errorf("no MemTotal: %+v", got)
	}
	if got := r.disk("/definitely/not/a/path"); got.Status != Unknown {
		t.Errorf("missing disk: %+v", got)
	}
	if got := r.conntrack(); got.Status != Unknown || !strings.Contains(got.Detail, "не загружен") {
		t.Errorf("no conntrack: %+v", got)
	}
	ct := filepath.Join(r.Root, "sys", "net", "netfilter")
	must(t, os.MkdirAll(ct, 0o755))
	must(t, os.WriteFile(filepath.Join(ct, "nf_conntrack_count"), []byte("5\n"), 0o644))
	if got := r.conntrack(); got.Status != Unknown || !strings.Contains(got.Detail, "недоступен") {
		t.Errorf("no conntrack max: %+v", got)
	}
	must(t, os.WriteFile(filepath.Join(ct, "nf_conntrack_max"), []byte("0\n"), 0o644))
	if got := r.conntrack(); got.Status != Unknown {
		t.Errorf("zero conntrack max: %+v", got)
	}
}

func TestInboundChecksReportAnUnreadableProcAsUnknown(t *testing.T) {
	m := New(Config{Threshold: 1, Location: time.UTC}, "", nil,
		func(context.Context) ([]Port, error) { return []Port{{"a", 443}}, nil }, &fakeNotifier{}, nil)
	m.listeners = Listeners{Root: t.TempDir()}
	checks := m.due(context.Background())
	if len(checks) != 1 {
		t.Fatalf("checks = %d", len(checks))
	}
	if got := checks[0].Run(context.Background()); got.Status != Unknown {
		t.Errorf("got %+v", got)
	}
}

func TestWorldProbeHandlesEveryWayTheServiceMisbehaves(t *testing.T) {
	handler := func(start func(w http.ResponseWriter), result func(w http.ResponseWriter)) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/check-tcp") {
				start(w)
				return
			}
			result(w)
		}))
	}
	okStart := func(w http.ResponseWriter) { fmt.Fprint(w, `{"request_id":"r","nodes":{}}`) }
	probe := func(srv *httptest.Server, wait time.Duration) Result {
		defer srv.Close()
		return World{BaseURL: srv.URL, Poll: time.Millisecond, Wait: wait}.Probe(context.Background(), "h", 1)
	}

	// The service refuses to start a check.
	if r := probe(handler(func(w http.ResponseWriter) { http.Error(w, "no", 500) }, nil), time.Second); r.Status != Unknown || !strings.Contains(r.Detail, "HTTP 500") {
		t.Errorf("start 500: %+v", r)
	}
	// It starts one but names no request.
	if r := probe(handler(func(w http.ResponseWriter) { fmt.Fprint(w, `{}`) }, nil), time.Second); r.Status != Unknown || !strings.Contains(r.Detail, "request_id") {
		t.Errorf("no request id: %+v", r)
	}
	// Results never become readable: it gives up as Unknown.
	if r := probe(handler(okStart, func(w http.ResponseWriter) { http.Error(w, "busy", 503) }), 30*time.Millisecond); r.Status != Unknown || !strings.Contains(r.Detail, "не ответил") {
		t.Errorf("unreadable results: %+v", r)
	}
	// No node ever finishes.
	if r := probe(handler(okStart, func(w http.ResponseWriter) { fmt.Fprint(w, `{"n1":null}`) }), 30*time.Millisecond); r.Status != Unknown {
		t.Errorf("unfinished nodes: %+v", r)
	}
	// With the node count unannounced, the count of answers decides.
	if r := probe(handler(okStart, func(w http.ResponseWriter) { fmt.Fprint(w, `{"n1":[{"time":1}]}`) }), time.Second); r.Status != OK || r.Detail != "1/1 узлов" {
		t.Errorf("unannounced nodes: %+v", r)
	}

	// Cancellation while polling.
	srv := handler(okStart, func(w http.ResponseWriter) { fmt.Fprint(w, `{"n1":null}`) })
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := (World{BaseURL: srv.URL, Poll: time.Hour, Wait: time.Hour}).Probe(ctx, "h", 1); r.Status != Unknown {
		t.Errorf("cancelled: %+v", r)
	}
	if (World{}).BaseURL != "" {
		t.Error("zero BaseURL")
	}
}

func TestWorldProbeBuildsItsRequestOrFails(t *testing.T) {
	w := World{BaseURL: "http://[::1"} // not a URL
	if r := w.Probe(context.Background(), "h", 1); r.Status != Unknown {
		t.Errorf("bad URL: %+v", r)
	}
}

// socks5 is the smallest proxy that satisfies a client: no auth, CONNECT only.
func socks5(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 262)
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, buf[:4]); err != nil {
					return
				}
				var host string
				switch buf[3] {
				case 1:
					io.ReadFull(c, buf[:4])
					host = net.IP(buf[:4]).String()
				case 3:
					io.ReadFull(c, buf[:1])
					n := int(buf[0])
					io.ReadFull(c, buf[:n])
					host = string(buf[:n])
				default:
					return
				}
				io.ReadFull(c, buf[:2])
				port := int(buf[0])<<8 | int(buf[1])
				up, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	return l.Addr().String()
}

func TestEgressComparesTheExitAddressThroughTheProxy(t *testing.T) {
	status, body := http.StatusOK, "203.0.113.9\n"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	defer target.Close()
	proxy := socks5(t)
	probe := func(e Egress) Result {
		e.Socks, e.ProbeURL, e.Timeout = proxy, target.URL, 5*time.Second
		return e.Probe(context.Background())
	}

	if r := probe(Egress{}); r.Status != OK || !strings.Contains(r.Detail, "203.0.113.9") {
		t.Errorf("any answer: %+v", r)
	}
	if r := probe(Egress{ExpectIP: "203.0.113.9"}); r.Status != OK {
		t.Errorf("expected exit: %+v", r)
	}
	if r := probe(Egress{ExpectIP: "198.51.100.1"}); r.Status != Fail || !strings.Contains(r.Detail, "ждали 198.51.100.1") {
		t.Errorf("wrong exit: %+v", r)
	}
	body = strings.Repeat("x", 200)
	if r := probe(Egress{ExpectIP: "198.51.100.1"}); !strings.Contains(r.Detail, "…") {
		t.Errorf("a long answer was not clipped: %+v", r)
	}
	status = http.StatusBadGateway
	if r := probe(Egress{}); r.Status != Fail || !strings.Contains(r.Detail, "HTTP 502") {
		t.Errorf("bad status: %+v", r)
	}
	if r := (Egress{Socks: proxy, ProbeURL: "http://[::1", Timeout: time.Second}).Probe(context.Background()); r.Status != Fail {
		t.Errorf("bad probe URL: %+v", r)
	}
}

func TestSmallTextHelpers(t *testing.T) {
	if clipText("абвгд", 3) != "абв…" || clipText("abc", 5) != "abc" {
		t.Error("clipText")
	}
	if got := shortErr(errors.New("dial tcp 1.2.3.4:5: connect: connection refused")); got != "connection refused" {
		t.Errorf("shortErr = %q", got)
	}
	if got := shortErr(errors.New("short: x")); got != "short: x" {
		t.Errorf("shortErr kept too little: %q", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleep(ctx, time.Hour); err == nil {
		t.Error("cancelled sleep returned nil")
	}
}

func TestTheStatusPageMarksDownUnknownAndQueuedAlerts(t *testing.T) {
	c := &clock{t: at(12, 0)}
	good, bad, unknown := OK, Fail, Unknown
	m := newTestMonitor(t, Config{Threshold: 1}, []Check{
		{Key: "a", Label: "a", Group: GroupCore, Run: switchable(&good)},
		{Key: "b", Label: "b", Group: GroupWorld, Run: switchable(&bad)},
		{Key: "c", Label: "c", Group: GroupEgress, Run: switchable(&unknown)},
	}, &fakeNotifier{}, c)
	m.Tick(context.Background())
	page := m.Status()
	for _, want := range []string{"🔴 b", "❔ c", "🟢 a"} {
		if !strings.Contains(page, want) {
			t.Errorf("status lacks %q:\n%s", want, page)
		}
	}
	m.mu.Lock()
	m.tr.st.Queue = append(m.tr.st.Queue, Event{Label: "x"})
	m.mu.Unlock()
	if !strings.Contains(m.Status(), "В очереди дайджеста") {
		t.Errorf("queue not shown:\n%s", m.Status())
	}
}
