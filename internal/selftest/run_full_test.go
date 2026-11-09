package selftest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/corelog"
)

func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return uint16(l.LocalAddr().(*net.UDPAddr).Port)
}

// coreWithEndpoint is a management API that behaves like the core for the one
// endpoint the self-test adds: the first apply starts a listener on the test
// port, the second stops it.
func coreWithEndpoint(t *testing.T, port uint16, tag string) func(w http.ResponseWriter, r *http.Request) {
	var mu sync.Mutex
	applies := 0
	var listener net.PacketConn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		if listener != nil {
			listener.Close()
		}
	})
	return func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == "POST" && r.URL.Path == "/manage/apply":
			applies++
			if applies == 1 {
				l, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				listener = l
				fmt.Fprintf(w, `{"message":"ok","endpoints":{"added":[%q]}}`, tag)
				return
			}
			if listener != nil {
				listener.Close()
				listener = nil
			}
			fmt.Fprintf(w, `{"message":"ok","endpoints":{"removed":[%q]}}`, tag)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}
}

// scriptedTunnel stands in for the host's WireGuard interface: what the core
// would log when each datagram arrives is decided by the test.
type scriptedTunnel struct {
	logPath      string
	tag          string
	lines        func(port uint16) []string
	handshakeErr error
	sendErr      error
	closeErr     error
	sent         []uint16
	closed       bool
}

func (s *scriptedTunnel) WaitHandshake(context.Context, time.Duration) error { return s.handshakeErr }
func (s *scriptedTunnel) Close() error                                       { s.closed = true; return s.closeErr }
func (s *scriptedTunnel) Send(dst netip.AddrPort, _ []byte) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sent = append(s.sent, dst.Port())
	f, err := os.OpenFile(s.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, line := range s.lines(dst.Port()) {
		fmt.Fprintln(f, strings.ReplaceAll(strings.ReplaceAll(line, "{dst}", dst.String()), "{tag}", s.tag))
	}
	return nil
}

const (
	detectionFmt = "+0000 2026-11-08 10:00:00 INFO router: bittorrent sniff detection: network=udp, detector=%s, inbound={tag}, source=10.99.0.3:4444, destination={dst}, payload_bytes=40"
	rejectLog    = "+0000 2026-11-08 10:00:00 DEBUG router: match[1] protocol=bittorrent => reject(drop,xdp-block)"
)

var goodLog = func(port uint16) []string {
	detector := map[uint16]string{6881: "dht", 6969: "udp-tracker-connect", 6771: "lsd-bt-search"}[port]
	if detector == "" {
		return nil // the control datagram is not flagged
	}
	return []string{fmt.Sprintf(detectionFmt, detector), rejectLog}
}

func runWith(t *testing.T, level string, tunnel *scriptedTunnel, mutate func(*Options)) (*Result, string, error) {
	t.Helper()
	port := freeUDPPort(t)
	opts, _ := liveFixture(t, nil)
	opts.Port = port
	opts.SettleDelay = 0
	opts.HandshakeTimeout = time.Second
	// Rebuild the fixture around the stateful core and the requested log level.
	opts, _ = liveFixtureAt(t, level, coreWithEndpoint(t, port, opts.Tag), opts)
	tunnel.logPath, tunnel.tag = opts.LogPath, opts.Tag
	old := createTunnel
	createTunnel = func(TunnelConfig) (tunnelClient, error) { return tunnel, nil }
	t.Cleanup(func() { createTunnel = old })
	if mutate != nil {
		mutate(&opts)
	}
	var out bytes.Buffer
	res, err := Run(context.Background(), &out, opts)
	return res, out.String(), err
}

func TestRunPassesWhenEveryProbeIsDetectedAndRejected(t *testing.T) {
	tun := &scriptedTunnel{lines: goodLog}
	res, out, err := runWith(t, "debug", tun, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(res.Detections) != 3 || len(res.Rejections) != 3 {
		t.Errorf("detections %d, rejections %d", len(res.Detections), len(res.Rejections))
	}
	if len(tun.sent) != 4 || !tun.closed {
		t.Errorf("sent %v, closed %v", tun.sent, tun.closed)
	}
	for _, want := range []string{"handshake complete", "PASS  :5353", "detector=dht", "detector=udp-tracker-connect", "detector=lsd-bt-search", "reject actions: drop,xdp-block", "removed, and", "production endpoints verified"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestRunNotesALoopbackPeerSkip(t *testing.T) {
	tun := &scriptedTunnel{lines: func(port uint16) []string {
		return append(goodLog(port), "+0000 x DEBUG router: XDP: skipping local peer endpoint 127.0.0.1 for 10.99.0.3")
	}}
	res, out, err := runWith(t, "debug", tun, nil)
	if err != nil || !res.LocalPeerSkipped || !strings.Contains(out, "XDP skipped the loopback peer") {
		t.Fatalf("%v skipped=%v\n%s", err, res != nil && res.LocalPeerSkipped, out)
	}
}

func TestRunFailsOnEachWayTheSnifferCanBeWrong(t *testing.T) {
	cases := map[string]struct {
		lines func(port uint16) []string
		want  string
	}{
		"a missed detection": {
			lines: func(port uint16) []string {
				if port == 6881 {
					return nil
				}
				return goodLog(port)
			},
			want: "no detection for dht",
		},
		"a false positive on the control": {
			lines: func(port uint16) []string {
				if port == 5353 {
					return []string{fmt.Sprintf(detectionFmt, "dht")}
				}
				return goodLog(port)
			},
			want: "control datagram on port 5353 was flagged",
		},
		"the wrong detector": {
			lines: func(port uint16) []string {
				if port == 6969 {
					return []string{fmt.Sprintf(detectionFmt, "dht"), rejectLog}
				}
				return goodLog(port)
			},
			want: `detected as "dht", expected "udp-tracker-connect"`,
		},
		"detections that are not enforced": {
			lines: func(port uint16) []string {
				var out []string
				for _, l := range goodLog(port) {
					if l != rejectLog {
						out = append(out, l)
					}
				}
				return out
			},
			want: "allowed through",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tun := &scriptedTunnel{lines: c.lines}
			_, out, err := runWith(t, "debug", tun, nil)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q\n%s", err, c.want, out)
			}
			// A failed verdict still tears everything down.
			if !tun.closed || !strings.Contains(out, "removed, and") {
				t.Errorf("no cleanup after a failure: closed=%v\n%s", tun.closed, out)
			}
		})
	}
}

func TestRunAtInfoLevelCannotProveEnforcementAndSaysSo(t *testing.T) {
	tun := &scriptedTunnel{lines: func(port uint16) []string {
		var out []string
		for _, l := range goodLog(port) {
			if l != rejectLog {
				out = append(out, l)
			}
		}
		return out
	}}
	_, _, err := runWith(t, "info", tun, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot be proved at log level") || strings.Contains(err.Error(), "no reject action was recorded") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunStopsWhenTheTunnelCannotBeUsed(t *testing.T) {
	boom := errors.New("handshake timed out")
	tun := &scriptedTunnel{lines: goodLog, handshakeErr: boom}
	_, out, err := runWith(t, "debug", tun, nil)
	if err == nil || !errors.Is(err, boom) || !strings.Contains(err.Error(), "handshake is the only proof") {
		t.Fatalf("err = %v", err)
	}
	if !tun.closed || !strings.Contains(out, "removed, and") {
		t.Errorf("a failed handshake left things behind: closed=%v\n%s", tun.closed, out)
	}

	tun = &scriptedTunnel{lines: goodLog, sendErr: errors.New("network unreachable")}
	if _, _, err := runWith(t, "debug", tun, nil); err == nil || !strings.Contains(err.Error(), `probe "control"`) {
		t.Errorf("send failure: %v", err)
	}

	tun = &scriptedTunnel{lines: goodLog, closeErr: errors.New("device busy")}
	if _, out, err := runWith(t, "debug", tun, nil); err != nil || !strings.Contains(out, "could not remove") {
		t.Errorf("close failure should warn, not fail: %v\n%s", err, out)
	}
}

func TestRunTearsDownWhenTheContextIsCancelledDuringTheSettleWait(t *testing.T) {
	tun := &scriptedTunnel{lines: goodLog}
	port := freeUDPPort(t)
	opts, _ := liveFixture(t, nil)
	opts, _ = liveFixtureAt(t, "debug", coreWithEndpoint(t, port, opts.Tag), opts)
	opts.Port = port
	opts.SettleDelay = time.Hour
	tun.logPath, tun.tag = opts.LogPath, opts.Tag
	old := createTunnel
	createTunnel = func(TunnelConfig) (tunnelClient, error) { return tun, nil }
	t.Cleanup(func() { createTunnel = old })

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for len(tun.sent) < 4 {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()
	var out bytes.Buffer
	if _, err := Run(ctx, &out, opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if !tun.closed || !strings.Contains(out.String(), "removed, and") {
		t.Errorf("a cancelled run left things behind: closed=%v\n%s", tun.closed, out.String())
	}
}

func TestRunNotesAProductionEndpointThatWasNotListeningToBeginWith(t *testing.T) {
	tun := &scriptedTunnel{lines: goodLog}
	_, out, err := runWith(t, "debug", tun, func(o *Options) {
		os.WriteFile(o.ConfigPath, []byte(strings.Replace(mustRead(t, o.ConfigPath), `"experimental"`,
			`"endpoints":[{"tag":"prod-in","listen_port":`+fmt.Sprint(freeUDPPort(t))+`,"address":["10.10.0.1/24"]}],"experimental"`, 1)), 0o600)
	})
	if !strings.Contains(out, "prod-in (port") || !strings.Contains(out, "was already not listening before the test") {
		t.Errorf("no note about prod-in:\n%s", out)
	}
	// ...and cleanup still says it is down afterwards, because it is.
	if !strings.Contains(out, "CLEANUP FAILED") || !strings.Contains(out, "not listening after cleanup: prod-in") {
		t.Errorf("a production endpoint that is down went unreported: err=%v\n%s", err, out)
	}
}

// A production endpoint that WAS listening and stopped during the apply is a
// disturbance of live traffic and fails the run at once.
func TestRunFailsWhenTheApplyStopsAProductionListener(t *testing.T) {
	prod, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer prod.Close()
	prodPort := prod.LocalAddr().(*net.UDPAddr).Port

	tun := &scriptedTunnel{lines: goodLog}
	port := freeUDPPort(t)
	base, _ := liveFixture(t, nil)
	inner := coreWithEndpoint(t, port, base.Tag)
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/manage/apply" {
			prod.Close() // the apply tore the production listener down
		}
		inner(w, r)
	}
	opts, _ := liveFixtureAt(t, "debug", handler, base)
	opts.Port = port
	os.WriteFile(opts.ConfigPath, []byte(strings.Replace(mustRead(t, opts.ConfigPath), `"experimental"`,
		`"endpoints":[{"tag":"prod-in","listen_port":`+fmt.Sprint(prodPort)+`,"address":["10.10.0.1/24"]}],"experimental"`, 1)), 0o600)
	tun.logPath, tun.tag = opts.LogPath, opts.Tag
	old := createTunnel
	createTunnel = func(TunnelConfig) (tunnelClient, error) { return tun, nil }
	t.Cleanup(func() { createTunnel = old })

	_, err = Run(context.Background(), &bytes.Buffer{}, opts)
	if err == nil || !strings.Contains(err.Error(), "production endpoint prod-in stopped listening") {
		t.Fatalf("err = %v", err)
	}
	if len(tun.sent) != 0 {
		t.Error("probes were sent after live traffic was disturbed")
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Probes carry distinct detectors, so a catch-all can only be seen by feeding
// the verdict two probes that expect the same one.
func TestVerdictCatchesOneDetectorFiringForTwoProbes(t *testing.T) {
	probes := []Probe{
		{Name: "a", Port: 1, Detector: "dht"},
		{Name: "b", Port: 2, Detector: "dht"},
	}
	result := &Result{
		Detections: []corelog.Detection{
			{Detector: "dht", Inbound: "t", DestinationPort: 1},
			{Detector: "dht", Inbound: "t", DestinationPort: 2},
		},
		Rejections:           []string{"drop"},
		RouteDecisionsLogged: true,
	}
	err := assertProbes(&bytes.Buffer{}, "t", probes, result)
	if err == nil || !strings.Contains(err.Error(), "fired for both port 1 and port 2") {
		t.Fatalf("err = %v", err)
	}
	// Detections on another inbound are somebody else's and do not count.
	result.Detections[0].Inbound, result.Detections[1].Inbound = "other", "other"
	if err := assertProbes(&bytes.Buffer{}, "t", probes, result); err == nil || !strings.Contains(err.Error(), "no detection for a") {
		t.Fatalf("foreign detections counted: %v", err)
	}
}

// An apply that reports the endpoint as added but binds nothing proves nothing
// about the sniffer, and the run must not go on to send datagrams into a void.
func TestRunFailsWhenTheAppliedEndpointIsNotListening(t *testing.T) {
	port := freeUDPPort(t)
	base, _ := liveFixture(t, nil)
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/manage/apply" {
			fmt.Fprintf(w, `{"message":"ok","endpoints":{"added":[%q],"removed":[%q]}}`, base.Tag, base.Tag)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	opts, _ := liveFixtureAt(t, "debug", handler, base)
	opts.Port = port
	tun := &scriptedTunnel{lines: goodLog}
	old := createTunnel
	createTunnel = func(TunnelConfig) (tunnelClient, error) { return tun, nil }
	t.Cleanup(func() { createTunnel = old })

	_, err := Run(context.Background(), &bytes.Buffer{}, opts)
	if err == nil || !strings.Contains(err.Error(), "nothing was actually started") {
		t.Fatalf("err = %v", err)
	}
	if len(tun.sent) != 0 {
		t.Error("datagrams were sent to an endpoint that is not there")
	}
}
