package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/exporter"
)

const logFixture = `+0000 2026-10-22 22:09:08 DEBUG router: match[0] => sniff(bittorrent,100ms)
+0000 2026-10-22 22:09:10 INFO router: bittorrent sniff detection: network=udp, detector=dht, inbound=bt-in, source=10.99.0.2:40844, destination=192.0.2.1:6881, payload_bytes=92
+0000 2026-10-22 22:09:10 DEBUG router: match[1] protocol=bittorrent => reject(drop,xdp-block)
+0000 2026-10-22 22:09:12 INFO router: bittorrent sniff detection: network=tcp, detector=handshake, inbound=awg-in, source=10.10.0.5:12345, destination=203.0.113.9:51413, payload_bytes=68
+0000 2026-10-22 22:09:13 WARN router: something odd
`

func logsDir(t *testing.T, log string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sing-box.log"), []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runLogsCapture(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runLogs(context.Background(), &out, args)
	return out.String(), err
}

func TestLogsListsFilterAndTail(t *testing.T) {
	dir := logsDir(t, logFixture)
	out, err := runLogsCapture(t, "-dir", dir, "-level", "warn")
	if err != nil || strings.TrimSpace(out) != strings.TrimSpace("+0000 2026-10-22 22:09:13 WARN router: something odd") {
		t.Fatalf("level filter: %v %q", err, out)
	}
	out, _ = runLogsCapture(t, "-dir", dir, "-grep", "detector=")
	if strings.Count(out, "\n") != 2 {
		t.Errorf("grep gave %q", out)
	}
	out, _ = runLogsCapture(t, "-dir", dir, "-tail", "2")
	if strings.Count(out, "\n") != 2 || !strings.Contains(out, "something odd") {
		t.Errorf("tail gave %q", out)
	}
	out, _ = runLogsCapture(t, "-dir", dir)
	if strings.Count(out, "\n") != 5 {
		t.Errorf("all lines gave %q", out)
	}
}

func TestLogsDetectionsAreOneLineEach(t *testing.T) {
	dir := logsDir(t, logFixture)
	out, err := runLogsCapture(t, "-dir", dir, "-detections")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "dht") || !strings.Contains(out, "192.0.2.1:6881 (92 bytes)") || !strings.Contains(out, "\n2 detections") {
		t.Errorf("out = %q", out)
	}
	out, _ = runLogsCapture(t, "-dir", dir, "-detections", "-tail", "1")
	if strings.Contains(out, "dht") || !strings.Contains(out, "handshake") {
		t.Errorf("tail kept the wrong one: %q", out)
	}
	// The footer counts all detections, not only the tailed ones.
	if !strings.Contains(out, "2 detections") {
		t.Errorf("footer = %q", out)
	}
}

func TestLogsSummaryWarnsWhenDetectionsWereNotRejected(t *testing.T) {
	dir := logsDir(t, logFixture)
	out, err := runLogsCapture(t, "-dir", dir, "-summary")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2 detections", "by detector", "by inbound", "10.99.0.2", "only 1 reject actions", "No bans recorded"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}

	rejected := strings.Replace(logFixture, "DEBUG router: something", "x", 1) +
		"+0000 2026-10-22 22:09:14 DEBUG router: match[1] protocol=bittorrent => reject(drop,xdp-block)\n" +
		"+0000 2026-10-22 22:09:14 INFO XDP blocked 10.99.0.2\n"
	out, _ = runLogsCapture(t, "-file", filepath.Join(logsDir(t, rejected), "sing-box.log"), "-summary")
	if strings.Contains(out, "reject actions") || !strings.Contains(out, "1 clients were banned by the XDP blocker") {
		t.Errorf("rejected summary:\n%s", out)
	}

	skipped := logFixture + "+0000 x DEBUG router: XDP: skipping local peer endpoint 127.0.0.1 for 10.99.0.2\n"
	out, _ = runLogsCapture(t, "-file", filepath.Join(logsDir(t, skipped), "sing-box.log"), "-summary")
	if !strings.Contains(out, "No bans enforced: 1 were skipped as loopback peers") {
		t.Errorf("skipped summary:\n%s", out)
	}
}

func TestLogsSummaryOfAQuietLog(t *testing.T) {
	out, err := runLogsCapture(t, "-dir", logsDir(t, "+0000 x INFO hello\n"), "-summary")
	if err != nil || !strings.Contains(out, "No BitTorrent detections.") || !strings.Contains(out, "selftest") {
		t.Errorf("%v\n%s", err, out)
	}
}

func TestFindLogFilePrefersWhatTheConfigNames(t *testing.T) {
	dir := t.TempDir()
	if _, err := findLogFile(dir); err == nil || !strings.Contains(err.Error(), "pass -file") {
		t.Fatalf("err = %v", err)
	}
	os.WriteFile(filepath.Join(dir, "sing-box.log"), nil, 0o644)
	os.WriteFile(filepath.Join(dir, "core.log"), nil, 0o644)
	os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"log":{"output":"/etc/sing-box/core.log"}}`), 0o644)
	got, err := findLogFile(dir)
	if err != nil || got != filepath.Join(dir, "core.log") {
		t.Errorf("got %q, %v", got, err)
	}
	// A config naming a file that is not there falls back to the default name.
	os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"log":{"output":"gone.log"}}`), 0o644)
	if got, _ := findLogFile(dir); got != filepath.Join(dir, "sing-box.log") {
		t.Errorf("fallback = %q", got)
	}
	if logOutputFromConfig([]byte("not json")) != "" || logOutputFromConfig([]byte(`{}`)) != "" {
		t.Error("garbage should name nothing")
	}
}

func TestLogsMissingFile(t *testing.T) {
	if _, err := runLogsCapture(t, "-file", filepath.Join(t.TempDir(), "nope.log")); err == nil {
		t.Error("a missing log was not an error")
	}
}

func TestParsePortListSortsAndDedupes(t *testing.T) {
	got, err := parsePortList("443, 80,443,8080")
	if err != nil || !reflect.DeepEqual(got, []uint16{80, 443, 8080}) {
		t.Errorf("got %v, %v", got, err)
	}
	if got, err := parsePortList(""); err != nil || len(got) != 0 {
		t.Errorf("empty = %v, %v", got, err)
	}
	for _, bad := range []string{"0", "70000", "http"} {
		if _, err := parsePortList(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCondenseSaysWhatToDo(t *testing.T) {
	cases := map[string]string{
		"dial tcp: connection refused":    "nothing is listening",
		"dial tcp: i/o timeout":           "firewall or NAT",
		"connect: no route to host":       "no route to host",
		"connect: network is unreachable": "network is unreachable",
		"weird":                           "weird",
	}
	for in, want := range cases {
		if got := condense(errors.New(in)); !strings.Contains(got, want) {
			t.Errorf("condense(%q) = %q", in, got)
		}
	}
}

func TestProbeTargetsFromSecretsMatchTheFirewallRules(t *testing.T) {
	sb := fakeSingBox(t, "exit 0")
	dir := filepath.Join(t.TempDir(), "sb")
	if out, err := runInitCapture(t, initArgs(dir, sb)...); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	tcp, udp, err := probeTargets(dir, "", "ignored", "ignored")
	if err != nil || len(tcp)+len(udp) == 0 {
		t.Fatalf("tcp=%v udp=%v err=%v", tcp, udp, err)
	}
	// An explicit secrets path wins over -dir's location.
	tcp2, udp2, err := probeTargets("", filepath.Join(dir, "secrets", "secrets.json"), "", "")
	if err != nil || !reflect.DeepEqual(tcp, tcp2) || !reflect.DeepEqual(udp, udp2) {
		t.Errorf("secrets path differs: %v %v %v", tcp2, udp2, err)
	}
	bad := filepath.Join(t.TempDir(), "s.json")
	os.WriteFile(bad, []byte("{"), 0o600)
	if _, _, err := probeTargets("", bad, "", ""); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("err = %v", err)
	}
	if _, _, err := probeTargets("", filepath.Join(t.TempDir(), "none"), "", ""); err == nil || !strings.Contains(err.Error(), "read") {
		t.Errorf("err = %v", err)
	}
	if _, _, err := probeTargets("", "", "x", ""); err == nil || !strings.Contains(err.Error(), "-tcp") {
		t.Errorf("err = %v", err)
	}
	if _, _, err := probeTargets("", "", "", "x"); err == nil || !strings.Contains(err.Error(), "-udp") {
		t.Errorf("err = %v", err)
	}
}

func TestProbeReportsOpenAndClosedPorts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	defer ln.Close()
	open := ln.Addr().(*net.TCPAddr).Port

	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := closed.Addr().(*net.TCPAddr).Port
	closed.Close()

	var out bytes.Buffer
	args := []string{"-host", "127.0.0.1", "-timeout", "2s", "-tcp", fmt.Sprint(open, ",", dead), "-udp", "9999"}
	err = runProbe(context.Background(), &out, args)
	if err == nil || !strings.Contains(err.Error(), "1 of 2 TCP ports") {
		t.Fatalf("err = %v\n%s", err, out.String())
	}
	for _, want := range []string{
		fmt.Sprintf("OK    tcp/%-6d", open), fmt.Sprintf("FAIL  tcp/%-6d", dead),
		"nothing is listening", "udp/9999", "1 TCP ports reachable, 1 not", "The 1 UDP port is unprovable",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("lacks %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	if err := runProbe(context.Background(), &out, []string{"-host", "127.0.0.1", "-tcp", fmt.Sprint(open), "-udp", "1,2"}); err != nil ||
		!strings.Contains(out.String(), "The 2 UDP ports are unprovable") {
		t.Errorf("%v\n%s", err, out.String())
	}
}

func TestProbeUsageErrors(t *testing.T) {
	var out bytes.Buffer
	if err := runProbe(context.Background(), &out, nil); !errors.Is(err, ErrUsage) {
		t.Errorf("no host: %v", err)
	}
	if err := runProbe(context.Background(), &out, []string{"-host", "h"}); !errors.Is(err, ErrUsage) {
		t.Errorf("nothing to probe: %v", err)
	}
}

func TestApplyExporterEnvMirrorsThePythonExporter(t *testing.T) {
	base := func() exporter.Options {
		return exporter.Options{DatabasePath: "db", LogPath: "log", Listen: ":1", HistoryDays: 7, ServiceTopN: 5, ServiceLookupTimeout: time.Second}
	}
	for _, k := range []string{"SINGBOX_DB", "SINGBOX_LOG", "PORT", "SINGBOX_HISTORY_DAYS", "SINGBOX_SERVICE_TOP_N", "SINGBOX_SERVICE_LOOKUP_TIMEOUT"} {
		t.Setenv(k, "")
	}
	o := base()
	applyExporterEnv(&o, true)
	if o != base() {
		t.Errorf("empty environment changed options: %+v", o)
	}

	t.Setenv("SINGBOX_DB", "/env/db")
	t.Setenv("SINGBOX_LOG", "/env/log")
	t.Setenv("PORT", "9200")
	t.Setenv("SINGBOX_HISTORY_DAYS", "30")
	t.Setenv("SINGBOX_SERVICE_TOP_N", "12")
	t.Setenv("SINGBOX_SERVICE_LOOKUP_TIMEOUT", "1.5")
	o = base()
	applyExporterEnv(&o, true)
	if o.DatabasePath != "/env/db" || o.LogPath != "/env/log" || o.Listen != ":9200" || o.HistoryDays != 30 ||
		o.ServiceTopN != 12 || o.ServiceLookupTimeout != 1500*time.Millisecond {
		t.Errorf("env not applied: %+v", o)
	}

	// An explicit -db beats the environment.
	o = base()
	applyExporterEnv(&o, false)
	if o.DatabasePath != "db" {
		t.Errorf("flag lost to env: %q", o.DatabasePath)
	}

	// Garbage numbers are ignored rather than zeroing the setting.
	t.Setenv("PORT", "http")
	t.Setenv("SINGBOX_HISTORY_DAYS", "x")
	t.Setenv("SINGBOX_SERVICE_TOP_N", "x")
	t.Setenv("SINGBOX_SERVICE_LOOKUP_TIMEOUT", "x")
	o = base()
	applyExporterEnv(&o, true)
	if o.Listen != ":1" || o.HistoryDays != 7 || o.ServiceTopN != 5 || o.ServiceLookupTimeout != time.Second {
		t.Errorf("garbage applied: %+v", o)
	}
}

func TestMetricsOncePrintsAScrapeAndNeedsTheDatabase(t *testing.T) {
	var out bytes.Buffer
	err := runMetrics(context.Background(), &out, []string{"-dir", t.TempDir(), "-once"})
	if err == nil || !strings.Contains(err.Error(), "not readable") {
		t.Errorf("err = %v", err)
	}
}
