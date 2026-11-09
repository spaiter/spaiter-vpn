package apply

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/ddns"
)

// shortProbes keeps the retry windows tiny for the duration of a test.
func shortProbes(t *testing.T) {
	t.Helper()
	oldControl, oldDDNS, oldPause := controlProbeWindow, ddnsProbeWindow, probeRetryPause
	controlProbeWindow, ddnsProbeWindow, probeRetryPause = 300*time.Millisecond, 300*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { controlProbeWindow, ddnsProbeWindow, probeRetryPause = oldControl, oldDDNS, oldPause })
}

// serveControl answers every request on a fresh unix socket with response.
func serveControl(t *testing.T, response map[string]any) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "c.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return socket
}

func TestTheControlProbeWantsAnOKStatusAnswerOnTheSocket(t *testing.T) {
	shortProbes(t)
	old := controlSocketPath
	t.Cleanup(func() { controlSocketPath = old })

	controlSocketPath = serveControl(t, map[string]any{"apiVersion": "1", "ok": true})
	if err := (Options{}).probeControl(context.Background()); err != nil {
		t.Errorf("a healthy daemon failed the probe: %v", err)
	}

	controlSocketPath = serveControl(t, map[string]any{"apiVersion": "1", "ok": false, "error": "backend broken"})
	if err := (Options{}).probeControl(context.Background()); err == nil || !strings.Contains(err.Error(), "backend broken") {
		t.Errorf("an error answer passed: %v", err)
	}

	controlSocketPath = filepath.Join(t.TempDir(), "absent.sock")
	if err := (Options{}).probeControl(context.Background()); err == nil || !strings.Contains(err.Error(), "did not answer on") {
		t.Errorf("a missing socket passed: %v", err)
	}

	called := false
	if err := (Options{ProbeControl: func(context.Context) error { called = true; return nil }}).probeControl(context.Background()); err != nil || !called {
		t.Errorf("injected probe: %v %v", called, err)
	}
}

func writeDDNSStatus(t *testing.T, status ddns.Status) {
	t.Helper()
	data, _ := json.Marshal(status)
	if err := os.WriteFile(ddnsStatusPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTheDDNSProbeSeparatesAWrongSetupFromAFlakyNetwork(t *testing.T) {
	shortProbes(t)
	old := ddnsStatusPath
	t.Cleanup(func() { ddnsStatusPath = old })
	ddnsStatusPath = filepath.Join(t.TempDir(), "status.json")

	desired := state.State{}
	desired.Bot.PublicHost = "vpn.example.org"
	out := &bytes.Buffer{}
	options := Options{Desired: desired, Out: out}
	ctx := context.Background()

	// No report at all yet.
	if err := options.probeDDNS(ctx, false); err == nil || !strings.Contains(err.Error(), "has not reported yet") {
		t.Errorf("no status file: %v", err)
	}

	writeDDNSStatus(t, ddns.Status{Time: time.Now(), OK: true, IPv4: "203.0.113.7"})
	if err := options.probeDDNS(ctx, true); err != nil || !strings.Contains(out.String(), "vpn.example.org on 203.0.113.7") {
		t.Errorf("ok status: %v, out %q", err, out)
	}

	// A round from before this apply does not count when a fresh one is asked
	// for, but the latest stands when it is not.
	writeDDNSStatus(t, ddns.Status{Time: time.Now().Add(-time.Hour), OK: true, IPv4: "203.0.113.7"})
	if err := options.probeDDNS(ctx, true); err == nil || !strings.Contains(err.Error(), "has not run since this apply") {
		t.Errorf("stale status accepted as fresh: %v", err)
	}
	if err := options.probeDDNS(ctx, false); err != nil {
		t.Errorf("latest status refused: %v", err)
	}

	// A rejected token fails the apply; a network problem only warns.
	writeDDNSStatus(t, ddns.Status{Time: time.Now(), Error: "token rejected", Permanent: true})
	if err := options.probeDDNS(ctx, true); err == nil || !strings.Contains(err.Error(), "token rejected") {
		t.Errorf("permanent failure: %v", err)
	}
	out.Reset()
	writeDDNSStatus(t, ddns.Status{Time: time.Now(), Error: "timeout"})
	if err := options.probeDDNS(ctx, true); err != nil || !strings.Contains(out.String(), "warning") || !strings.Contains(out.String(), "timeout") {
		t.Errorf("transient failure: %v, out %q", err, out)
	}

	// A corrupt file is reported as not yet readable.
	if err := os.WriteFile(ddnsStatusPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := options.probeDDNS(ctx, false); err == nil {
		t.Error("a corrupt status file passed")
	}

	called := false
	options.ProbeDDNS = func(context.Context) error { called = true; return nil }
	if err := options.probeDDNS(ctx, true); err != nil || !called {
		t.Errorf("injected probe: %v %v", called, err)
	}
}
