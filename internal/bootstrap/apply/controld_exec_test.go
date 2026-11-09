package apply

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

// fakeSystemctl puts a `systemctl` on PATH that appends its arguments to a
// file and exits with the status in the first line of its own script.
func fakeSystemctl(t *testing.T, status int, output string) string {
	t.Helper()
	dir := t.TempDir()
	record := filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$@\" >>" + record + "\necho '" + output + "'\nexit " + string(rune('0'+status)) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return record
}

func TestTheRealSystemdWrapperIssuesExactlyTheCommandsItPromises(t *testing.T) {
	record := fakeSystemctl(t, 0, "")
	ctx := context.Background()
	sd := execSystemd{}
	for _, call := range []func() error{
		func() error { return sd.Reload(ctx) },
		func() error { return sd.Start(ctx, "a.service") },
		func() error { return sd.Restart(ctx, "b.service") },
		func() error { return sd.Stop(ctx, "c.service") },
	} {
		if err := call(); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := os.ReadFile(record)
	want := "daemon-reload\nenable --now a.service\nrestart b.service\ndisable --now c.service\n"
	if string(got) != want {
		t.Errorf("systemctl was called with\n%s\nwant\n%s", got, want)
	}
}

func TestAFailingSystemctlReportsItsArgumentsAndOutput(t *testing.T) {
	fakeSystemctl(t, 1, "Unit not found.")
	err := execSystemd{}.Restart(context.Background(), "gone.service")
	if err == nil || !strings.Contains(err.Error(), "systemctl restart gone.service") || !strings.Contains(err.Error(), "Unit not found.") {
		t.Errorf("err = %v", err)
	}
	if (Options{}).systemd() == nil {
		t.Error("no default systemd")
	}
	custom := &fakeSystemd{}
	if (Options{Systemd: custom}).systemd() != Systemd(custom) {
		t.Error("an injected systemd was not used")
	}
}

func TestRetryForStopsOnSuccessDeadlineAndCancellation(t *testing.T) {
	ctx := context.Background()
	attempts := 0
	if err := retryFor(ctx, time.Minute, func() error {
		attempts++
		if attempts < 2 {
			return errors.New("not yet")
		}
		return nil
	}); err != nil || attempts != 2 {
		t.Errorf("success after a retry: err=%v attempts=%d", err, attempts)
	}

	last := errors.New("still down")
	if err := retryFor(ctx, 0, func() error { return last }); !errors.Is(err, last) {
		t.Errorf("an expired deadline must return the last error: %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := retryFor(cancelled, time.Minute, func() error { return last }); !errors.Is(err, context.Canceled) {
		t.Errorf("cancellation: %v", err)
	}
}

func TestTheWebProbeExpectsAnAnonymousRequestToBeTurnedAway(t *testing.T) {
	status := http.StatusUnauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
	defer server.Close()

	desired := state.Default([]string{"alice"})
	desired.Web = &state.Web{Listen: strings.TrimPrefix(server.URL, "http://")}
	options := Options{Desired: desired}

	if err := options.probeWeb(context.Background()); err != nil {
		t.Errorf("a 401 means the login wall is up: %v", err)
	}

	status = http.StatusOK
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	if err := options.probeWeb(ctx); err == nil {
		t.Error("an open web UI passed the probe")
	}

	// An injected probe wins over the real one.
	called := false
	options.ProbeWeb = func(context.Context) error { called = true; return nil }
	if err := options.probeWeb(context.Background()); err != nil || !called {
		t.Errorf("injected probe: called=%v err=%v", called, err)
	}
}

func TestTheWebProbeReportsAnUnreachableUI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := strings.TrimPrefix(server.URL, "http://")
	server.Close()

	desired := state.Default([]string{"alice"})
	desired.Web = &state.Web{Listen: addr}
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	if err := (Options{Desired: desired}).probeWeb(ctx); err == nil {
		t.Error("a closed port passed the probe")
	}
}
