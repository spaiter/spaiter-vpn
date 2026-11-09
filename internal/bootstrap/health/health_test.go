package health

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/compose"
)

type fakeCompose struct {
	samples [][]compose.ServiceState
	index   int
	logs    map[string]string
	err     error
}

func (f *fakeCompose) Services(context.Context, string) ([]compose.ServiceState, error) {
	if f.err != nil {
		return nil, f.err
	}
	if len(f.samples) == 0 {
		return nil, nil
	}
	state := f.samples[min(f.index, len(f.samples)-1)]
	f.index++
	return state, nil
}
func (f *fakeCompose) Logs(_ context.Context, _, service string, _ int) (string, error) {
	return f.logs[service], nil
}
func (f *fakeCompose) Pull(context.Context, string, io.Writer, io.Writer) error { return nil }
func (f *fakeCompose) Up(context.Context, string, io.Writer, io.Writer) error   { return nil }
func (f *fakeCompose) Recreate(context.Context, string, io.Writer, io.Writer) error {
	return nil
}
func (f *fakeCompose) StopService(context.Context, string, string, io.Writer, io.Writer) error {
	return nil
}
func (f *fakeCompose) Down(context.Context, string, io.Writer, io.Writer) error { return nil }
func (f *fakeCompose) DisplayName() string                                      { return "fake" }

// clock gives the wait deterministic time: every Sleep advances it, so a
// deadline is reached by sampling rather than by the test actually waiting.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }
func (c *clock) Sleep(_ context.Context, d time.Duration) error {
	c.now = c.now.Add(d)
	return nil
}

func options(runner compose.Runner, services ...string) (Options, *clock) {
	c := &clock{now: time.Unix(0, 0)}
	return Options{
		Project:  "/tmp/docker-compose.yml",
		Services: services,
		Compose:  runner,
		Probe:    func(context.Context) error { return nil },
		Deadline: 30 * time.Second,
		Settle:   6 * time.Second,
		Interval: 2 * time.Second,
		Now:      c.Now,
		Sleep:    c.Sleep,
		Out:      io.Discard,
	}, c
}

func running(service string) compose.ServiceState {
	return compose.ServiceState{Service: service, State: "running"}
}

// TestRestartLoopNeverSettles is the check's reason to exist. A crash-looping
// service is "running" for part of every cycle, so a single sample is worthless
// and anything that accepts one would have reported the tunnel outage as a
// successful start.
func TestRestartLoopNeverSettles(t *testing.T) {
	runner := &fakeCompose{
		samples: [][]compose.ServiceState{
			{running("sing-box")},
			{{Service: "sing-box", State: "restarting"}},
			{running("sing-box")},
			{{Service: "sing-box", State: "restarting"}},
		},
		logs: map[string]string{"sing-box": "FATAL: decode config: unknown field"},
	}
	// The samples repeat the last state once exhausted, so this loops to the
	// deadline exactly as a real crash loop would.
	opts, _ := options(runner, "sing-box")
	_, err := Wait(context.Background(), opts)
	if !errors.Is(err, ErrUnhealthy) {
		t.Fatalf("err = %v, want ErrUnhealthy", err)
	}
	if !strings.Contains(err.Error(), "restarting") {
		t.Fatalf("the failure does not say what was wrong: %v", err)
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("the failure carries no recent output: %v", err)
	}
}

// TestSettleWindowRestartsAfterFlap. A service that was healthy and then was not
// must not inherit the time it was healthy, or a flap inside the window reads
// as a clean start.
func TestSettleWindowRestartsAfterFlap(t *testing.T) {
	runner := &fakeCompose{samples: [][]compose.ServiceState{
		{running("sing-box")},
		{running("sing-box")},
		{{Service: "sing-box", State: "restarting"}},
		{running("sing-box")},
		{running("sing-box")},
		{running("sing-box")},
		{running("sing-box")},
	}}
	opts, c := options(runner, "sing-box")
	report, err := Wait(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	// Four healthy samples at 2s apart are needed after the flap to cover a 6s
	// window, so readiness cannot be reported before the flap plus that window.
	if c.now.Sub(time.Unix(0, 0)) < 8*time.Second {
		t.Fatalf("settled after %s, which is sooner than the flap allows", c.now.Sub(time.Unix(0, 0)))
	}
	if report.Samples < 6 {
		t.Fatalf("samples = %d, want the window to have been restarted", report.Samples)
	}
}

// TestProbeFailureIsNotHealthy. The core can be running and still have failed
// to load its configuration; without the management probe this wait would pass
// on exactly the deployments it is supposed to catch.
func TestProbeFailureIsNotHealthy(t *testing.T) {
	runner := &fakeCompose{
		samples: [][]compose.ServiceState{{running("sing-box")}},
		logs:    map[string]string{},
	}
	opts, _ := options(runner, "sing-box")
	opts.Probe = func(context.Context) error { return errors.New("401 unauthorized") }
	_, err := Wait(context.Background(), opts)
	if !errors.Is(err, ErrUnhealthy) || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v, want the probe failure reported", err)
	}
}

// TestEmptyLogIsReportedAsNeverStarted. An empty log is a diagnosis in itself:
// the process never ran, so the fault is at the container level rather than in
// the application, and saying so saves an operator from reading application
// code that never executed.
func TestEmptyLogIsReportedAsNeverStarted(t *testing.T) {
	runner := &fakeCompose{
		samples: [][]compose.ServiceState{{{Service: "sing-box", State: "exited", ExitCode: 255}}},
		logs:    map[string]string{"sing-box": "   \n"},
	}
	opts, _ := options(runner, "sing-box")
	_, err := Wait(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "never started") {
		t.Fatalf("err = %v, want the empty-log diagnosis", err)
	}
	if !strings.Contains(err.Error(), "exit 255") {
		t.Fatalf("the exit code was dropped: %v", err)
	}
}

func TestMissingServiceIsNotHealthy(t *testing.T) {
	runner := &fakeCompose{
		samples: [][]compose.ServiceState{{running("sing-box")}},
		logs:    map[string]string{},
	}
	opts, _ := options(runner, "sing-box", "vpn-bot")
	_, err := Wait(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "vpn-bot is not in the project") {
		t.Fatalf("err = %v, want the absent service named", err)
	}
}

// TestSecretsAreScrubbedFromCapturedLogs. A container that fails to start often
// prints the environment it was handed.
func TestSecretsAreScrubbedFromCapturedLogs(t *testing.T) {
	const token = "123456:AAHtelegramtokenvalue"
	runner := &fakeCompose{
		samples: [][]compose.ServiceState{{{Service: "vpn-bot", State: "exited", ExitCode: 1}}},
		logs:    map[string]string{"vpn-bot": "starting with TELEGRAM_TOKEN=" + token},
	}
	opts, _ := options(runner, "vpn-bot")
	opts.Redact = func(text string) string { return strings.ReplaceAll(text, token, "[redacted]") }
	_, err := Wait(context.Background(), opts)
	if err == nil {
		t.Fatal("expected a failure")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("the token reached the failure report: %v", err)
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("the log was not captured at all: %v", err)
	}
}

// TestProbeIsRequired. Passing nil would silently reduce the wait to "a
// container is running", which is the claim this package exists to refuse.
func TestProbeIsRequired(t *testing.T) {
	opts, _ := options(&fakeCompose{}, "sing-box")
	opts.Probe = nil
	if _, err := Wait(context.Background(), opts); err == nil {
		t.Fatal("a wait with no management probe was accepted")
	}
}

func TestComposeErrorIsReported(t *testing.T) {
	runner := &fakeCompose{err: fmt.Errorf("daemon refused")}
	opts, _ := options(runner, "sing-box")
	_, err := Wait(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "daemon refused") {
		t.Fatalf("err = %v, want the compose error", err)
	}
}
