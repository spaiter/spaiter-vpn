package health

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/compose"
)

func TestWaitRefusesToStartWithoutWhatItNeeds(t *testing.T) {
	ctx := context.Background()
	runner := &fakeCompose{}

	o, _ := options(nil, "core")
	if _, err := Wait(ctx, o); err == nil || !strings.Contains(err.Error(), "compose runner") {
		t.Errorf("no runner: %v", err)
	}
	o, _ = options(runner, "core")
	o.Probe = nil
	if _, err := Wait(ctx, o); err == nil || !strings.Contains(err.Error(), "management probe") {
		t.Errorf("no probe: %v", err)
	}
	o, _ = options(runner)
	if _, err := Wait(ctx, o); err == nil || !strings.Contains(err.Error(), "expected services") {
		t.Errorf("no services: %v", err)
	}
}

func TestZeroValuedTimingsFallBackToTheProductionDefaults(t *testing.T) {
	runner := &fakeCompose{samples: [][]compose.ServiceState{{running("core")}}}
	o, c := options(runner, "core")
	o.Deadline, o.Interval, o.Settle, o.LogLines = 0, 0, -1, 0
	o.Out = nil
	report, err := Wait(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	defaults := DefaultOptions()
	// Settled after the default window, sampled at the default interval.
	if report.Waited < defaults.Settle || c.now.Sub(time.Unix(0, 0)) < defaults.Settle-defaults.Interval {
		t.Errorf("waited %s, clock advanced %s", report.Waited, c.now.Sub(time.Unix(0, 0)))
	}
}

func TestACancelledWaitReturnsTheContextError(t *testing.T) {
	runner := &fakeCompose{samples: [][]compose.ServiceState{{running("core")}}}
	o, _ := options(runner, "core")
	o.Sleep = func(context.Context, time.Duration) error { return context.Canceled }
	if _, err := Wait(context.Background(), o); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestTheRealSleepWaitsOrObeysCancellation(t *testing.T) {
	if err := sleep(context.Background(), time.Millisecond); err != nil {
		t.Errorf("sleep: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled sleep: %v", err)
	}
}

func TestAnUnhealthyServiceIsReportedWithItsHealthState(t *testing.T) {
	runner := &fakeCompose{
		samples: [][]compose.ServiceState{{{Service: "core", State: "restarting", Health: "unhealthy"}}},
		logs:    map[string]string{},
	}
	o, _ := options(runner, "core")
	_, err := Wait(context.Background(), o)
	if !errors.Is(err, ErrUnhealthy) || !strings.Contains(err.Error(), "restarting/unhealthy") {
		t.Errorf("err = %v", err)
	}
}

type logsFailing struct{ *fakeCompose }

func (logsFailing) Logs(context.Context, string, string, int) (string, error) {
	return "", errors.New("docker logs failed")
}

func TestAFailureReportSaysWhenLogsCouldNotBeRead(t *testing.T) {
	runner := logsFailing{&fakeCompose{samples: [][]compose.ServiceState{{{Service: "core", State: "exited", ExitCode: 1}}}}}
	o, _ := options(runner, "core")
	_, err := Wait(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "core logs unavailable: docker logs failed") || !strings.Contains(err.Error(), "exit 1") {
		t.Errorf("err = %v", err)
	}
}
