package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/apply"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

// engineStub replaces the two entry points to the host and records whether the
// engine was reached.
type engineStub struct {
	optionsCalls, runCalls int
	optionsErr, runErr     error
	result                 *apply.Result
}

func stubEngine(t *testing.T, s *engineStub) {
	t.Helper()
	oldOptions, oldRun := buildApplyOptions, runApply
	buildApplyOptions = func(context.Context, discover.Layout, state.State, plan.Plan, io.Writer, bool, string) (apply.Options, error) {
		s.optionsCalls++
		return apply.Options{}, s.optionsErr
	}
	runApply = func(context.Context, apply.Options) (*apply.Result, error) {
		s.runCalls++
		return s.result, s.runErr
	}
	t.Cleanup(func() { buildApplyOptions, runApply = oldOptions, oldRun })
}

// plannedHost is a fresh host with a stored desired state whose plan is not
// blocked, owned by the test user so the transaction manager works without root.
func plannedHost(t *testing.T) []string {
	t.Helper()
	pretendRoot(t, true)
	old := managerOwner
	managerOwner.UID, managerOwner.GID = uint32(os.Getuid()), uint32(os.Getgid())
	t.Cleanup(func() { managerOwner = old })

	layout := freshLayout(t)
	writeDesired(t, layout, state.Default([]string{"owner"}))
	restore := discoverHost
	discoverHost = func(_ context.Context, desired state.State, _ discover.Layout) (discover.Observed, error) {
		return fakeObservation(t, desired), nil
	}
	t.Cleanup(func() { discoverHost = restore })
	return []string{
		"-config-root", layout.ConfigRoot, "-data-root", layout.DataRoot,
		"-logrotate-path", layout.LogrotatePath, "-control-unit-path", layout.ControlUnitPath,
	}
}

func TestApplyDrivesTheEngineAndReportsItsResult(t *testing.T) {
	stub := &engineStub{result: &apply.Result{Transaction: "tx-1", Mode: plan.Mode("install")}}
	stubEngine(t, stub)
	args := plannedHost(t)

	var out bytes.Buffer
	if err := runBootstrapApply(context.Background(), &out, append([]string{"-yes"}, args...)); err != nil {
		t.Fatalf("apply: %v\n%s", err, out.String())
	}
	if stub.optionsCalls != 1 || stub.runCalls != 1 {
		t.Errorf("engine calls = %d/%d", stub.optionsCalls, stub.runCalls)
	}
	if !strings.Contains(out.String(), "desired state:") {
		t.Errorf("the plan was not shown:\n%s", out.String())
	}
}

func TestApplyNeverReachesTheEngineWhenThePlanIsBlocked(t *testing.T) {
	stub := &engineStub{result: &apply.Result{}}
	stubEngine(t, stub)
	args := plannedHost(t)
	discoverHost = func(_ context.Context, desired state.State, _ discover.Layout) (discover.Observed, error) {
		observed := fakeObservation(t, desired)
		observed.Platform.OS = "plan9"
		return observed, nil
	}
	err := runBootstrapApply(context.Background(), &bytes.Buffer{}, append([]string{"-yes"}, args...))
	if err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error = %v", err)
	}
	if stub.optionsCalls != 0 {
		t.Error("the engine was configured for a blocked plan")
	}
}

func TestApplyReportsWhatTheEngineRefuses(t *testing.T) {
	for name, stub := range map[string]*engineStub{
		"options": {optionsErr: errors.New("no sing-box")},
		"run":     {runErr: errors.New("health gate failed")},
	} {
		stubEngine(t, stub)
		args := plannedHost(t)
		err := runBootstrapApply(context.Background(), &bytes.Buffer{}, append([]string{"-yes"}, args...))
		if err == nil {
			t.Errorf("%s: a failure was swallowed", name)
		}
	}
}

func TestApplyRefusesAnIncoherentHealthWindowBeforeConfiguringTheEngine(t *testing.T) {
	stub := &engineStub{result: &apply.Result{}}
	stubEngine(t, stub)
	args := plannedHost(t)
	err := runBootstrapApply(context.Background(), &bytes.Buffer{}, append([]string{"-yes", "-health-settle", "9h"}, args...))
	if err == nil || !strings.Contains(err.Error(), "health-settle") {
		t.Errorf("error = %v", err)
	}
	if stub.optionsCalls != 0 {
		t.Error("the engine was configured")
	}
}

func TestApplyWithoutConsentOrTerminalNamesTheWayOut(t *testing.T) {
	args := plannedHost(t)
	stdinHolds(t, "yes\n")
	err := runBootstrapApply(context.Background(), &bytes.Buffer{}, args)
	if err == nil || !strings.Contains(err.Error(), "bootstrap plan") {
		t.Errorf("error = %v", err)
	}
}
