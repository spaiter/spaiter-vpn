package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

func TestPlanPrintsMachineReadableOutputOnRequest(t *testing.T) {
	args := plannedHost(t)
	var out bytes.Buffer
	if err := runBootstrapPlan(context.Background(), &out, append([]string{"-json"}, args...)); err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out.String())
	}
	if parsed["mode"] == nil && parsed["Mode"] == nil {
		t.Errorf("no mode in %v", parsed)
	}
	if strings.Contains(out.String(), "desired state:") {
		t.Error("the human table leaked into the JSON output")
	}
}

func TestPlanOfABlockedHostPrintsItAndFails(t *testing.T) {
	args := plannedHost(t)
	discoverHost = func(_ context.Context, desired state.State, _ discover.Layout) (discover.Observed, error) {
		observed := fakeObservation(t, desired)
		observed.Platform.OS = "plan9"
		return observed, nil
	}
	var out bytes.Buffer
	err := runBootstrapPlan(context.Background(), &out, args)
	if err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error = %v", err)
	}
	if !strings.Contains(out.String(), "BLOCKED") {
		t.Errorf("the blockers were not shown:\n%s", out.String())
	}
}

func TestPlanReportsAHostItCannotReadAndAMissingDocument(t *testing.T) {
	args := plannedHost(t)
	discoverHost = func(context.Context, state.State, discover.Layout) (discover.Observed, error) {
		return discover.Observed{}, errors.New("cannot read the host")
	}
	if err := runBootstrapPlan(context.Background(), &bytes.Buffer{}, args); err == nil || !strings.Contains(err.Error(), "cannot read the host") {
		t.Errorf("unreadable host: %v", err)
	}
	if err := runBootstrapPlan(context.Background(), &bytes.Buffer{}, append([]string{"-f", "/absent/desired.json"}, args...)); err == nil {
		t.Error("a missing document produced a plan")
	}
	var out bytes.Buffer
	if err := runBootstrapPlan(context.Background(), &out, []string{"-h"}); err == nil || !strings.Contains(out.String(), "usage: spaiter-vpn bootstrap plan") {
		t.Errorf("-h: %v\n%s", err, out.String())
	}
}
