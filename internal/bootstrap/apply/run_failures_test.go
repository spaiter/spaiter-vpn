package apply

import (
	"context"
	"errors"
	"github.com/spaiter/spaiter-vpn/internal/preflight"
	"strings"
	"testing"
)

func TestAFailedPullUndoesTheInstallAndNamesTheStep(t *testing.T) {
	h := newHarness(t)
	h.compose.pullErr = errors.New("registry unreachable")
	_, err := Run(context.Background(), h.options)
	if err == nil || !strings.Contains(err.Error(), "pull the core image") {
		t.Fatalf("err = %v", err)
	}
	if got := strings.Join(h.compose.calls, ","); !strings.Contains(got, "down") {
		t.Errorf("a fresh install that failed was not stopped: %s", got)
	}
}

func TestAFirewallRuleThatCannotBeOpenedFailsTheApplyAndIsUndone(t *testing.T) {
	h := newHarness(t)
	blockFirewallRule(h, t)
	h.options.Firewall = &fakeFirewall{addErr: errors.New("ufw refused")}
	_, err := Run(context.Background(), h.options)
	if err == nil || !strings.Contains(err.Error(), "open ") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(strings.Join(h.compose.calls, ","), "up") {
		t.Error("the project was started with the firewall closed")
	}
}

func TestAnApplyWithoutAnApprovedPlanIsRefused(t *testing.T) {
	h := newHarness(t)
	h.options.Approved.APIVersion = ""
	_, err := Run(context.Background(), h.options)
	if err == nil || !strings.Contains(err.Error(), "needs the approved plan") {
		t.Errorf("err = %v", err)
	}
}

func TestPreflightWarningsAreShownBeforeTheApplyGoesOn(t *testing.T) {
	h := newHarness(t)
	var out strings.Builder
	h.options.Out = &out
	h.options.Preflight = warningPreflight
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "heads up") {
		t.Errorf("the warning was not shown:\n%s", out.String())
	}
}

func warningPreflight(context.Context, preflight.Options) *preflight.Report {
	return &preflight.Report{Checks: []preflight.Check{{Name: "heads up", Severity: preflight.Warn}}}
}
