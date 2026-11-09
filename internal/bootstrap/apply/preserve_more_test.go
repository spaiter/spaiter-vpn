package apply

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

func TestUnreadableRuntimeStateIsRefusedBeforeAnythingChanges(t *testing.T) {
	f := newRotationFixture(t)
	o := f.h.options
	ctx := context.Background()
	config, secrets := mustRead(t, o.Layout.ConfigPath()), mustRead(t, o.Layout.SecretsPath())

	for name, run := range map[string]func() error{
		"secrets not json": func() error { _, err := parseRuntimeState(ctx, config, []byte("{")); return err },
		"config not json":  func() error { _, err := parseRuntimeState(ctx, []byte("{"), secrets); return err },
		"config no users":  func() error { _, err := parseRuntimeState(ctx, []byte(`{"inbounds":[]}`), secrets); return err },
	} {
		if err := run(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := parseRuntimeState(ctx, config, secrets); err != nil {
		t.Fatalf("the live pair was refused: %v", err)
	}

	if err := os.Remove(o.Layout.SecretsPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := o.readRuntimeState(ctx); err == nil || !strings.Contains(err.Error(), "read the live credentials") {
		t.Errorf("missing secrets: %v", err)
	}
	if err := os.Remove(o.Layout.ConfigPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := o.readRuntimeState(ctx); err == nil || !strings.Contains(err.Error(), "read the live configuration") {
		t.Errorf("missing config: %v", err)
	}
}

func TestVerifyPreservedHoldsSecretsToByteEqualityAndNarratesTheRest(t *testing.T) {
	f := newRotationFixture(t)
	o := f.h.options
	out := &bytes.Buffer{}
	o.Out = out
	before, err := o.readRuntimeState(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if err := o.verifyPreserved(before, plan.ModeReconcile); err != nil || !strings.Contains(out.String(), "preserved:") {
		t.Errorf("untouched: %v, out %q", err, out)
	}

	// The core rewriting config.json is information, not a failure.
	out.Reset()
	config := mustRead(t, o.Layout.ConfigPath())
	if err := os.WriteFile(o.Layout.ConfigPath(), append(config, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := o.verifyPreserved(before, plan.ModeReconcile); err != nil || !strings.Contains(out.String(), "note: the core rewrote") || !strings.Contains(out.String(), "preserved:") {
		t.Errorf("core rewrite: %v, out %q", err, out)
	}

	// A migration says it migrated, whoever else touched the file.
	for _, mode := range []plan.Mode{plan.ModeMigrate, plan.ModeRestartMigrate, plan.ModeSubnetMigrate} {
		out.Reset()
		if err := o.verifyPreserved(before, mode); err != nil || !strings.Contains(out.String(), "migrated:") || strings.Contains(out.String(), "core rewrote") {
			t.Errorf("%s: %v, out %q", mode, err, out)
		}
	}

	// A rotation names who was reissued and counts the rest.
	out.Reset()
	rotated := *before
	rotated.rotated = []string{"owner"}
	if err := o.verifyPreserved(&rotated, plan.ModeReconcile); err != nil || !strings.Contains(out.String(), "rotated: owner") {
		t.Errorf("rotation: %v, out %q", err, out)
	}

	// An apply that expected a new handover is held to that digest instead.
	expected := *before
	expected.expectedSecretsDigest = digestOf([]byte("something else"))
	if err := o.verifyPreserved(&expected, plan.ModeReconcile); err == nil || !strings.Contains(err.Error(), "changed during this apply") {
		t.Errorf("wrong expected digest: %v", err)
	}

	// Any change to secrets.json is this apply's fault.
	secrets := mustRead(t, o.Layout.SecretsPath())
	if err := os.WriteFile(o.Layout.SecretsPath(), append(secrets, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := o.verifyPreserved(before, plan.ModeReconcile); err == nil || !strings.Contains(err.Error(), "changed during this apply") {
		t.Errorf("modified secrets: %v", err)
	}

	if err := os.Remove(o.Layout.SecretsPath()); err != nil {
		t.Fatal(err)
	}
	if err := o.verifyPreserved(before, plan.ModeReconcile); err == nil || !strings.Contains(err.Error(), "re-read the live credentials") {
		t.Errorf("missing secrets: %v", err)
	}
	if err := os.WriteFile(o.Layout.SecretsPath(), secrets, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(o.Layout.ConfigPath()); err != nil {
		t.Fatal(err)
	}
	if err := o.verifyPreserved(before, plan.ModeReconcile); err == nil || !strings.Contains(err.Error(), "re-read the live configuration") {
		t.Errorf("missing config: %v", err)
	}
}

func TestOnlyImplementedActionsMayBeApplied(t *testing.T) {
	apply := func(ids ...string) plan.Plan {
		var p plan.Plan
		for _, id := range ids {
			p.Actions = append(p.Actions, plan.Action{ID: id, Disposition: plan.Apply})
		}
		return p
	}
	if err := refuseUnimplemented(apply("compose-up", "desert-island")); !errors.Is(err, ErrNotImplemented) || !strings.Contains(err.Error(), "desert-island") || strings.Contains(err.Error(), "compose-up") {
		t.Errorf("unknown action: %v", err)
	}
	if err := refuseUnimplemented(apply("zzz-unknown", "aaa-unknown")); err == nil || !strings.Contains(err.Error(), "aaa-unknown, zzz-unknown") {
		t.Errorf("names not sorted: %v", err)
	}
	if err := refuseUnimplemented(apply("compose-up", "compose-pull")); err != nil {
		t.Errorf("implemented actions refused: %v", err)
	}
	// Only actions that would be applied count; a check or a manual step does not.
	skipped := plan.Plan{Actions: []plan.Action{{ID: "desert-island", Disposition: plan.Verify}, {ID: "other", Disposition: plan.Manual}}}
	if err := refuseUnimplemented(skipped); err != nil {
		t.Errorf("non-apply actions refused: %v", err)
	}
}

func TestAutoXDPTakesTheDiscoveredInterfaceAndNeverGuesses(t *testing.T) {
	auto := state.State{}
	auto.Deployment.XDPInterfaces = []string{"auto"}
	found := discover.Observed{}
	found.Network.DefaultInterface = "enp3s0"

	if got := resolveXDP(auto, found); len(got) != 1 || got[0] != "enp3s0" {
		t.Errorf("auto with a default interface = %v", got)
	}
	if got := resolveXDP(auto, discover.Observed{}); got != nil {
		t.Errorf("auto without one = %v, want nothing (the planner blocks on it)", got)
	}

	explicit := state.State{}
	explicit.Deployment.XDPInterfaces = []string{"eth0", "eth1"}
	got := resolveXDP(explicit, found)
	if len(got) != 2 || got[0] != "eth0" || got[1] != "eth1" {
		t.Errorf("explicit = %v", got)
	}
	got[0] = "mutated"
	if explicit.Deployment.XDPInterfaces[0] != "eth0" {
		t.Error("the result aliases the desired state")
	}
	// "auto" among others is a literal interface name, not a request.
	mixed := state.State{}
	mixed.Deployment.XDPInterfaces = []string{"auto", "eth1"}
	if got := resolveXDP(mixed, found); len(got) != 2 || got[0] != "auto" {
		t.Errorf("mixed = %v", got)
	}
}
