package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/apply"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/health"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

func TestWritePlanMarksWhatChangesTheHostAndSaysWhyItIsBlocked(t *testing.T) {
	built := plan.Plan{
		DesiredDigest: "abcdef0123456789", ObservationDigest: "short", Mode: plan.Mode("install"), Blocked: true,
		Changes: []state.Change{{Class: state.Migration, Path: "/deployment/tier", Before: "a", After: "b"}},
		Actions: []plan.Action{
			{ID: "write", Disposition: plan.Apply, Mutates: true, Summary: "write config", Reason: "r1", Proof: "p1", Rollback: "restore file"},
			{ID: "check", Disposition: plan.Manual, Summary: "check dns", Reason: "r2", Proof: "p2", Rollback: "none"},
		},
	}
	var out bytes.Buffer
	writePlan(&out, "/etc/desired.json", built)
	text := out.String()
	for _, want := range []string{
		"desired state: /etc/desired.json", "desired abcdef012345 / host short",
		"changes against the stored intent:", "/deployment/tier: a -> b",
		"* ", "write config", "undo:  restore file", "2 actions, 1 of which change this host", "BLOCKED",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q:\n%s", want, text)
		}
	}
	if strings.Count(text, "undo:") != 1 {
		t.Errorf("an action with nothing to undo printed an undo line:\n%s", text)
	}
	if short("abc") != "abc" || short("0123456789abcdef") != "0123456789ab" {
		t.Error("short digest")
	}
}

func TestWriteResultListsWhatCannotBeProvedFromThisHost(t *testing.T) {
	layout, _ := statusLayout(t)
	desired := state.Default([]string{"owner"})
	approved := plan.Plan{Actions: []plan.Action{{Disposition: plan.Manual, Summary: "reach the port", Proof: "probe from outside"}}}
	result := &apply.Result{
		Transaction: "tx-9", Files: []string{"a", "b"}, FirewallAdded: []string{"10861/tcp"},
		Health: &health.Report{Samples: 3, Waited: 2500 * time.Millisecond},
	}
	var out bytes.Buffer
	writeResult(&out, layout, desired, approved, result)
	text := out.String()
	for _, want := range []string{
		"applied: transaction tx-9, 2 managed files", "healthy after 2.5s (3 samples)", "opened 10861/tcp on the host firewall",
		layout.SecretsPath(), "reach the port: probe from outside", "a provider firewall must allow:", "encrypted backup",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q:\n%s", want, text)
		}
	}
	out.Reset()
	writeResult(&out, layout, desired, plan.Plan{}, &apply.Result{Transaction: "tx-1"})
	if strings.Contains(out.String(), "healthy after") || strings.Contains(out.String(), "opened ") {
		t.Errorf("claims without evidence:\n%s", out.String())
	}
}

func TestConfirmAcceptsOnlyAnExplicitYes(t *testing.T) {
	for input, want := range map[string]bool{"yes\n": true, "  YES \n": true, "y\n": false, "\n": false, "no\n": false, "yes": true} {
		stdinFrom(t, input)
		var out bytes.Buffer
		got, err := confirm(&out, "go? ")
		if err != nil || got != want || !strings.Contains(out.String(), "go? ") {
			t.Errorf("%q: got=%v err=%v", input, got, err)
		}
	}
	stdinFrom(t, "")
	if _, err := confirm(&bytes.Buffer{}, "go? "); err == nil {
		t.Error("end of input counted as an answer")
	}
	_ = os.Stdin
}

func TestRotationDesiredKeepsTheAuditTrailAndIDsAreSortableAndUnique(t *testing.T) {
	current := state.Default([]string{"owner", "guest"})
	current.MigrationPolicy = &state.MigrationPolicy{RotateCredentials: &state.CredentialRotation{ID: "old", Users: []string{"guest"}, Strategy: state.CredentialRotationStrategyReissue}}
	desired, err := rotationDesired(current, []string{"owner"}, "new-id")
	if err != nil {
		t.Fatal(err)
	}
	rotation := desired.MigrationPolicy.RotateCredentials
	if rotation.ID != "new-id" || len(rotation.Users) != 1 || rotation.Users[0] != "owner" || rotation.Strategy != state.CredentialRotationStrategyReissue {
		t.Errorf("rotation = %+v", rotation)
	}
	if current.MigrationPolicy.RotateCredentials.ID != "old" {
		t.Error("the current state was modified")
	}
	if _, err := rotationDesired(state.Default([]string{"owner"}), []string{"owner"}, "id"); err != nil {
		t.Errorf("from no policy: %v", err)
	}

	at := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	a, err := newRotationID(at)
	b, _ := newRotationID(at)
	later, _ := newRotationID(at.Add(time.Second))
	if err != nil || !strings.HasPrefix(a, "20261108T100000Z-") || a == b || later <= a {
		t.Errorf("ids: %q %q %q (%v)", a, b, later, err)
	}
}
