package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/apply"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/health"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

func TestInstallsDockerOnlyWhenThePlanActuallyAppliesIt(t *testing.T) {
	mk := func(id string, d plan.Disposition) plan.Plan {
		return plan.Plan{Actions: []plan.Action{{ID: "other", Disposition: plan.Apply}, {ID: id, Disposition: d}}}
	}
	for _, id := range []string{"docker-install", "docker-compose-install"} {
		if !installsDocker(mk(id, plan.Apply)) {
			t.Errorf("%s applied was not noticed", id)
		}
		// A manual or skipped install is not an install: treating it as one
		// would defer sing-box detection to a Docker that never arrives.
		if installsDocker(mk(id, plan.Manual)) || installsDocker(mk(id, "skip")) {
			t.Errorf("%s not applied was counted as an install", id)
		}
	}
	if installsDocker(plan.Plan{}) {
		t.Error("an empty plan installs nothing")
	}
}

func TestWriteResultEndsWithWhatIsStillUnproven(t *testing.T) {
	layout := discover.Layout{ConfigRoot: "/etc/x", DataRoot: "/var/x"}
	desired := state.Default([]string{"alice"})
	approved := plan.Plan{Actions: []plan.Action{
		{ID: "external-checks", Disposition: plan.Manual, Summary: "verify reachability", Proof: "probe succeeds externally"},
		{ID: "files", Disposition: plan.Apply, Summary: "write the files", Proof: "SHOULD-NOT-APPEAR"},
	}}
	result := &apply.Result{
		Transaction: "tx-7", Files: []string{"a", "b"},
		Health:        &health.Report{Samples: 4, Waited: 12345 * time.Millisecond},
		FirewallAdded: []string{"10861/tcp"},
	}
	var out bytes.Buffer
	writeResult(&out, layout, desired, approved, result)
	got := out.String()
	for _, want := range []string{
		"applied: transaction tx-7, 2 managed files", "healthy after 12.345s (4 samples)",
		"opened 10861/tcp on the host firewall", layout.SecretsPath(),
		"Still unproven from this host:", "verify reachability: probe succeeds externally",
		"a provider firewall must allow:", "spaiter-vpn probe", "encrypted backup",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "SHOULD-NOT-APPEAR") {
		t.Error("an applied action was listed as unproven")
	}

	out.Reset()
	writeResult(&out, layout, desired, plan.Plan{}, &apply.Result{Transaction: "t"})
	if strings.Contains(out.String(), "healthy after") || strings.Contains(out.String(), "opened ") {
		t.Errorf("claims without evidence:\n%s", out.String())
	}
}

func withStdin(t *testing.T, input string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString(input)
	w.Close()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; r.Close() })
}

func TestConfirmNeedsAnExplicitYes(t *testing.T) {
	for input, want := range map[string]bool{
		"yes\n": true, " YES \n": true, "Yes": true, // no newline at EOF still counts
		"y\n": false, "\n": false, "no\n": false, "yess\n": false, "yes please\n": false,
	} {
		withStdin(t, input)
		var out bytes.Buffer
		got, err := confirm(&out, "Proceed? ")
		if err != nil || got != want {
			t.Errorf("confirm(%q) = %v, %v; want %v", input, got, err, want)
		}
		if out.String() != "Proceed? " {
			t.Errorf("prompt = %q", out.String())
		}
	}
	withStdin(t, "") // a closed stdin must not read as consent
	if ok, err := confirm(&bytes.Buffer{}, ""); ok || err == nil {
		t.Errorf("EOF: %v, %v", ok, err)
	}
}

func TestSynthesizeRollbackRefusesWhenThereIsNothingToRollBackTo(t *testing.T) {
	dir := t.TempDir()
	layout := discover.Layout{ConfigRoot: dir + "/etc", DataRoot: dir + "/var"}
	_, _, err := synthesizeRollback(layout, 0)
	if err == nil {
		t.Fatal("a rollback on a host with no committed generation was synthesized")
	}
	if _, _, err := synthesizeRollback(layout, 5); err == nil {
		t.Fatal("a rollback to generation 5 of nothing was synthesized")
	}
}

func TestSelfPathOrNameIsNeverEmpty(t *testing.T) {
	if selfPathOrName() == "" {
		t.Error("empty")
	}
}
