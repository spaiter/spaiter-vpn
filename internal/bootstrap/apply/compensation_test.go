package apply

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/health"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/firewall"
)

// undoFixture is a harness with a started transaction and a previous compose
// project on disk, ready for compensation to undo.
func undoFixture(t *testing.T, mode plan.Mode) (*harness, *compensation, *bytes.Buffer) {
	t.Helper()
	h := newHarness(t)
	target := h.layout.ComposePath()
	project := "services:\n  " + deploy.CoreServiceName + ":\n    image: x\n"
	change := func(data string) []transaction.Change {
		return []transaction.Change{{
			Path: target, Data: []byte(data), Mode: 0o644,
			UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), Ownership: transaction.Managed,
		}}
	}
	// The previous generation, committed: what compensation must put back.
	first, err := h.options.Manager.Start(change(project))
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := first.Commit(); err != nil {
		t.Fatal(err)
	}
	tx, err := h.options.Manager.Start(change(project + "# new\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	h.options.Out = &out
	h.options.Health = health.Wait
	return h, &compensation{tx: tx, mode: mode}, &out
}

func TestUndoOfAFreshInstallStopsTheProjectAndReportsEveryStepThatFailed(t *testing.T) {
	h, undo, _ := undoFixture(t, plan.ModeFresh)
	h.compose.downErr = errors.New("daemon gone")
	fw := &fakeFirewall{removeErr: errors.New("ufw refused"), addErr: errors.New("ufw refused")}
	h.options.Firewall = fw
	undo.added = []firewall.Rule{{Port: 1000, Network: "tcp"}}
	undo.retired = []firewall.Rule{{Port: 2000, Network: "udp"}}

	err := undo.run(context.Background(), h.options)
	if err == nil {
		t.Fatal("a rollback with failures reported success")
	}
	for _, want := range []string{"rollback incomplete", "stop the compose project", "close 1000/tcp", "re-open 2000/udp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
}

func TestUndoOfAFreshInstallThatWorksSaysSo(t *testing.T) {
	h, undo, out := undoFixture(t, plan.ModeFresh)
	h.options.Firewall = &fakeFirewall{}
	if err := undo.run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "compose project stopped") {
		t.Errorf("output = %q", out.String())
	}
}

func TestUndoOfAConvergenceRestartsThePreviousDeploymentEachWay(t *testing.T) {
	for mode, wanted := range map[plan.Mode]string{
		plan.ModeReconcile:      "previous deployment is running again",
		plan.ModeMigrate:        "previous configuration re-applied",
		plan.ModeRestartMigrate: "force-recreated",
		plan.ModeSubnetMigrate:  "force-recreated",
		plan.ModeRestartRecover: "recovered configuration force-recreated",
	} {
		h, undo, out := undoFixture(t, mode)
		h.options.Firewall = &fakeFirewall{}
		if err := undo.run(context.Background(), h.options); err != nil {
			t.Errorf("%s: %v", mode, err)
			continue
		}
		if !strings.Contains(out.String(), wanted) {
			t.Errorf("%s: output = %q", mode, out.String())
		}
	}
}

func TestUndoReportsAPreviousDeploymentThatDoesNotComeBack(t *testing.T) {
	cases := map[string]struct {
		mode  plan.Mode
		setup func(h *harness)
		want  string
	}{
		"up fails":       {plan.ModeReconcile, func(h *harness) { h.compose.upErr = errors.New("no") }, "restart the previous deployment"},
		"recreate fails": {plan.ModeRestartMigrate, func(h *harness) { h.compose.recreateErr = errors.New("no") }, "restart the previous deployment"},
		"runtime sync": {plan.ModeReconcile, func(h *harness) {
			h.options.ApplyRuntime = func(context.Context) error { return errors.New("api down") }
		}, "synchronise the restored configuration"},
		"no project": {plan.ModeReconcile, func(h *harness) { h.compose.upErr = nil; os.Remove(h.layout.ComposePath()) }, "restored compose project"},
		"unhealthy":  {plan.ModeReconcile, func(h *harness) { h.compose.states = nil }, "did not come back"},
	}
	for name, tc := range cases {
		h, undo, _ := undoFixture(t, tc.mode)
		h.options.Firewall = &fakeFirewall{}
		tc.setup(h)
		if tc.want == "restored compose project" {
			// The transaction restores the file, so make the project unreadable afterwards.
			h.options.Layout.ConfigRoot = filepath.Join(h.layout.ConfigRoot, "elsewhere")
		}
		err := undo.run(context.Background(), h.options)
		if err == nil || !strings.Contains(err.Error(), "rollback incomplete") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestUndoDoesNotRestartWhatItCouldNotRestore(t *testing.T) {
	h, undo, _ := undoFixture(t, plan.ModeReconcile)
	h.options.Firewall = &fakeFirewall{}
	if err := undo.tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	err := undo.run(context.Background(), h.options)
	if err == nil || !strings.Contains(err.Error(), "restore managed files") || !strings.Contains(err.Error(), "not restarting the previous deployment") {
		t.Errorf("error = %v", err)
	}
	for _, call := range h.compose.calls {
		if call == "up" || call == "recreate" {
			t.Errorf("compose ran %q on files that were not restored", call)
		}
	}
}
