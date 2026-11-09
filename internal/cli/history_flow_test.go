package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/apply"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
)

// commitDesired records desired as a committed generation, the way a finished
// apply would, with the test user standing in for root.
func commitDesired(t *testing.T, layout discover.Layout, desired state.State) {
	t.Helper()
	data, err := desired.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := newTransactionManager(layout).Start([]transaction.Change{{
		Path: layout.DesiredPath(), Data: data, Mode: 0o600,
		UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), Ownership: transaction.Managed,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// twoGenerations is a host whose history holds an older and a newer intent.
func twoGenerations(t *testing.T) (discover.Layout, []string) {
	t.Helper()
	pretendRoot(t, true)
	old := managerOwner
	managerOwner.UID, managerOwner.GID = uint32(os.Getuid()), uint32(os.Getgid())
	t.Cleanup(func() { managerOwner = old })

	layout := freshLayout(t)
	first := state.Default([]string{"owner"})
	commitDesired(t, layout, first)
	second := first
	second.Deployment.LogLevel = "debug"
	commitDesired(t, layout, second)

	restore := discoverHost
	discoverHost = func(_ context.Context, desired state.State, _ discover.Layout) (discover.Observed, error) {
		return fakeObservation(t, desired), nil
	}
	t.Cleanup(func() { discoverHost = restore })
	return layout, []string{
		"-config-root", layout.ConfigRoot, "-data-root", layout.DataRoot,
		"-logrotate-path", layout.LogrotatePath, "-control-unit-path", layout.ControlUnitPath,
	}
}

func TestRollbackRestoresTheEarlierIntentAsANewGeneration(t *testing.T) {
	stub := &engineStub{result: &apply.Result{Transaction: "tx-rollback"}}
	stubEngine(t, stub)
	_, args := twoGenerations(t)

	var out bytes.Buffer
	if err := runBootstrapRollback(context.Background(), &out, append([]string{"-yes"}, args...)); err != nil {
		t.Fatalf("rollback: %v\n%s", err, out.String())
	}
	if stub.runCalls != 1 || !strings.Contains(out.String(), "rollback target: generation 1") {
		t.Errorf("runs = %d\n%s", stub.runCalls, out.String())
	}
	if !strings.Contains(out.String(), "committed as transaction tx-rollback") {
		t.Errorf("no commit report:\n%s", out.String())
	}
}

func TestRollbackRefusesAGenerationItCannotUse(t *testing.T) {
	stub := &engineStub{result: &apply.Result{}}
	stubEngine(t, stub)
	_, args := twoGenerations(t)
	for _, generation := range []string{"2", "9"} {
		err := runBootstrapRollback(context.Background(), &bytes.Buffer{}, append([]string{"-yes", "-generation", generation}, args...))
		if err == nil {
			t.Errorf("generation %s was accepted", generation)
		}
	}
	if stub.runCalls != 0 {
		t.Error("the engine ran for a refused rollback")
	}
}

func TestRollbackReportsEngineFailures(t *testing.T) {
	_, args := twoGenerations(t)
	for _, stub := range []*engineStub{{optionsErr: os.ErrInvalid}, {runErr: os.ErrInvalid}} {
		stubEngine(t, stub)
		if err := runBootstrapRollback(context.Background(), &bytes.Buffer{}, append([]string{"-yes"}, args...)); err == nil {
			t.Error("an engine failure was swallowed")
		}
	}
}

func TestRotateReissuesNamedUsersAsANewGeneration(t *testing.T) {
	stub := &engineStub{result: &apply.Result{Transaction: "tx-rotate"}}
	stubEngine(t, stub)
	_, args := twoGenerations(t)

	var out bytes.Buffer
	if err := runBootstrapRotate(context.Background(), &out, append([]string{"-yes", "-users", "owner"}, args...)); err != nil {
		t.Fatalf("rotate: %v\n%s", err, out.String())
	}
	if stub.runCalls != 1 || !strings.Contains(out.String(), "committed as transaction tx-rotate") {
		t.Errorf("runs = %d\n%s", stub.runCalls, out.String())
	}
	if !strings.Contains(out.String(), "new client credentials for owner") {
		t.Errorf("the seed user is not told where the new credentials are:\n%s", out.String())
	}
}

func TestRotateReportsEngineFailures(t *testing.T) {
	_, args := twoGenerations(t)
	for _, stub := range []*engineStub{{optionsErr: os.ErrInvalid}, {runErr: os.ErrInvalid}} {
		stubEngine(t, stub)
		if err := runBootstrapRotate(context.Background(), &bytes.Buffer{}, append([]string{"-yes", "-users", "owner"}, args...)); err == nil {
			t.Error("an engine failure was swallowed")
		}
	}
}

func TestPruneKeepsTheRetainedGenerationsAndPreviewsByDefault(t *testing.T) {
	_, args := twoGenerations(t)
	var out bytes.Buffer
	if err := runBootstrapPrune(context.Background(), &out, append([]string{"-keep", "2"}, args...)); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if !strings.Contains(out.String(), "preview only") {
		t.Errorf("a prune without -yes did not preview:\n%s", out.String())
	}
	out.Reset()
	if err := runBootstrapPrune(context.Background(), &out, append([]string{"-keep", "2", "-yes"}, args...)); err != nil {
		t.Fatalf("prune -yes: %v", err)
	}
	if !strings.Contains(out.String(), "pruned 0 transaction(s)") {
		t.Errorf("output:\n%s", out.String())
	}
}
