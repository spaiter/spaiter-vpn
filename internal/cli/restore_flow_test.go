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
)

// restoreHost is a fresh server and an archive to restore onto it, with the
// engine stubbed and the test user owning the transaction directories.
func restoreHost(t *testing.T, stub *engineStub) (args []string, target discover.Layout) {
	t.Helper()
	archive, passFile, _ := archiveOf(t)
	target = freshLayout(t)
	pretendRoot(t, true)
	old := managerOwner
	managerOwner.UID, managerOwner.GID = uint32(os.Getuid()), uint32(os.Getgid())
	t.Cleanup(func() { managerOwner = old })
	stubEngine(t, stub)
	restore := discoverHost
	discoverHost = func(_ context.Context, desired state.State, _ discover.Layout) (discover.Observed, error) {
		return fakeObservation(t, desired), nil
	}
	t.Cleanup(func() { discoverHost = restore })
	return append(layoutArgs(target), "-from", archive, "-passphrase-file", passFile, "-yes"), target
}

func TestRestoreInstallsTheBackupThroughTheEngine(t *testing.T) {
	stub := &engineStub{result: &apply.Result{Transaction: "tx-restore"}}
	args, target := restoreHost(t, stub)

	var out bytes.Buffer
	if err := runRestore(context.Background(), &out, append(args, "-keep-address")); err != nil {
		t.Fatalf("restore: %v\n%s", err, out.String())
	}
	if stub.runCalls != 1 {
		t.Errorf("engine runs = %d", stub.runCalls)
	}
	for _, want := range []string{"Backup of", "Placed", "No key is generated"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("lacks %q:\n%s", want, out.String())
		}
	}
	token, err := os.ReadFile(target.CredentialDir() + "/telegram-token")
	if err != nil || string(token) != "123:abc" {
		t.Errorf("credential = %q, %v", token, err)
	}
}

func TestRestoreToANewAddressTellsClientsWhatChanged(t *testing.T) {
	stub := &engineStub{result: &apply.Result{Transaction: "tx-restore"}}
	args, _ := restoreHost(t, stub)

	var out bytes.Buffer
	if err := runRestore(context.Background(), &out, append(args, "-public-host", "203.0.113.77")); err != nil {
		t.Fatalf("restore: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "203.0.113.77") {
		t.Errorf("the new address is not reported:\n%s", out.String())
	}
}

func TestRestoreReportsEngineFailuresAfterPlacingTheState(t *testing.T) {
	for _, stub := range []*engineStub{{optionsErr: os.ErrInvalid}, {runErr: os.ErrInvalid}} {
		args, _ := restoreHost(t, stub)
		if err := runRestore(context.Background(), &bytes.Buffer{}, append(args, "-keep-address")); err == nil {
			t.Error("an engine failure was swallowed")
		}
	}
}

func TestRestoreStopsAtABlockedPlanOrANonFreshServer(t *testing.T) {
	stub := &engineStub{result: &apply.Result{}}
	args, _ := restoreHost(t, stub)
	discoverHost = func(_ context.Context, desired state.State, _ discover.Layout) (discover.Observed, error) {
		observed := fakeObservation(t, desired)
		observed.Platform.OS = "plan9"
		return observed, nil
	}
	err := runRestore(context.Background(), &bytes.Buffer{}, append(args, "-keep-address"))
	if err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Errorf("err = %v", err)
	}
	if stub.runCalls != 0 {
		t.Error("the engine ran for a blocked plan")
	}
}
