package cli

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/apply"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	"github.com/spaiter/spaiter-vpn/internal/control"
)

func historyBackend(t *testing.T) *controlBackend {
	t.Helper()
	layout, _ := twoGenerations(t)
	t.Setenv("PATH", t.TempDir()) // no docker: services are reported as unavailable
	return &controlBackend{layout: layout}
}

func TestControlBackendListsGenerationsAndReportsTheCurrentOne(t *testing.T) {
	b := historyBackend(t)
	generations, err := b.Generations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if list, ok := generations.([]transaction.Generation); ok && len(list) != 2 {
		t.Errorf("generations = %v", list)
	}
	got, err := b.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	status := got.(controlStatus)
	if status.Generation != 2 || status.Transaction == "" || status.ServicesError == "" {
		t.Errorf("status = %+v", status)
	}
}

func TestControlPrepareThenCommitDrivesTheEngine(t *testing.T) {
	stub := &engineStub{result: &apply.Result{Transaction: "tx-control"}}
	stubEngine(t, stub)
	b := historyBackend(t)

	for _, change := range []control.Change{
		{Kind: control.ChangeImage, Image: sameRepository("t2")},
		{Kind: control.ChangeRollback},
		{Kind: control.ChangeRotate, Users: []string{"owner"}},
		{Kind: control.ChangeSettings, Ports: map[string]uint16{"awg-in": 34567}},
	} {
		prepared, err := b.Prepare(context.Background(), change, io.Discard)
		if err != nil {
			t.Fatalf("%s: prepare: %v", change.Kind, err)
		}
		_, txID, err := prepared.Commit(context.Background(), io.Discard)
		if err != nil || txID != "tx-control" {
			t.Errorf("%s: commit = %q, %v", change.Kind, txID, err)
		}
	}
	if stub.runCalls != 4 {
		t.Errorf("engine runs = %d", stub.runCalls)
	}
}

func TestControlCommitReportsEngineFailures(t *testing.T) {
	b := historyBackend(t)
	for _, stub := range []*engineStub{{optionsErr: os.ErrInvalid}, {runErr: os.ErrInvalid}} {
		stubEngine(t, stub)
		prepared, err := b.Prepare(context.Background(), control.Change{Kind: control.ChangeImage, Image: sameRepository("t3")}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := prepared.Commit(context.Background(), io.Discard); err == nil {
			t.Error("an engine failure was swallowed")
		}
	}
}

func TestControlPrepareRefusesABlockedPlan(t *testing.T) {
	stubEngine(t, &engineStub{})
	b := historyBackend(t)
	discoverHost = func(_ context.Context, desired state.State, _ discover.Layout) (discover.Observed, error) {
		observed := fakeObservation(t, desired)
		observed.Platform.OS = "plan9"
		return observed, nil
	}
	_, err := b.Prepare(context.Background(), control.Change{Kind: control.ChangeImage, Image: sameRepository("t4")}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "the plan is blocked") {
		t.Errorf("err = %v", err)
	}
}

func TestControlPreflightRunsAgainstTheStoredIntent(t *testing.T) {
	b := historyBackend(t)
	var out strings.Builder
	got, err := b.Preflight(context.Background(), &out)
	counts, ok := got.(map[string]int)
	if !ok {
		t.Fatalf("result = %#v, err = %v", got, err)
	}
	if _, has := counts["pass"]; !has || out.Len() == 0 {
		t.Errorf("counts = %v, report empty = %v", counts, out.Len() == 0)
	}
}

// sameRepository is an image tag from the repository the default intent deploys.
func sameRepository(tag string) string {
	image := state.Default([]string{"owner"}).Deployment.Image
	if i := strings.LastIndexAny(image, ":@"); i > strings.LastIndex(image, "/") {
		image = image[:i]
	}
	return image + ":" + tag
}
