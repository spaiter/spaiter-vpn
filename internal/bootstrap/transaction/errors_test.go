package transaction

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCurrentIsReadOnlyAndRefusesAnUnsafeOrCorruptReceipt(t *testing.T) {
	h := newHarness(t)
	if _, ok, err := h.manager.Current(); ok || err != nil {
		t.Fatalf("fresh host: ok=%v err=%v", ok, err)
	}
	if _, err := os.Stat(h.manager.StateDir); err == nil {
		t.Fatal("Current created the state directory")
	}

	commitChange(t, h, h.change("one", Managed))
	receipt, ok, err := h.manager.Current()
	if err != nil || !ok || receipt.Sequence != 1 {
		t.Fatalf("committed: %+v ok=%v err=%v", receipt, ok, err)
	}

	path := h.manager.currentPath()
	good, _ := os.ReadFile(path)
	for name, mutate := range map[string]func(){
		"loose mode":    func() { os.Chmod(path, 0o644) },
		"not json":      func() { os.WriteFile(path, []byte("{nope"), 0o600) },
		"trailing json": func() { os.WriteFile(path, append(append([]byte(nil), good...), []byte(`{"x":1}`)...), 0o600) },
		"unknown field": func() { os.WriteFile(path, []byte(`{"apiVersion":"x","bogus":1}`), 0o600) },
		"wrong version": func() { os.WriteFile(path, []byte(`{"apiVersion":"other","files":{}}`), 0o600) },
	} {
		os.WriteFile(path, good, 0o600)
		os.Chmod(path, 0o600)
		mutate()
		if _, _, err := h.manager.Current(); err == nil {
			t.Errorf("%s: a damaged receipt was accepted", name)
		}
	}

	os.Remove(path)
	if err := os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.manager.Current(); err == nil {
		t.Error("a symlinked receipt was accepted")
	}
}

func TestTheLockIsExclusiveAndTheGuardCannotBeReused(t *testing.T) {
	h := newHarness(t)
	guard, err := h.manager.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.Lock(); !errors.Is(err, ErrLocked) {
		t.Errorf("second Lock = %v, want ErrLocked", err)
	}
	if err := guard.Release(); err != nil {
		t.Fatal(err)
	}
	if err := guard.Release(); err != nil {
		t.Errorf("second Release: %v", err)
	}
	if _, err := guard.Start([]Change{h.change("x", Managed)}); err == nil || !strings.Contains(err.Error(), "already been released") {
		t.Errorf("Start after Release: %v", err)
	}
	again, err := h.manager.Lock()
	if err != nil {
		t.Fatalf("the lock was not freed: %v", err)
	}
	again.Release()
}

func TestAnUnsafeLockFileIsRefused(t *testing.T) {
	h := newHarness(t)
	g, err := h.manager.Lock()
	if err != nil {
		t.Fatal(err)
	}
	g.Release()
	if err := os.Chmod(h.manager.lockPath(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.Lock(); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Errorf("err = %v", err)
	}
}

func TestGenerationFileRefusesWhatTheReceiptNeverOwned(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("one", Managed))
	other := filepath.Join(h.root, "managed", "other.json")
	cases := map[string]struct {
		seq  uint64
		path string
		want string
	}{
		"outside the allowlist": {1, other, "outside the transaction allowlist"},
		"no such generation":    {9, h.target, "does not exist"},
	}
	for name, c := range cases {
		if _, err := h.manager.GenerationFile(c.seq, c.path); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	h.manager.AllowedTargets = append(h.manager.AllowedTargets, other)
	if _, err := h.manager.GenerationFile(1, other); err == nil || !strings.Contains(err.Error(), "did not own") {
		t.Errorf("unowned file: %v", err)
	}
	if data, err := h.manager.GenerationFile(1, h.target); err != nil || string(data) != "one" {
		t.Errorf("current content: %q, %v", data, err)
	}
}

func TestGenerationsAreEmptyOnAFreshManagerAndRefuseCorruptJournals(t *testing.T) {
	h := newHarness(t)
	got, err := h.manager.Generations()
	if err != nil || len(got) != 0 {
		t.Fatalf("fresh: %v %v", got, err)
	}
	commitChange(t, h, h.change("one", Managed))
	commitChange(t, h, h.change("two", Managed))
	got, err = h.manager.Generations()
	if err != nil || len(got) != 2 || got[0].Sequence != 1 || got[1].Sequence != 2 {
		t.Fatalf("generations = %+v, %v", got, err)
	}
	if got[1].Transaction == "" {
		t.Error("generation without a transaction id")
	}
}

func TestATransactionKnowsItsIDAndCannotBeAppliedTwice(t *testing.T) {
	h := newHarness(t)
	tx, err := h.manager.Start([]Change{h.change("one", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	if tx.ID() != "tx-1" {
		t.Errorf("ID = %q", tx.ID())
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err == nil || !strings.Contains(err.Error(), "status") {
		t.Errorf("second Apply: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("Apply after Commit: %v", err)
	}
}

func TestApplyNoticesATargetThatChangedAfterPlanning(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("one", Managed))
	tx, err := h.manager.Start([]Change{h.change("two", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := os.WriteFile(h.target, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err == nil || !strings.Contains(err.Error(), "changed after the transaction was planned") {
		t.Errorf("tampered target: %v", err)
	}

	// A file that vanished.
	h2 := newHarness(t)
	commitChange(t, h2, h2.change("one", Managed))
	tx2, err := h2.manager.Start([]Change{h2.change("two", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	defer tx2.Rollback()
	os.Remove(h2.target)
	if err := tx2.Apply(); err == nil || !strings.Contains(err.Error(), "disappeared") {
		t.Errorf("vanished target: %v", err)
	}
}
