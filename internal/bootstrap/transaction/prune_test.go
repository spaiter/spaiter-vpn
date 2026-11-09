package transaction

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestPrunePreviewRetainsReconstructableGenerationsAndForeignDirectories(t *testing.T) {
	h := newHarness(t)
	for _, value := range []string{"one", "two", "three", "four"} {
		commitChange(t, h, h.change(value, Managed))
	}
	foreignDir := filepath.Join(h.manager.transactionsDir(), "operator-notes")
	if err := os.Mkdir(foreignDir, 0o700); err != nil {
		t.Fatal(err)
	}
	foreignFile := filepath.Join(foreignDir, "notes.txt")
	if err := os.WriteFile(foreignFile, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}

	preview, err := h.manager.Prune(2, true)
	if err != nil {
		t.Fatal(err)
	}
	if !preview.DryRun || len(preview.Retained) != 2 || len(preview.Selected) != 2 {
		t.Fatalf("preview = %#v", preview)
	}
	for sequence := 1; sequence <= 2; sequence++ {
		if _, err := os.Stat(transactionDir(h, sequence)); err != nil {
			t.Fatalf("preview deleted transaction %d: %v", sequence, err)
		}
	}

	result, err := h.manager.Prune(2, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.DryRun || len(result.Selected) != 2 {
		t.Fatalf("result = %#v", result)
	}
	for sequence := 1; sequence <= 2; sequence++ {
		if _, err := os.Stat(transactionDir(h, sequence)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("transaction %d still exists: %v", sequence, err)
		}
	}
	generations, err := h.manager.Generations()
	if err != nil {
		t.Fatal(err)
	}
	if len(generations) != 2 || generations[0].Sequence != 3 || generations[1].Sequence != 4 {
		t.Fatalf("retained generations = %#v", generations)
	}
	for index, want := range []string{"three", "four"} {
		data, err := h.manager.GenerationFile(generations[index].Sequence, h.target)
		if err != nil {
			t.Fatalf("generation %d: %v", generations[index].Sequence, err)
		}
		if string(data) != want {
			t.Fatalf("generation %d file = %q, want %q", generations[index].Sequence, data, want)
		}
	}
	if data, err := os.ReadFile(foreignFile); err != nil || string(data) != "keep me" {
		t.Fatalf("foreign directory was changed: data=%q err=%v", data, err)
	}
}

func TestPruneRemovesOldRolledBackTransactions(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("one", Managed))
	tx, err := h.manager.Start([]Change{h.change("two", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	commitChange(t, h, h.change("three", Managed))
	commitChange(t, h, h.change("four", Managed))

	result, err := h.manager.Prune(2, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Selected) != 2 || result.Selected[0].Status != string(statusCommitted) || result.Selected[1].Status != string(statusRolledBack) {
		t.Fatalf("selected = %#v", result.Selected)
	}
	if _, err := os.Stat(transactionDir(h, 2)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rolled-back transaction still exists: %v", err)
	}
}

func TestPruneRequiresCurrentAndPreviousGenerations(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("one", Managed))
	for _, keep := range []int{0, 1} {
		if _, err := h.manager.Prune(keep, false); err == nil {
			t.Fatalf("keep=%d was accepted", keep)
		}
	}
	generations, err := h.manager.Generations()
	if err != nil {
		t.Fatal(err)
	}
	if len(generations) != 1 {
		t.Fatalf("generations = %#v", generations)
	}
}

func transactionDir(h *harness, sequence int) string {
	return filepath.Join(h.manager.transactionsDir(), fmt.Sprintf("%020d-tx-%d", sequence, sequence))
}
