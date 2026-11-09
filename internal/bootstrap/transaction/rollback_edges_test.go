package transaction

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// applied returns a transaction whose single operation has been applied over an
// existing committed file, so a rollback has a real backup to restore from.
func applied(t *testing.T) (*harness, *Transaction) {
	t.Helper()
	h := newHarness(t)
	commitChange(t, h, h.change("original", Managed))
	tx, err := h.manager.Start([]Change{h.change("replacement", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	return h, tx
}

func backupFile(t *testing.T, tx *Transaction) string {
	t.Helper()
	name := tx.journal.Operations[0].BackupName
	if name == "" {
		t.Fatal("the operation has no backup")
	}
	return filepath.Join(tx.dir, "backups", name)
}

func TestRollbackRestoresThePriorContent(t *testing.T) {
	h, tx := applied(t)
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(h.target); string(got) != "original" {
		t.Errorf("target = %q", got)
	}
	if err := tx.Rollback(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("second Rollback: %v", err)
	}
}

func TestRollbackRefusesToOverwriteContentItDidNotWrite(t *testing.T) {
	h, tx := applied(t)
	os.WriteFile(h.target, []byte("someone else"), 0o600)
	err := tx.Rollback()
	if err == nil || !strings.Contains(err.Error(), "written outside this transaction") {
		t.Fatalf("err = %v", err)
	}
	if got, _ := os.ReadFile(h.target); string(got) != "someone else" {
		t.Errorf("the foreign content was overwritten: %q", got)
	}
	if tx.journal.Status != statusRollbackIncomplete {
		t.Errorf("status = %q, want the journal to say the rollback is incomplete", tx.journal.Status)
	}
}

func TestRollbackRefusesABackupThatIsMissingTamperedOrLoose(t *testing.T) {
	cases := map[string]struct {
		damage func(t *testing.T, tx *Transaction)
		want   string
	}{
		"missing": {func(t *testing.T, tx *Transaction) { os.Remove(backupFile(t, tx)) }, "missing or does not match"},
		"tampered": {func(t *testing.T, tx *Transaction) {
			os.WriteFile(backupFile(t, tx), []byte("forged"), 0o600)
		}, "missing or does not match"},
		"loose mode": {func(t *testing.T, tx *Transaction) { os.Chmod(backupFile(t, tx), 0o644) }, "unsafe"},
		"unnamed":    {func(t *testing.T, tx *Transaction) { tx.journal.Operations[0].BackupName = "" }, "no backup"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h, tx := applied(t)
			c.damage(t, tx)
			err := tx.Rollback()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if got, _ := os.ReadFile(h.target); string(got) != "replacement" {
				t.Errorf("a failed restore touched the target: %q", got)
			}
		})
	}
}

func TestRollbackOfAFreshFileRemovesItAndToleratesItBeingGone(t *testing.T) {
	h := newHarness(t)
	tx, err := h.manager.Start([]Change{h.change("fresh", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.target); err == nil {
		t.Error("the file this transaction created is still there")
	}

	// Gone before the rollback: nothing to remove, still a clean rollback.
	h2 := newHarness(t)
	tx2, _ := h2.manager.Start([]Change{h2.change("fresh", Managed)})
	tx2.Apply()
	os.Remove(h2.target)
	if err := tx2.Rollback(); err != nil {
		t.Errorf("rollback with the file already gone: %v", err)
	}

	// Replaced by something else: neither ours nor the prior state.
	h3 := newHarness(t)
	tx3, _ := h3.manager.Start([]Change{h3.change("fresh", Managed)})
	tx3.Apply()
	os.WriteFile(h3.target, []byte("not ours"), 0o600)
	if err := tx3.Rollback(); err == nil || !strings.Contains(err.Error(), "neither the transaction output nor the prior state") {
		t.Errorf("foreign content: %v", err)
	}
	if got, _ := os.ReadFile(h3.target); string(got) != "not ours" {
		t.Errorf("foreign content was removed: %q", got)
	}
}

func TestACommittedTransactionCannotBeRolledBackAsIncomplete(t *testing.T) {
	h := newHarness(t)
	tx, _ := h.manager.Start([]Change{h.change("one", Managed)})
	tx.Apply()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := tx.rollbackLocked(); err == nil || !strings.Contains(err.Error(), "cannot be rolled back") {
		t.Errorf("err = %v", err)
	}
	tx.journal.Status = statusRolledBack
	if err := tx.rollbackLocked(); err != nil {
		t.Errorf("an already rolled back transaction: %v", err)
	}
}

func TestRecoveryRetriesAnIncompleteRollbackOnceTheObstacleIsGone(t *testing.T) {
	h, tx := applied(t)
	os.WriteFile(h.target, []byte("someone else"), 0o600)
	if err := tx.Rollback(); err == nil {
		t.Fatal("setup: the rollback should have been refused")
	}

	// While the obstacle stands, recovery reports it and keeps the journal.
	if err := h.manager.Recover(); err == nil || !strings.Contains(err.Error(), "recover transaction") {
		t.Fatalf("Recover = %v", err)
	}
	// The operator puts back what the transaction wrote; recovery now finishes.
	os.WriteFile(h.target, []byte("replacement"), 0o600)
	if err := h.manager.Recover(); err != nil {
		t.Fatalf("Recover after the obstacle was removed: %v", err)
	}
	if got, _ := os.ReadFile(h.target); string(got) != "original" {
		t.Errorf("target = %q, want the prior content back", got)
	}
	if err := h.manager.Recover(); err != nil {
		t.Errorf("Recover is not idempotent: %v", err)
	}
}

func TestRecoveryRefusesAJournalWithAnUnknownStatusAndAReceiptWithoutHistory(t *testing.T) {
	h := newHarness(t)
	tx, _ := h.manager.Start([]Change{h.change("one", Managed)})
	tx.journal.Status = "mystery"
	if err := tx.persist(); err != nil {
		t.Fatal(err)
	}
	tx.close()
	if err := h.manager.Recover(); err == nil || !strings.Contains(err.Error(), "unknown status") {
		t.Errorf("unknown status: %v", err)
	}

	// A receipt that claims files with no committed journal behind it.
	h2 := newHarness(t)
	commitChange(t, h2, h2.change("one", Managed))
	entries, _ := os.ReadDir(h2.manager.transactionsDir())
	for _, e := range entries {
		os.RemoveAll(filepath.Join(h2.manager.transactionsDir(), e.Name()))
	}
	if err := h2.manager.Recover(); err == nil || !strings.Contains(err.Error(), "claims files but no committed transaction journal") {
		t.Errorf("receipt without history: %v", err)
	}
}

func TestRecoveryRemovesAnEmptyReceiptWhenNothingWasEverCommitted(t *testing.T) {
	h := newHarness(t)
	tx, _ := h.manager.Start([]Change{h.change("one", Managed)})
	tx.Apply()
	tx.Rollback()
	if err := h.manager.Recover(); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := h.manager.Current(); ok || err != nil {
		t.Errorf("Current = %v %v, want no receipt", ok, err)
	}
}

func TestJournalsAreReadStrictly(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("one", Managed))
	entries, _ := os.ReadDir(h.manager.transactionsDir())
	var journalPath string
	for _, e := range entries {
		if e.IsDir() {
			journalPath = filepath.Join(h.manager.transactionsDir(), e.Name(), "journal.json")
		}
	}
	good, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	// A stray file and a directory without a journal are ignored.
	os.WriteFile(filepath.Join(h.manager.transactionsDir(), "stray"), nil, 0o600)
	os.Mkdir(filepath.Join(h.manager.transactionsDir(), "empty"), 0o700)
	if _, err := h.manager.Generations(); err != nil {
		t.Fatalf("stray entries broke reading: %v", err)
	}

	for name, damage := range map[string]func(){
		"loose mode":    func() { os.Chmod(journalPath, 0o644) },
		"not json":      func() { os.WriteFile(journalPath, []byte("{nope"), 0o600) },
		"trailing json": func() { os.WriteFile(journalPath, append(append([]byte(nil), good...), []byte(`{"x":1}`)...), 0o600) },
		"unknown field": func() { os.WriteFile(journalPath, []byte(`{"apiVersion":"x","bogus":1}`), 0o600) },
		"incomplete":    func() { os.WriteFile(journalPath, []byte(`{}`), 0o600) },
	} {
		os.WriteFile(journalPath, good, 0o600)
		os.Chmod(journalPath, 0o600)
		damage()
		if _, err := h.manager.Generations(); err == nil {
			t.Errorf("%s: a damaged journal was accepted", name)
		}
	}
}
