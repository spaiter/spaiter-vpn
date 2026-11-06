package transaction

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type harness struct {
	root    string
	target  string
	manager *Manager
	uid     uint32
	gid     uint32
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid, err := owner(info)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "managed", "config.json")
	sequence := 0
	manager := &Manager{
		StateDir:       filepath.Join(root, "state"),
		AllowedTargets: []string{target},
		UID:            uid,
		GID:            gid,
		Now:            func() time.Time { return time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC) },
		NewID: func() (string, error) {
			sequence++
			return fmt.Sprintf("tx-%d", sequence), nil
		},
	}
	return &harness{root: root, target: target, manager: manager, uid: uid, gid: gid}
}

func (h *harness) change(data string, ownership Ownership) Change {
	return Change{Path: h.target, Data: []byte(data), Mode: 0o600, UID: h.uid, GID: h.gid, Ownership: ownership}
}

func commitChange(t *testing.T, h *harness, change Change) {
	t.Helper()
	tx, err := h.manager.Start([]Change{change})
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

func TestFreshCommitWritesReceiptWithoutSecretContent(t *testing.T) {
	h := newHarness(t)
	secret := "super-secret-file-content"
	commitChange(t, h, h.change(secret, Managed))

	data, err := os.ReadFile(h.target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != secret {
		t.Fatalf("target = %q", data)
	}
	info, err := os.Stat(h.target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("target mode = %04o", info.Mode().Perm())
	}
	receipt, err := h.manager.loadCurrent()
	if err != nil {
		t.Fatal(err)
	}
	owned, ok := receipt.Files[h.target]
	if !ok || owned.Digest != digest([]byte(secret)) || owned.Ownership != Managed {
		t.Fatalf("receipt does not own the committed file: %#v", receipt)
	}

	err = filepath.WalkDir(h.manager.StateDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		journalData, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(journalData, []byte(secret)) {
			return fmt.Errorf("secret content leaked into transaction metadata %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenerationsReconstructManagedFilesFromCommittedBackups(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("one", Managed))
	commitChange(t, h, h.change("two", Managed))
	commitChange(t, h, h.change("three", Managed))

	generations, err := h.manager.Generations()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(generations); got != 3 {
		t.Fatalf("generation count = %d, want 3", got)
	}
	for index, want := range []string{"one", "two", "three"} {
		data, err := h.manager.GenerationFile(generations[index].Sequence, h.target)
		if err != nil {
			t.Fatalf("generation %d: %v", generations[index].Sequence, err)
		}
		if string(data) != want {
			t.Fatalf("generation %d file = %q, want %q", generations[index].Sequence, data, want)
		}
	}
}

func TestGenerationFileRejectsCorruptBackup(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("one", Managed))
	commitChange(t, h, h.change("two", Managed))

	backups, err := filepath.Glob(filepath.Join(h.manager.StateDir, "transactions", "00000000000000000002-*", "backups", "*.backup"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups = %v, err = %v", backups, err)
	}
	if err := os.WriteFile(backups[0], []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.GenerationFile(1, h.target); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("err = %v, want corrupt-backup refusal", err)
	}
}

func TestForeignFileIsNeverOverwritten(t *testing.T) {
	h := newHarness(t)
	if err := os.MkdirAll(filepath.Dir(h.target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.target, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.Start([]Change{h.change("replacement", Managed)}); err == nil || !strings.Contains(err.Error(), "foreign file") {
		t.Fatalf("foreign file was not refused: %v", err)
	}
	data, err := os.ReadFile(h.target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "foreign" {
		t.Fatalf("foreign file changed to %q", data)
	}
}

func TestRollbackRestoresContentAndReceipt(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("version-one", Managed))
	before, err := h.manager.loadCurrent()
	if err != nil {
		t.Fatal(err)
	}

	tx, err := h.manager.Start([]Change{h.change("version-two", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(h.target); string(data) != "version-two" {
		t.Fatalf("apply did not write version two: %q", data)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(h.target); string(data) != "version-one" {
		t.Fatalf("rollback did not restore version one: %q", data)
	}
	after, err := h.manager.loadCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if before.Sequence != after.Sequence || before.Files[h.target] != after.Files[h.target] {
		t.Fatalf("rollback changed the committed receipt:\nbefore=%#v\nafter=%#v", before, after)
	}
}

func TestRecoveryRollsBackAppliedTransactionAndRepairsReceipt(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("stable", Managed))
	tx, err := h.manager.Start([]Change{h.change("crashed", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.close(); err != nil { // simulate process death: release the OS lock without rollback
		t.Fatal(err)
	}
	if err := os.Remove(h.manager.currentPath()); err != nil {
		t.Fatal(err)
	}

	if err := h.manager.Recover(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(h.target); string(data) != "stable" {
		t.Fatalf("recovery did not restore stable content: %q", data)
	}
	receipt, err := h.manager.loadCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Sequence != 1 || receipt.Files[h.target].Digest != digest([]byte("stable")) {
		t.Fatalf("recovery did not repair the last committed receipt: %#v", receipt)
	}
}

func TestRecoveryHandlesCrashBetweenMutationAndJournalCompletion(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("stable", Managed))
	tx, err := h.manager.Start([]Change{h.change("half-applied", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	tx.journal.Status = statusApplying
	tx.journal.Operations[0].State = opApplying
	if err := tx.persist(); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(h.target, []byte("half-applied"), 0o600, h.uid, h.gid); err != nil {
		t.Fatal(err)
	}
	if err := tx.close(); err != nil {
		t.Fatal(err)
	}

	if err := h.manager.Recover(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(h.target); string(data) != "stable" {
		t.Fatalf("recovery did not handle opApplying state: %q", data)
	}
}

func TestExclusiveLockAndSymlinkBoundary(t *testing.T) {
	h := newHarness(t)
	tx, err := h.manager.Start([]Change{h.change("one", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.Start([]Change{h.change("two", Managed)}); !errors.Is(err, ErrLocked) {
		t.Fatalf("second transaction lock error = %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	realParent := filepath.Join(h.root, "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkParent := filepath.Join(h.root, "link-parent")
	if err := os.Symlink(realParent, symlinkParent); err != nil {
		t.Fatal(err)
	}
	symlinkTarget := filepath.Join(symlinkParent, "config.json")
	h.manager.AllowedTargets = []string{symlinkTarget}
	if _, err := h.manager.Start([]Change{{Path: symlinkTarget, Data: []byte("x"), Mode: 0o600, UID: h.uid, GID: h.gid, Ownership: Managed}}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink parent was not refused: %v", err)
	}
}

func TestRuntimeMutableContentMayDriftButCannotBeReplaced(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("runtime-one", RuntimeMutable))
	if err := os.WriteFile(h.target, []byte("runtime-two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.Start([]Change{h.change("generated", RuntimeMutable)}); err == nil || !strings.Contains(err.Error(), "runtime-mutable") {
		t.Fatalf("runtime-mutable replacement was not refused: %v", err)
	}
}

func TestRuntimeMutableCanBeExplicitlyReplacedByAMigration(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("runtime-one", RuntimeMutable))
	if err := os.WriteFile(h.target, []byte("runtime-two"), 0o600); err != nil {
		t.Fatal(err)
	}
	change := h.change("migrated", RuntimeMutable)
	change.ReplaceRuntimeMutable = true
	tx, err := h.manager.Start([]Change{change})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(h.target)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(restored); got != "runtime-two" {
		t.Fatalf("rollback restored %q, want the live pre-migration contents", got)
	}
}

func TestRuntimeMutableCanBeAdoptedByAMigration(t *testing.T) {
	h := newHarness(t)
	if err := os.MkdirAll(filepath.Dir(h.target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.target, []byte("bot-owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	change := h.change("migrated", RuntimeMutable)
	change.AdoptRuntimeMutable = true
	tx, err := h.manager.Start([]Change{change})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	receipt, _, err := h.manager.Current()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Files[h.target].Ownership != RuntimeMutable {
		t.Fatal("adopted file was not recorded runtime-mutable")
	}
	if err := os.WriteFile(h.target, []byte("bot-mutated"), 0o600); err != nil {
		t.Fatal(err)
	}
	replacement := h.change("migrated-again", RuntimeMutable)
	replacement.ReplaceRuntimeMutable = true
	if _, err := h.manager.Start([]Change{replacement}); err != nil {
		t.Fatalf("adopted file cannot be migrated again: %v", err)
	}
}

func TestRuntimeMutableSnapshotRefusesALostUpdateBeforeTransactionStart(t *testing.T) {
	h := newHarness(t)
	if err := os.MkdirAll(filepath.Dir(h.target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.target, []byte("snapshot-read"), 0o600); err != nil {
		t.Fatal(err)
	}
	change := h.change("migration-result", RuntimeMutable)
	change.AdoptRuntimeMutable = true
	change.ExpectedPriorDigest = digest([]byte("snapshot-read"))
	if err := os.WriteFile(h.target, []byte("relay-updated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.Start([]Change{change}); err == nil || !strings.Contains(err.Error(), "migration snapshot") {
		t.Fatalf("a concurrent runtime update would have been overwritten: %v", err)
	}
	if got, err := os.ReadFile(h.target); err != nil || string(got) != "relay-updated" {
		t.Fatalf("refused migration disturbed the concurrent update: %q, %v", got, err)
	}
}

func TestDeleteRemovesOnlyOwnedFileAndReceiptEntry(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("owned", Managed))
	tx, err := h.manager.Start([]Change{{Path: h.target, Delete: true, Ownership: Managed}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.target); !os.IsNotExist(err) {
		t.Fatalf("deleted target still exists: %v", err)
	}
	receipt, err := h.manager.loadCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := receipt.Files[h.target]; exists {
		t.Fatalf("deleted target remains in receipt: %#v", receipt)
	}
}

func TestManagedDriftAndEmptyTransactionsAreRefused(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("owned", Managed))
	if err := os.WriteFile(h.target, []byte("edited-outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.Start([]Change{h.change("new", Managed)}); err == nil || !strings.Contains(err.Error(), "content drifted") {
		t.Fatalf("managed content drift was not refused: %v", err)
	}

	clean := newHarness(t)
	if _, err := clean.manager.Start(nil); err == nil || !strings.Contains(err.Error(), "no changes") {
		t.Fatalf("empty transaction was accepted: %v", err)
	}
}

func TestTransactionStateDirectoryMustStayPrivate(t *testing.T) {
	h := newHarness(t)
	if err := os.Mkdir(h.manager.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.Start([]Change{h.change("secret", Managed)}); err == nil || !strings.Contains(err.Error(), "exposes transaction data") {
		t.Fatalf("public transaction directory was accepted: %v", err)
	}
}

// TestGuardHoldsTheLockAcrossTransactions. Apply has to hold the lock from
// discovery through the receipt, so committing a transaction inside a guard
// must not release it — otherwise a second apply could start containers for the
// same deployment while the first is still starting its own.
func TestGuardHoldsTheLockAcrossTransactions(t *testing.T) {
	manager, target := newGuardManager(t)

	guard, err := manager.Lock()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := manager.Lock(); err != ErrLocked {
		t.Fatalf("second Lock = %v, want ErrLocked", err)
	}
	if _, err := manager.Start([]Change{change(target, "first", t)}); err != ErrLocked {
		t.Fatalf("Start under a held guard = %v, want ErrLocked", err)
	}

	tx, err := guard.Start([]Change{change(target, "first", t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Still locked after a commit.
	if _, err := manager.Lock(); err != ErrLocked {
		t.Fatalf("Lock after an in-guard commit = %v, want ErrLocked", err)
	}

	if err := guard.Release(); err != nil {
		t.Fatal(err)
	}
	if err := guard.Release(); err != nil {
		t.Fatalf("a second Release must be a no-op so callers can defer it: %v", err)
	}
	released, err := manager.Lock()
	if err != nil {
		t.Fatalf("Lock after Release = %v, want success", err)
	}
	if err := released.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := released.Start(nil); err == nil {
		t.Fatal("a released guard still started a transaction")
	}
}

func newGuardManager(t *testing.T) (*Manager, string) {
	t.Helper()
	root := t.TempDir()
	target := filepath.Join(root, "managed", "file.txt")
	return &Manager{
		StateDir:       filepath.Join(root, "state"),
		AllowedTargets: []string{target},
		UID:            uint32(os.Getuid()),
		GID:            uint32(os.Getgid()),
	}, target
}

func change(path, content string, t *testing.T) Change {
	t.Helper()
	return Change{
		Path: path, Data: []byte(content), Mode: 0o600,
		UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), Ownership: Managed,
	}
}

// TestRecoveryAdoptsFirewallRulesAnInterruptedApplyOpened. The leak this
// closes: ownership was recorded only in the receipt, written at commit, so a
// process that died between opening a port and committing left that port open
// and owned by nobody — and since an already-allowed rule is indistinguishable
// from one the operator opened, no later apply could adopt or retire it. It
// stayed open for the life of the host.
func TestRecoveryAdoptsFirewallRulesAnInterruptedApplyOpened(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("installed", Managed))

	tx, err := h.manager.Start([]Change{h.change("mid-apply", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	// The order a real apply uses: say what you are about to do, then do it.
	if err := tx.PlanFirewall([]string{"10863/udp", "10861/tcp"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	// Killed here: the rules are open on the host, no receipt names them.
	if err := tx.close(); err != nil {
		t.Fatal(err)
	}

	if err := h.manager.Recover(); err != nil {
		t.Fatal(err)
	}
	receipt, err := h.manager.loadCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(receipt.Firewall, []string{"10861/tcp", "10863/udp"}) {
		t.Fatalf("recovery did not adopt the leaked rules: %v", receipt.Firewall)
	}
	// The committed generation's files must still be the ones restored; adopting
	// firewall ownership is not licence to keep a rolled-back file.
	if data, _ := os.ReadFile(h.target); string(data) != "installed" {
		t.Fatalf("recovery lost the committed content: %q", data)
	}

	// Idempotent: a second recovery must not report the same rules as
	// outstanding work again, or every pass would re-adopt them.
	if err := h.manager.Recover(); err != nil {
		t.Fatal(err)
	}
	again, err := h.manager.loadCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(again.Firewall, receipt.Firewall) {
		t.Fatalf("a second recovery changed the adopted set: %v -> %v", receipt.Firewall, again.Firewall)
	}
}

// TestRecoveryAdoptsRulesEvenWithNoCommittedGeneration. A killed FIRST install
// has no receipt to merge into, and writing none would leave its open ports
// indistinguishable from the operator's forever.
func TestRecoveryAdoptsRulesEvenWithNoCommittedGeneration(t *testing.T) {
	h := newHarness(t)
	tx, err := h.manager.Start([]Change{h.change("first", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.PlanFirewall([]string{"10878/tcp"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.close(); err != nil {
		t.Fatal(err)
	}

	if err := h.manager.Recover(); err != nil {
		t.Fatal(err)
	}
	receipt, err := h.manager.loadCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(receipt.Firewall, []string{"10878/tcp"}) {
		t.Fatalf("firewall = %v, want the leaked rule", receipt.Firewall)
	}
	// It owns no files: the transaction that opened the port never committed.
	if len(receipt.Files) != 0 {
		t.Fatalf("the adoption receipt claims files it never committed: %v", receipt.Files)
	}
	if _, err := os.Stat(h.target); !os.IsNotExist(err) {
		t.Errorf("the interrupted first install left its file behind: %v", err)
	}

	// With no committed journal, recovery used to delete this ownership-only
	// receipt on its second pass. It must remain until a successful first
	// installation absorbs it into a normal generation receipt.
	if err := h.manager.Recover(); err != nil {
		t.Fatal(err)
	}
	again, err := h.manager.loadCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(again.Firewall, receipt.Firewall) {
		t.Fatalf("a second recovery lost first-install firewall ownership: %v -> %v", receipt.Firewall, again.Firewall)
	}
}

// TestRecoveryCanRepeatAfterReceiptWriteBeforeJournalMark simulates the crash
// boundary between the two durable writes. Replaying the pending adoption must
// be idempotent and finish the marker without losing ownership.
func TestRecoveryCanRepeatAfterReceiptWriteBeforeJournalMark(t *testing.T) {
	h := newHarness(t)
	tx, err := h.manager.Start([]Change{h.change("first", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.PlanFirewall([]string{"10863/udp"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.close(); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.Recover(); err != nil {
		t.Fatal(err)
	}

	journals, err := h.manager.loadJournals()
	if err != nil {
		t.Fatal(err)
	}
	if len(journals) != 1 || journals[0].journal.Firewall == nil {
		t.Fatalf("missing firewall intent: %#v", journals)
	}
	// Model a crash after current.json was written but before Adopted made it
	// to this journal.
	journals[0].journal.Firewall.Adopted = false
	if err := journals[0].persist(); err != nil {
		t.Fatal(err)
	}

	if err := h.manager.Recover(); err != nil {
		t.Fatal(err)
	}
	receipt, err := h.manager.loadCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(receipt.Firewall, []string{"10863/udp"}) {
		t.Fatalf("replayed adoption changed ownership: %v", receipt.Firewall)
	}
	journals, err = h.manager.loadJournals()
	if err != nil {
		t.Fatal(err)
	}
	if !journals[0].journal.Firewall.Adopted {
		t.Fatal("replayed recovery did not finish the adoption marker")
	}
}

// TestCommittedFirewallIntentIsNotReAdopted. A committed transaction already
// recorded its ownership; adopting the same rules again would say nothing new
// and would resurrect them if a later generation had retired them.
func TestCommittedFirewallIntentIsNotReAdopted(t *testing.T) {
	h := newHarness(t)
	tx, err := h.manager.Start([]Change{h.change("one", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.PlanFirewall([]string{"10863/udp"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	// Committed having decided it owns nothing — which is what a later
	// generation that retired the rule looks like.
	tx.SetFirewall(nil)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	if err := h.manager.Recover(); err != nil {
		t.Fatal(err)
	}
	receipt, err := h.manager.loadCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if len(receipt.Firewall) != 0 {
		t.Fatalf("recovery resurrected ownership the committed generation had dropped: %v", receipt.Firewall)
	}
}

func TestRecoveryCarriesInterruptedRecreateIntoReceipt(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("installed", Managed))

	tx, err := h.manager.Start([]Change{h.change("restart-shape", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.PlanRecreate(); err != nil {
		t.Fatal(err)
	}
	// Killed after Compose may have acted but before the generation committed.
	if err := tx.close(); err != nil {
		t.Fatal(err)
	}

	if err := h.manager.Recover(); err != nil {
		t.Fatal(err)
	}
	receipt, err := h.manager.loadCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.RecreatePending {
		t.Fatal("recovery lost the interrupted container recreation")
	}
	if data, _ := os.ReadFile(h.target); string(data) != "installed" {
		t.Fatalf("file recovery did not restore the committed generation: %q", data)
	}
	if err := h.manager.Recover(); err != nil {
		t.Fatal(err)
	}
	again, err := h.manager.loadCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if !again.RecreatePending {
		t.Fatal("a second recovery discarded the pending recreation")
	}

	// A later approved apply performs the owed recreate and commits it. The old
	// rolled-back journal must not resurrect the marker afterwards.
	next, err := h.manager.Start([]Change{h.change("installed-after-recreate", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	if err := next.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := next.PlanRecreate(); err != nil {
		t.Fatal(err)
	}
	if err := next.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.Recover(); err != nil {
		t.Fatal(err)
	}
	resolved, err := h.manager.loadCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if resolved.RecreatePending {
		t.Fatal("completed recreation was resurrected by an old journal")
	}
}

func TestCompensatedRecreateDoesNotLeaveRecoveryMarker(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("installed", Managed))
	tx, err := h.manager.Start([]Change{h.change("restart-shape", Managed)})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.PlanRecreate(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	// Models compensation successfully recreating the restored project.
	if err := tx.ResolveRecreate(); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.Recover(); err != nil {
		t.Fatal(err)
	}
	receipt, err := h.manager.loadCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.RecreatePending {
		t.Fatal("successful compensation still requested another recreation")
	}
}
