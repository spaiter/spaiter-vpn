package transaction

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAMisconfiguredManagerRefusesEveryEntryPoint(t *testing.T) {
	for name, mutate := range map[string]func(m *Manager){
		"relative state dir": func(m *Manager) { m.StateDir = "relative/state" },
		"unclean state dir":  func(m *Manager) { m.StateDir += "/../state" },
		"no state dir":       func(m *Manager) { m.StateDir = "" },
		"relative target":    func(m *Manager) { m.AllowedTargets = []string{"managed/config.json"} },
		"duplicate target":   func(m *Manager) { m.AllowedTargets = append(m.AllowedTargets, m.AllowedTargets[0]) },
	} {
		h := newHarness(t)
		mutate(h.manager)
		if _, err := h.manager.Start([]Change{h.change("x", Managed)}); err == nil {
			t.Errorf("%s: Start accepted it", name)
		}
		if _, err := h.manager.Lock(); err == nil {
			t.Errorf("%s: Lock accepted it", name)
		}
		if _, err := h.manager.Generations(); err == nil {
			t.Errorf("%s: Generations accepted it", name)
		}
		if _, err := h.manager.GenerationFile(1, h.target); err == nil {
			t.Errorf("%s: GenerationFile accepted it", name)
		}
		if _, err := h.manager.Prune(2, true); err == nil {
			t.Errorf("%s: Prune accepted it", name)
		}
	}
}

func TestChangesAreValidatedBeforeAnythingIsWritten(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("one", Managed))
	runtime := h.manager
	other := filepath.Join(h.root, "managed", "other.json")

	cases := map[string]struct {
		changes []Change
		want    string
	}{
		"empty":                  {nil, "no changes"},
		"outside":                {[]Change{{Path: other, Data: []byte("x"), Mode: 0o600, Ownership: Managed}}, "outside the transaction allowlist"},
		"duplicate":              {[]Change{h.change("a", Managed), h.change("b", Managed)}, "more than one change"},
		"unknown mode":           {[]Change{{Path: h.target, Data: []byte("x"), Mode: 0o600, UID: h.uid, GID: h.gid, Ownership: "weird"}}, "unknown ownership"},
		"empty perms":            {[]Change{{Path: h.target, Data: []byte("x"), UID: h.uid, GID: h.gid, Ownership: Managed}}, "empty permissions"},
		"replace and adopt":      {[]Change{{Path: h.target, Data: []byte("x"), Mode: 0o600, UID: h.uid, GID: h.gid, Ownership: RuntimeMutable, ReplaceRuntimeMutable: true, AdoptRuntimeMutable: true}}, "both replacement and adoption"},
		"replace a managed file": {[]Change{{Path: h.target, Data: []byte("x"), Mode: 0o600, UID: h.uid, GID: h.gid, Ownership: RuntimeMutable, ReplaceRuntimeMutable: true}}, "not an owned runtime-mutable file"},
		"adopt an owned file":    {[]Change{{Path: h.target, Data: []byte("x"), Mode: 0o600, UID: h.uid, GID: h.gid, Ownership: RuntimeMutable, AdoptRuntimeMutable: true}}, "not an unowned existing file"},
		"stale snapshot":         {[]Change{{Path: h.target, Data: []byte("x"), Mode: 0o600, UID: h.uid, GID: h.gid, Ownership: Managed, ExpectedPriorDigest: "deadbeef"}}, "changed after its migration snapshot"},
	}
	for name, c := range cases {
		if _, err := runtime.Start(c.changes); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}

	// A file the receipt owns whose mode drifted since it was written.
	if err := os.Chmod(h.target, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Start([]Change{h.change("two", Managed)}); err == nil || !strings.Contains(err.Error(), "metadata drifted") {
		t.Errorf("mode drift: %v", err)
	}
}

func TestAReceiptThatClaimsMoreThanTheAllowlistIsRefused(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("one", Managed))
	path := h.manager.currentPath()
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipt Receipt
	if err := json.Unmarshal(good, &receipt); err != nil {
		t.Fatal(err)
	}

	outside := receipt
	outside.Files = map[string]OwnedFile{"/etc/elsewhere": receipt.Files[h.target]}
	weird := receipt
	owned := receipt.Files[h.target]
	owned.Ownership = "weird"
	weird.Files = map[string]OwnedFile{h.target: owned}

	for name, r := range map[string]Receipt{"outside the allowlist": outside, "unknown ownership": weird} {
		data, _ := json.Marshal(r)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := h.manager.Current(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGenerationsWithBrokenMetadataAreRefused(t *testing.T) {
	now := time.Now()
	committed := func(id string, sequence uint64, receipt *Receipt, at *time.Time) *Transaction {
		return &Transaction{journal: journal{ID: id, Sequence: sequence, Status: statusCommitted, CommittedAt: at, Receipt: receipt}}
	}
	good := func(id string, sequence uint64) *Transaction {
		return committed(id, sequence, &Receipt{Sequence: sequence, Transaction: id}, &now)
	}

	if got, err := committedGenerations([]*Transaction{good("b", 2), good("a", 1), {journal: journal{Status: statusRolledBack}}}); err != nil || len(got) != 2 || got[0].Sequence != 1 {
		t.Errorf("valid set = %v, %v", got, err)
	}
	for name, set := range map[string][]*Transaction{
		"no receipt":        {committed("a", 1, nil, &now)},
		"no commit time":    {committed("a", 1, &Receipt{Sequence: 1, Transaction: "a"}, nil)},
		"sequence mismatch": {committed("a", 1, &Receipt{Sequence: 2, Transaction: "a"}, &now)},
		"id mismatch":       {committed("a", 1, &Receipt{Sequence: 1, Transaction: "z"}, &now)},
		"duplicate":         {good("a", 1), good("b", 1)},
	} {
		if _, err := committedGenerations(set); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGenerationFileNamesWhyItCannotReconstruct(t *testing.T) {
	h := newHarness(t)
	commitChange(t, h, h.change("one", Managed))
	commitChange(t, h, h.change("two", Managed))

	if got, err := h.manager.GenerationFile(1, h.target); err != nil || string(got) != "one" {
		t.Fatalf("generation 1 = %q, %v", got, err)
	}
	if _, err := h.manager.GenerationFile(1, filepath.Join(h.root, "managed", "other")); err == nil || !strings.Contains(err.Error(), "outside the transaction allowlist") {
		t.Errorf("outside the allowlist: %v", err)
	}
	if _, err := h.manager.GenerationFile(99, h.target); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("unknown generation: %v", err)
	}

	// The latest generation can only be proven by the live file.
	if err := os.WriteFile(h.target, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.GenerationFile(2, h.target); err == nil || !strings.Contains(err.Error(), "live digest changed") {
		t.Errorf("tampered live file: %v", err)
	}
	// An older one comes from the backup the next commit made, which must be intact.
	backups, _ := filepath.Glob(filepath.Join(h.manager.transactionsDir(), "*", "backups", "*"))
	if len(backups) != 1 {
		t.Fatalf("backups = %v", backups)
	}
	good, _ := os.ReadFile(backups[0])
	if err := os.WriteFile(backups[0], []byte("rotten"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.GenerationFile(1, h.target); err == nil || !strings.Contains(err.Error(), "missing or corrupt") {
		t.Errorf("corrupt backup: %v", err)
	}
	if err := os.WriteFile(backups[0], good, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(backups[0], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.GenerationFile(1, h.target); err == nil {
		t.Error("a loose backup was trusted")
	}
	os.Chmod(backups[0], 0o600)

	os.Remove(h.target)
	if _, err := h.manager.GenerationFile(2, h.target); err == nil || !strings.Contains(err.Error(), "live file is absent") {
		t.Errorf("absent live file: %v", err)
	}
}

func TestPruneDryRunSelectsWithoutRemoving(t *testing.T) {
	h := newHarness(t)
	for _, data := range []string{"one", "two", "three", "four"} {
		commitChange(t, h, h.change(data, Managed))
	}
	dry, err := h.manager.Prune(2, true)
	if err != nil || !dry.DryRun || len(dry.Selected) == 0 || len(dry.Retained) != 2 {
		t.Fatalf("dry run = %+v, %v", dry, err)
	}
	before, _ := os.ReadDir(h.manager.transactionsDir())
	real, err := h.manager.Prune(2, false)
	if err != nil || len(real.Selected) != len(dry.Selected) {
		t.Fatalf("real prune = %+v, %v", real, err)
	}
	after, _ := os.ReadDir(h.manager.transactionsDir())
	if len(after) >= len(before) {
		t.Errorf("nothing was removed: %d → %d", len(before), len(after))
	}
	if _, err := h.manager.Prune(1, false); err == nil {
		t.Error("a retention below the minimum was accepted")
	}
}
