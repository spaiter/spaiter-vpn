package transaction

import (
	"fmt"
	"path/filepath"
	"sort"
)

// Generations returns successfully committed generations in sequence order.
// The caller must run Recover first when it needs a mutation-safe view.
func (m *Manager) Generations() ([]Generation, error) {
	if err := m.prepare(); err != nil {
		return nil, err
	}
	journals, err := m.loadJournals()
	if err != nil {
		return nil, err
	}
	return committedGenerations(journals)
}

func committedGenerations(journals []*Transaction) ([]Generation, error) {
	var generations []Generation
	seen := map[uint64]bool{}
	for _, tx := range journals {
		j := tx.journal
		if j.Status != statusCommitted {
			continue
		}
		if j.CommittedAt == nil || j.Receipt == nil || j.Receipt.Sequence != j.Sequence || j.Receipt.Transaction != j.ID {
			return nil, fmt.Errorf("committed transaction %d-%s has incomplete generation metadata", j.Sequence, j.ID)
		}
		if seen[j.Sequence] {
			return nil, fmt.Errorf("more than one committed transaction has sequence %d", j.Sequence)
		}
		seen[j.Sequence] = true
		generations = append(generations, Generation{
			Sequence: j.Sequence, Transaction: j.ID, CommittedAt: j.CommittedAt.UTC(), Receipt: *j.Receipt,
		})
	}
	sort.Slice(generations, func(i, j int) bool { return generations[i].Sequence < generations[j].Sequence })
	return generations, nil
}

// GenerationFile reconstructs a managed file exactly as it existed in a
// committed generation. Backups are content-addressed by the receipt digest;
// a journal path alone is never treated as proof.
func (m *Manager) GenerationFile(sequence uint64, path string) ([]byte, error) {
	if err := m.prepare(); err != nil {
		return nil, err
	}
	allowed := false
	for _, target := range m.AllowedTargets {
		if target == path {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("target %s is outside the transaction allowlist", path)
	}

	journals, err := m.loadJournals()
	if err != nil {
		return nil, err
	}
	var target *journal
	for _, tx := range journals {
		j := &tx.journal
		if j.Status == statusCommitted && j.Sequence == sequence {
			if target != nil {
				return nil, fmt.Errorf("more than one committed transaction has sequence %d", sequence)
			}
			target = j
		}
	}
	if target == nil || target.Receipt == nil {
		return nil, fmt.Errorf("committed generation %d does not exist", sequence)
	}
	owned, ok := target.Receipt.Files[path]
	if !ok {
		return nil, fmt.Errorf("generation %d did not own %s", sequence, path)
	}
	if owned.Ownership != Managed {
		return nil, fmt.Errorf("generation %d owned %s as %s, not managed", sequence, path, owned.Ownership)
	}

	current, err := readRegular(path)
	if err != nil {
		return nil, err
	}
	if current != nil && current.digest == owned.Digest {
		return append([]byte(nil), current.data...), nil
	}

	sort.Slice(journals, func(i, j int) bool { return journals[i].journal.Sequence < journals[j].journal.Sequence })
	for _, tx := range journals {
		j := tx.journal
		if j.Status != statusCommitted || j.Sequence <= sequence {
			continue
		}
		for _, op := range j.Operations {
			if op.Path != path || !op.Prior.Exists || op.Prior.Digest != owned.Digest || op.BackupName == "" {
				continue
			}
			backupPath := filepath.Join(tx.dir, "backups", op.BackupName)
			backup, err := readRegular(backupPath)
			if err != nil {
				return nil, err
			}
			if backup == nil || backup.digest != owned.Digest {
				return nil, fmt.Errorf("backup for %s in generation %d is missing or corrupt", path, j.Sequence)
			}
			if backup.mode.Perm() != 0o600 || backup.uid != m.UID || backup.gid != m.GID {
				return nil, fmt.Errorf("backup for %s in generation %d has unsafe metadata", path, j.Sequence)
			}
			return append([]byte(nil), backup.data...), nil
		}
	}
	if current == nil {
		return nil, fmt.Errorf("cannot reconstruct %s from generation %d: live file is absent and no later committed backup matches", path, sequence)
	}
	return nil, fmt.Errorf("cannot reconstruct %s from generation %d: live digest changed and no later committed backup matches", path, sequence)
}
