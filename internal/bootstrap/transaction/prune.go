package transaction

import (
	"errors"
	"fmt"
	"os"
	"sort"
)

const MinimumRetainedGenerations = 2

type PruneTransaction struct {
	Sequence    uint64
	Transaction string
	Status      string
}

type PruneResult struct {
	Retained []Generation
	Selected []PruneTransaction
	DryRun   bool
}

// Prune removes transactions older than the retained committed generations.
// Every retained generation keeps its own journal and every later backup needed
// to reconstruct it. The minimum retains both current and previous generations.
func (m *Manager) Prune(keep int, dryRun bool) (result PruneResult, err error) {
	if keep < MinimumRetainedGenerations {
		return PruneResult{}, fmt.Errorf("retention must keep at least %d committed generations", MinimumRetainedGenerations)
	}
	guard, err := m.Lock()
	if err != nil {
		return PruneResult{}, err
	}
	defer func() { err = errors.Join(err, guard.Release()) }()

	journals, err := m.loadJournals()
	if err != nil {
		return PruneResult{}, err
	}
	generations, err := committedGenerations(journals)
	if err != nil {
		return PruneResult{}, err
	}
	firstRetained := 0
	if len(generations) > keep {
		firstRetained = len(generations) - keep
	}
	result.Retained = append([]Generation(nil), generations[firstRetained:]...)
	result.DryRun = dryRun

	var cutoff uint64
	if len(result.Retained) > 0 {
		cutoff = result.Retained[0].Sequence
	}
	var selected []*Transaction
	for _, tx := range journals {
		if cutoff == 0 || tx.journal.Sequence >= cutoff {
			continue
		}
		selected = append(selected, tx)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].journal.Sequence < selected[j].journal.Sequence })
	for _, tx := range selected {
		result.Selected = append(result.Selected, PruneTransaction{
			Sequence: tx.journal.Sequence, Transaction: tx.journal.ID, Status: string(tx.journal.Status),
		})
	}
	if dryRun {
		return result, nil
	}
	for _, tx := range selected {
		if err := os.RemoveAll(tx.dir); err != nil {
			return result, fmt.Errorf("prune transaction %d-%s: %w", tx.journal.Sequence, tx.journal.ID, err)
		}
	}
	if len(selected) > 0 {
		if err := syncDir(m.transactionsDir()); err != nil {
			return result, err
		}
	}
	return result, nil
}
