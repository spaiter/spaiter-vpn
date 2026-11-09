package transaction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

func (m *Manager) Recover() error {
	if err := m.prepare(); err != nil {
		return err
	}
	lock, err := m.acquire()
	if err != nil {
		return err
	}
	recoverErr := m.recoverLocked()
	closeErr := releaseLock(lock)
	if recoverErr != nil {
		return recoverErr
	}
	return closeErr
}

func (m *Manager) recoverLocked() error {
	journals, err := m.loadJournals()
	if err != nil {
		return err
	}
	// A later transaction can only exist after an earlier one committed or
	// rolled back, but descending order is the safe direction if an operator
	// copied transaction directories in by hand.
	sort.Slice(journals, func(i, j int) bool { return journals[i].journal.Sequence > journals[j].journal.Sequence })
	for _, tx := range journals {
		switch tx.journal.Status {
		case statusCommitted, statusRolledBack:
			continue
		case statusPreparing, statusPrepared, statusApplying, statusApplied, statusRollingBack, statusRollbackIncomplete:
			if err := tx.rollbackLocked(); err != nil {
				return fmt.Errorf("recover transaction %s: %w", tx.journal.ID, err)
			}
		default:
			return fmt.Errorf("transaction %s has unknown status %q", tx.journal.ID, tx.journal.Status)
		}
	}

	// Collect what an interrupted transaction may have opened. The journals
	// are marked only AFTER the ownership receipt is durable: marking first
	// leaves a crash window in which the next recovery skips an adoption that
	// never reached current.json.
	adopted, pending := pendingFirewallAdoption(journals)
	recreatePending := pendingRecreateAdoption(journals)

	var latest *Receipt
	for _, tx := range journals {
		if tx.journal.Status != statusCommitted {
			continue
		}
		if tx.journal.Receipt == nil {
			return fmt.Errorf("committed transaction %s has no receipt", tx.journal.ID)
		}
		if latest == nil || tx.journal.Receipt.Sequence > latest.Sequence {
			copy := *tx.journal.Receipt
			latest = &copy
		}
	}
	live, err := m.loadCurrent()
	if err != nil {
		return err
	}
	if latest == nil {
		if len(live.Files) > 0 {
			return fmt.Errorf("current receipt claims files but no committed transaction journal exists")
		}
		owned := mergeRules(live.Firewall, adopted)
		if len(owned) == 0 && !live.RecreatePending && len(recreatePending) == 0 {
			if err := durableRemove(m.currentPath()); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		}
		// No committed generation, but a killed first install left rules open.
		// A receipt that owns only those is still worth writing: without it the
		// next apply cannot tell them from rules the operator opened, and they
		// stay open for good.
		if err := m.writeReceipt(Receipt{
			APIVersion:      ReceiptAPIVersion,
			Files:           map[string]OwnedFile{},
			Firewall:        owned,
			RecreatePending: live.RecreatePending || len(recreatePending) > 0,
		}); err != nil {
			return err
		}
		if err := markFirewallAdopted(pending); err != nil {
			return err
		}
		return markRecreateAdopted(recreatePending)
	}
	// The live receipt's ownership is merged in, not just the committed
	// journal's snapshot of it.
	//
	// Recovery rebuilds current.json from the last committed journal, which
	// discards anything written to it since — and an adoption from an earlier
	// recovery is exactly that. Without this merge the first pass adopts the
	// leaked rules and the second throws them away again, which is worse than
	// not adopting at all: it looks fixed and is not. A generation that
	// deliberately retired a rule is unaffected, because its own commit wrote
	// the reduced set to both places.
	latest.Firewall = mergeRules(latest.Firewall, mergeRules(live.Firewall, adopted))
	latest.RecreatePending = latest.RecreatePending || live.RecreatePending || len(recreatePending) > 0
	if err := m.writeReceipt(*latest); err != nil {
		return err
	}
	if err := markFirewallAdopted(pending); err != nil {
		return err
	}
	return markRecreateAdopted(recreatePending)
}

func pendingRecreateAdoption(journals []*Transaction) []*Transaction {
	var pending []*Transaction
	for _, tx := range journals {
		intent := tx.journal.Recreate
		if intent == nil || intent.Adopted || tx.journal.Status == statusCommitted {
			continue
		}
		pending = append(pending, tx)
	}
	return pending
}

func markRecreateAdopted(pending []*Transaction) error {
	for _, tx := range pending {
		tx.journal.Recreate.Adopted = true
		if err := tx.persist(); err != nil {
			return fmt.Errorf("record recreate adoption for %s: %w", tx.journal.ID, err)
		}
	}
	return nil
}

// pendingFirewallAdoption returns the rules and journals not yet folded into a
// durable receipt. It deliberately does not mutate those journals.
//
// Only the Add side. A Retire that may or may not have happened needs nothing:
// the rule is still claimed by the receipt, so the next apply either re-opens
// it because it is wanted and blocked, or retires it again — and closing a rule
// that is already closed is a no-op.
func pendingFirewallAdoption(journals []*Transaction) ([]string, []*Transaction) {
	var adopted []string
	var pending []*Transaction
	for _, tx := range journals {
		intent := tx.journal.Firewall
		if intent == nil || intent.Adopted || len(intent.Add) == 0 {
			continue
		}
		if tx.journal.Status == statusCommitted {
			// A committed transaction already recorded its ownership in the
			// receipt; adopting again would say nothing new.
			continue
		}
		adopted = mergeRules(adopted, intent.Add)
		pending = append(pending, tx)
	}
	return adopted, pending
}

// markFirewallAdopted runs only after current.json owns every pending rule.
// If marking is interrupted, the next recovery unions the same rules into the
// already-written receipt and safely tries the marker again.
func markFirewallAdopted(pending []*Transaction) error {
	for _, tx := range pending {
		tx.journal.Firewall.Adopted = true
		if err := tx.persist(); err != nil {
			return fmt.Errorf("record firewall adoption for %s: %w", tx.journal.ID, err)
		}
	}
	return nil
}

// mergeRules returns the sorted union of two rule lists.
func mergeRules(left, right []string) []string {
	if len(right) == 0 {
		return left
	}
	seen := map[string]bool{}
	for _, rule := range left {
		seen[rule] = true
	}
	for _, rule := range right {
		seen[rule] = true
	}
	out := make([]string, 0, len(seen))
	for rule := range seen {
		out = append(out, rule)
	}
	sort.Strings(out)
	return out
}

func (m *Manager) loadJournals() ([]*Transaction, error) {
	entries, err := os.ReadDir(m.transactionsDir())
	if err != nil {
		return nil, fmt.Errorf("read transaction directory: %w", err)
	}
	var result []*Transaction
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(m.transactionsDir(), entry.Name())
		path := filepath.Join(dir, "journal.json")
		snapshot, err := readRegular(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if snapshot == nil {
			continue
		}
		if snapshot.mode.Perm() != 0o600 || snapshot.uid != m.UID || snapshot.gid != m.GID {
			return nil, fmt.Errorf("journal %s metadata is unsafe", path)
		}
		var value journal
		decoder := json.NewDecoder(bytes.NewReader(snapshot.data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return nil, fmt.Errorf("%s contains trailing JSON", path)
		}
		if value.APIVersion != JournalAPIVersion || value.ID == "" || value.Sequence == 0 {
			return nil, fmt.Errorf("%s has an unsupported or incomplete journal", path)
		}
		result = append(result, &Transaction{manager: m, dir: dir, journal: value})
	}
	return result, nil
}

func (m *Manager) writeReceipt(receipt Receipt) error {
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal current receipt: %w", err)
	}
	data = append(data, '\n')
	return atomicWrite(m.currentPath(), data, 0o600, m.UID, m.GID)
}
