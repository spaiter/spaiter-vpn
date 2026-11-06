package transaction

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// PlanFirewall writes down the rules this transaction is about to open and
// close, before it touches any of them.
//
// Called before the mutations, not after, for the same reason the file journal
// is flushed before each write: a process that dies in between must leave
// enough behind to work out what happened. add must contain only rules that
// were observed blocked, since that is what lets recovery conclude we were the
// ones who opened them.
func (tx *Transaction) PlanFirewall(add, retire []string) error {
	if tx.closed {
		return fmt.Errorf("transaction is closed")
	}
	if len(add) == 0 && len(retire) == 0 {
		return nil
	}
	intent := &firewallIntent{
		Add:    append([]string(nil), add...),
		Retire: append([]string(nil), retire...),
	}
	sort.Strings(intent.Add)
	sort.Strings(intent.Retire)
	tx.journal.Firewall = intent
	return tx.persist()
}

// PlanRecreate is flushed before Compose is asked to replace containers. If
// the process dies afterwards, file recovery alone is insufficient: the old
// files are back, but the replacement core may still hold the new top-level
// configuration in memory. Recovery carries this intent into current.json so
// the next approved apply force-recreates from the restored generation.
func (tx *Transaction) PlanRecreate() error {
	if tx.closed {
		return fmt.Errorf("transaction is closed")
	}
	tx.journal.Recreate = &recreateIntent{}
	return tx.persist()
}

// ResolveRecreate records that compensation successfully force-recreated the
// restored generation. It is intentionally valid after Rollback closed the
// file transaction: the caller can only know the recreate succeeded after the
// files have been restored.
func (tx *Transaction) ResolveRecreate() error {
	if tx.journal.Recreate == nil || tx.journal.Recreate.Adopted {
		return nil
	}
	tx.journal.Recreate.Adopted = true
	return tx.persist()
}

// SetFirewall records which host-firewall rules the deployment owns once this
// transaction commits. Not calling it keeps whatever the last receipt said.
func (tx *Transaction) SetFirewall(rules []string) {
	sorted := append([]string(nil), rules...)
	sort.Strings(sorted)
	tx.firewall = &sorted
}

// ID identifies this transaction, matching its directory under the state root
// so a failure report can point an operator at the journal and backups.
func (tx *Transaction) ID() string { return tx.journal.ID }

func (tx *Transaction) Apply() error {
	if tx.closed {
		return fmt.Errorf("transaction is closed")
	}
	if tx.journal.Status != statusPrepared {
		return fmt.Errorf("transaction status is %q, want %q", tx.journal.Status, statusPrepared)
	}
	tx.journal.Status = statusApplying
	if err := tx.persist(); err != nil {
		return err
	}
	for index := range tx.journal.Operations {
		op := &tx.journal.Operations[index]
		if err := verifyPrior(*op); err != nil {
			return err
		}
		op.State = opApplying
		if err := tx.persist(); err != nil {
			return err
		}
		var err error
		if op.Delete {
			err = durableRemove(op.Path)
		} else {
			if err := ensureDirOwned(filepath.Dir(op.Path), 0o700, tx.manager.UID, tx.manager.GID, tx.manager.dirOwnerAllowed); err != nil {
				return fmt.Errorf("prepare parent for %s: %w", op.Path, err)
			}
			err = atomicWrite(op.Path, op.newData, os.FileMode(op.NewMode), op.NewUID, op.NewGID)
		}
		if err != nil {
			return fmt.Errorf("apply file operation %s: %w", op.Path, err)
		}
		op.State = opApplied
		if err := tx.persist(); err != nil {
			return err
		}
	}
	tx.journal.Status = statusApplied
	return tx.persist()
}

func verifyPrior(op operation) error {
	current, err := readRegular(op.Path)
	if err != nil {
		return err
	}
	if !op.Prior.Exists {
		if current != nil {
			return fmt.Errorf("target %s appeared after the transaction was planned", op.Path)
		}
		return nil
	}
	if current == nil {
		return fmt.Errorf("target %s disappeared after the transaction was planned", op.Path)
	}
	if current.digest != op.Prior.Digest || uint32(current.mode.Perm()) != op.Prior.Mode || current.uid != op.Prior.UID || current.gid != op.Prior.GID {
		return fmt.Errorf("target %s changed after the transaction was planned", op.Path)
	}
	return nil
}

func (tx *Transaction) Commit() error {
	if tx.closed {
		return fmt.Errorf("transaction is closed")
	}
	if tx.journal.Status != statusApplied {
		return fmt.Errorf("transaction status is %q, want %q", tx.journal.Status, statusApplied)
	}
	receipt, err := tx.manager.loadCurrent()
	if err != nil {
		return err
	}
	receipt.APIVersion = ReceiptAPIVersion
	receipt.Sequence = tx.journal.Sequence
	receipt.Transaction = tx.journal.ID
	// Carried over unless this transaction stated otherwise, so a caller that
	// manages no firewall cannot silently disown rules an earlier generation
	// opened.
	if tx.firewall != nil {
		receipt.Firewall = append([]string(nil), *tx.firewall...)
	}
	if tx.journal.Recreate != nil {
		receipt.RecreatePending = false
	}
	for _, op := range tx.journal.Operations {
		if op.Delete {
			delete(receipt.Files, op.Path)
			continue
		}
		receipt.Files[op.Path] = OwnedFile{
			Digest: op.NewDigest, Mode: op.NewMode, UID: op.NewUID, GID: op.NewGID, Ownership: op.Ownership,
		}
	}
	now := tx.manager.Now().UTC()
	tx.journal.Receipt = &receipt
	tx.journal.CommittedAt = &now
	tx.journal.Status = statusCommitted
	if err := tx.persist(); err != nil {
		return err
	}
	writeErr := tx.manager.writeReceipt(receipt)
	closeErr := tx.close()
	return errors.Join(writeErr, closeErr)
}

func (tx *Transaction) Rollback() error {
	if tx.closed {
		return fmt.Errorf("transaction is closed")
	}
	err := tx.rollbackLocked()
	closeErr := tx.close()
	return errors.Join(err, closeErr)
}

func (tx *Transaction) rollbackLocked() error {
	if tx.journal.Status == statusCommitted {
		return fmt.Errorf("committed transaction %s cannot be rolled back as an incomplete apply", tx.journal.ID)
	}
	if tx.journal.Status == statusRolledBack {
		return nil
	}
	tx.journal.Status = statusRollingBack
	if err := tx.persist(); err != nil {
		return err
	}
	var rollbackErrors []error
	for index := len(tx.journal.Operations) - 1; index >= 0; index-- {
		op := &tx.journal.Operations[index]
		if op.State == opPending || op.State == opRolledBack {
			continue
		}
		op.State = opRollingBack
		if err := tx.persist(); err != nil {
			rollbackErrors = append(rollbackErrors, err)
			continue
		}
		if err := tx.restoreOperation(op); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("restore %s: %w", op.Path, err))
			continue
		}
		op.State = opRolledBack
		if err := tx.persist(); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	if len(rollbackErrors) > 0 {
		tx.journal.Status = statusRollbackIncomplete
		persistErr := tx.persist()
		return errors.Join(append(rollbackErrors, persistErr)...)
	}
	tx.journal.Status = statusRolledBack
	return tx.persist()
}

func (tx *Transaction) restoreOperation(op *operation) error {
	current, err := readRegular(op.Path)
	if err != nil {
		return err
	}
	if !op.Prior.Exists {
		if current == nil {
			return nil
		}
		if op.Delete {
			return fmt.Errorf("unexpected file appeared at a target that was absent before delete")
		}
		if current.digest != op.NewDigest {
			return fmt.Errorf("target contains neither the transaction output nor the prior state")
		}
		return durableRemove(op.Path)
	}

	if current != nil && current.digest != op.NewDigest && current.digest != op.Prior.Digest {
		return fmt.Errorf("target contains content written outside this transaction")
	}
	if op.BackupName == "" {
		return fmt.Errorf("journal has no backup for the prior file")
	}
	backupPath := filepath.Join(tx.dir, "backups", op.BackupName)
	backup, err := readRegular(backupPath)
	if err != nil {
		return err
	}
	if backup == nil || backup.digest != op.Prior.Digest {
		return fmt.Errorf("backup is missing or does not match its recorded digest")
	}
	if backup.mode.Perm() != 0o600 || backup.uid != tx.manager.UID || backup.gid != tx.manager.GID {
		return fmt.Errorf("backup metadata is unsafe")
	}
	if err := ensureDirOwned(filepath.Dir(op.Path), 0o700, tx.manager.UID, tx.manager.GID, tx.manager.dirOwnerAllowed); err != nil {
		return err
	}
	return atomicWrite(op.Path, backup.data, os.FileMode(op.Prior.Mode), op.Prior.UID, op.Prior.GID)
}

func (tx *Transaction) close() error {
	if tx.closed {
		return nil
	}
	tx.closed = true
	if !tx.ownsLock {
		return nil
	}
	return releaseLock(tx.lock)
}
