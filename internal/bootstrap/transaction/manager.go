package transaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type Manager struct {
	StateDir       string
	AllowedTargets []string
	UID            uint32
	GID            uint32
	// Delegated names directories that belong to an unprivileged service
	// rather than to the manager, such as the bot's data directory. A target's
	// parent there may be owned by that service instead; it must still not be
	// group- or other-writable, and every write stays an exclusive no-follow
	// temporary file renamed into place.
	Delegated []Delegation
	Now       func() time.Time
	NewID     func() (string, error)
}

// Delegation is one directory tree and the owner its directories may have.
type Delegation struct {
	Root string
	UID  uint32
	GID  uint32
}

// dirOwnerAllowed reports whether a directory may be owned by uid:gid.
func (m *Manager) dirOwnerAllowed(dir string, uid, gid uint32) bool {
	if uid == m.UID && gid == m.GID {
		return true
	}
	for _, delegation := range m.Delegated {
		rel, err := filepath.Rel(delegation.Root, dir)
		if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
			continue
		}
		if uid == delegation.UID && gid == delegation.GID {
			return true
		}
	}
	return false
}

type Transaction struct {
	manager  *Manager
	dir      string
	journal  journal
	lock     *os.File
	ownsLock bool
	closed   bool
	// firewall is nil until SetFirewall is called, which is how "no opinion"
	// is told apart from "owns nothing".
	firewall *[]string
}

func (m *Manager) Start(changes []Change) (*Transaction, error) {
	if err := m.prepare(); err != nil {
		return nil, err
	}
	lock, err := m.acquire()
	if err != nil {
		return nil, err
	}
	if err := m.recoverLocked(); err != nil {
		releaseLock(lock)
		return nil, err
	}
	return m.startLocked(lock, true, changes)
}

// startLocked prepares a transaction against an already-held lock. ownsLock
// decides who releases it: a transaction started by Start owns the lock and
// drops it on commit, while one started inside a Guard must not, because the
// guard still needs it for the steps that follow the file writes.
func (m *Manager) startLocked(lock *os.File, ownsLock bool, changes []Change) (*Transaction, error) {
	failed := true
	defer func() {
		if failed && ownsLock {
			releaseLock(lock)
		}
	}()

	operations, err := m.prepareOperations(changes)
	if err != nil {
		return nil, err
	}
	id, err := m.NewID()
	if err != nil {
		return nil, err
	}
	sequence, err := m.nextSequence()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(m.transactionsDir(), fmt.Sprintf("%020d-%s", sequence, id))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create transaction directory: %w", err)
	}
	if err := os.Chown(dir, int(m.UID), int(m.GID)); err != nil {
		return nil, fmt.Errorf("own transaction directory: %w", err)
	}
	if err := ensurePrivateDir(dir, m.UID, m.GID); err != nil {
		return nil, err
	}
	backupDir := filepath.Join(dir, "backups")
	if err := os.Mkdir(backupDir, 0o700); err != nil {
		return nil, fmt.Errorf("create backup directory: %w", err)
	}
	if err := os.Chown(backupDir, int(m.UID), int(m.GID)); err != nil {
		return nil, fmt.Errorf("own backup directory: %w", err)
	}
	if err := ensurePrivateDir(backupDir, m.UID, m.GID); err != nil {
		return nil, err
	}
	if err := syncDir(m.transactionsDir()); err != nil {
		return nil, err
	}

	tx := &Transaction{
		manager:  m,
		dir:      dir,
		lock:     lock,
		ownsLock: ownsLock,
		journal: journal{
			APIVersion: JournalAPIVersion,
			ID:         id, Sequence: sequence, Status: statusPreparing,
			CreatedAt: m.Now().UTC(), Operations: operations,
		},
	}
	if err := tx.persist(); err != nil {
		return nil, err
	}
	for index := range tx.journal.Operations {
		op := &tx.journal.Operations[index]
		if !op.Prior.Exists {
			continue
		}
		backupName := fmt.Sprintf("%04d.backup", index)
		backupPath := filepath.Join(backupDir, backupName)
		if err := atomicWrite(backupPath, op.priorData, 0o600, m.UID, m.GID); err != nil {
			return nil, fmt.Errorf("back up %s: %w", op.Path, err)
		}
		op.BackupName = backupName
		if err := tx.persist(); err != nil {
			return nil, err
		}
	}
	tx.journal.Status = statusPrepared
	if err := tx.persist(); err != nil {
		return nil, err
	}
	failed = false
	return tx, nil
}

func (m *Manager) prepare() error {
	if m.StateDir == "" || !filepath.IsAbs(m.StateDir) || filepath.Clean(m.StateDir) != m.StateDir {
		return fmt.Errorf("transaction state directory must be a clean absolute path")
	}
	if m.Now == nil {
		m.Now = time.Now
	}
	if m.NewID == nil {
		m.NewID = func() (string, error) { return randomHex(8) }
	}
	clean := make([]string, 0, len(m.AllowedTargets))
	seen := map[string]bool{}
	for _, target := range m.AllowedTargets {
		if !filepath.IsAbs(target) || filepath.Clean(target) != target {
			return fmt.Errorf("allowed target %q is not a clean absolute path", target)
		}
		if seen[target] {
			return fmt.Errorf("duplicate allowed target %s", target)
		}
		seen[target] = true
		clean = append(clean, target)
	}
	sort.Strings(clean)
	m.AllowedTargets = clean
	if err := ensurePrivateDir(m.StateDir, m.UID, m.GID); err != nil {
		return err
	}
	if err := ensurePrivateDir(m.transactionsDir(), m.UID, m.GID); err != nil {
		return err
	}
	return nil
}

func (m *Manager) transactionsDir() string { return filepath.Join(m.StateDir, "transactions") }
func (m *Manager) currentPath() string     { return filepath.Join(m.StateDir, "current.json") }
func (m *Manager) lockPath() string        { return filepath.Join(m.StateDir, "lock") }

func (m *Manager) acquire() (*os.File, error) {
	lock, err := os.OpenFile(m.lockPath(), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open transaction lock: %w", err)
	}
	info, err := lock.Stat()
	if err != nil {
		lock.Close()
		return nil, fmt.Errorf("inspect transaction lock: %w", err)
	}
	uid, gid, err := owner(info)
	if err != nil || uid != m.UID || gid != m.GID || info.Mode().Perm() != 0o600 {
		lock.Close()
		return nil, fmt.Errorf("transaction lock metadata is unsafe: mode=%04o uid=%d gid=%d", info.Mode().Perm(), uid, gid)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("lock bootstrap transaction: %w", err)
	}
	return lock, nil
}

func releaseLock(lock *os.File) error {
	if lock == nil {
		return nil
	}
	flockErr := unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	closeErr := lock.Close()
	return errors.Join(flockErr, closeErr)
}

func (m *Manager) prepareOperations(changes []Change) ([]operation, error) {
	if len(changes) == 0 {
		return nil, fmt.Errorf("file transaction has no changes")
	}
	allowed := map[string]bool{}
	for _, target := range m.AllowedTargets {
		allowed[target] = true
	}
	receipt, err := m.loadCurrent()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	operations := make([]operation, 0, len(changes))
	for _, change := range changes {
		if !allowed[change.Path] {
			return nil, fmt.Errorf("target %s is outside the transaction allowlist", change.Path)
		}
		if seen[change.Path] {
			return nil, fmt.Errorf("more than one change targets %s", change.Path)
		}
		seen[change.Path] = true
		if change.Ownership != Managed && change.Ownership != RuntimeMutable {
			return nil, fmt.Errorf("%s has unknown ownership mode %q", change.Path, change.Ownership)
		}
		if !change.Delete && change.Mode.Perm() == 0 {
			return nil, fmt.Errorf("%s has empty permissions", change.Path)
		}

		snapshot, err := readRegular(change.Path)
		if err != nil {
			return nil, err
		}
		if change.ExpectedPriorDigest != "" && (snapshot == nil || snapshot.digest != change.ExpectedPriorDigest) {
			return nil, fmt.Errorf("target %s changed after its migration snapshot was read", change.Path)
		}
		owned, wasOwned := receipt.Files[change.Path]
		if change.ReplaceRuntimeMutable && change.AdoptRuntimeMutable {
			return nil, fmt.Errorf("%s cannot request both replacement and adoption", change.Path)
		}
		if change.ReplaceRuntimeMutable && (change.Delete || change.Ownership != RuntimeMutable || snapshot == nil || !wasOwned || owned.Ownership != RuntimeMutable) {
			return nil, fmt.Errorf("%s requests a runtime-mutable replacement but is not an owned runtime-mutable file", change.Path)
		}
		if change.AdoptRuntimeMutable && (change.Ownership != RuntimeMutable || snapshot == nil || wasOwned) {
			return nil, fmt.Errorf("%s requests runtime-mutable adoption but is not an unowned existing file", change.Path)
		}
		if snapshot != nil && !wasOwned && !change.AdoptRuntimeMutable {
			return nil, fmt.Errorf("refuse to overwrite foreign file %s: no committed receipt owns it", change.Path)
		}
		if wasOwned && snapshot != nil {
			if snapshot.mode.Perm() != os.FileMode(owned.Mode) || snapshot.uid != owned.UID || snapshot.gid != owned.GID {
				return nil, fmt.Errorf("owned file %s metadata drifted: mode=%04o uid=%d gid=%d, receipt mode=%04o uid=%d gid=%d", change.Path, snapshot.mode.Perm(), snapshot.uid, snapshot.gid, owned.Mode, owned.UID, owned.GID)
			}
			if owned.Ownership == Managed && snapshot.digest != owned.Digest {
				return nil, fmt.Errorf("owned file %s content drifted from receipt", change.Path)
			}
			if owned.Ownership == RuntimeMutable && !change.Delete && !change.ReplaceRuntimeMutable {
				return nil, fmt.Errorf("refuse to replace runtime-mutable file %s", change.Path)
			}
		}

		op := operation{
			Path: change.Path, Delete: change.Delete, Ownership: change.Ownership,
			NewMode: uint32(change.Mode.Perm()), NewUID: change.UID, NewGID: change.GID,
			State: opPending, newData: append([]byte(nil), change.Data...),
		}
		if !change.Delete {
			op.NewDigest = digest(change.Data)
		}
		if snapshot != nil {
			op.Prior = priorFile{Exists: true, Digest: snapshot.digest, Mode: uint32(snapshot.mode.Perm()), UID: snapshot.uid, GID: snapshot.gid}
			op.priorData = append([]byte(nil), snapshot.data...)
		}
		operations = append(operations, op)
	}
	return operations, nil
}

// Current returns the last committed receipt and whether one exists.
//
// Deliberately read-only: it takes no lock and creates no directory, because
// status has to be answerable on a host that must not be touched — including by
// an operator who is not root and is only asking what is installed.
func (m *Manager) Current() (Receipt, bool, error) {
	if _, err := os.Lstat(m.currentPath()); err != nil {
		if os.IsNotExist(err) {
			return Receipt{}, false, nil
		}
		return Receipt{}, false, fmt.Errorf("inspect current receipt: %w", err)
	}
	receipt, err := m.loadCurrent()
	if err != nil {
		return Receipt{}, false, err
	}
	return receipt, true, nil
}

func (m *Manager) loadCurrent() (Receipt, error) {
	receipt := Receipt{APIVersion: ReceiptAPIVersion, Files: map[string]OwnedFile{}}
	snapshot, err := readRegular(m.currentPath())
	if err != nil {
		return Receipt{}, fmt.Errorf("read current receipt: %w", err)
	}
	if snapshot == nil {
		return receipt, nil
	}
	if snapshot.uid != m.UID || snapshot.gid != m.GID || snapshot.mode.Perm() != 0o600 {
		return Receipt{}, fmt.Errorf("current receipt metadata is unsafe: mode=%04o uid=%d gid=%d", snapshot.mode.Perm(), snapshot.uid, snapshot.gid)
	}
	decoder := json.NewDecoder(bytes.NewReader(snapshot.data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("decode current receipt: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Receipt{}, fmt.Errorf("current receipt contains trailing JSON")
	}
	if receipt.APIVersion != ReceiptAPIVersion || receipt.Files == nil {
		return Receipt{}, fmt.Errorf("unsupported or incomplete current receipt")
	}
	allowed := map[string]bool{}
	for _, path := range m.AllowedTargets {
		allowed[path] = true
	}
	for path, file := range receipt.Files {
		if !allowed[path] {
			return Receipt{}, fmt.Errorf("current receipt claims path outside the allowlist: %s", path)
		}
		if file.Ownership != Managed && file.Ownership != RuntimeMutable {
			return Receipt{}, fmt.Errorf("current receipt has unknown ownership %q for %s", file.Ownership, path)
		}
	}
	return receipt, nil
}

func (m *Manager) nextSequence() (uint64, error) {
	entries, err := os.ReadDir(m.transactionsDir())
	if err != nil {
		return 0, err
	}
	var highest uint64
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		var sequence uint64
		if _, err := fmt.Sscanf(entry.Name(), "%d-", &sequence); err == nil && sequence > highest {
			highest = sequence
		}
	}
	return highest + 1, nil
}

func (tx *Transaction) journalPath() string { return filepath.Join(tx.dir, "journal.json") }

func (tx *Transaction) persist() error {
	data, err := json.MarshalIndent(tx.journal, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal transaction journal: %w", err)
	}
	data = append(data, '\n')
	return atomicWrite(tx.journalPath(), data, 0o600, tx.manager.UID, tx.manager.GID)
}
