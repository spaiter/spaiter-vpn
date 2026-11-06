// Package transaction provides the crash-recoverable file transaction used by
// bootstrap apply. It manages only an explicit allowlist of exact host paths.
package transaction

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

const (
	JournalAPIVersion = "spaiter-vpn/transaction/v1alpha1"
	ReceiptAPIVersion = "spaiter-vpn/receipt/v1alpha1"
)

var ErrLocked = fmt.Errorf("another bootstrap transaction holds the lock")

type Ownership string

const (
	// Managed files must retain the digest recorded by the last receipt.
	Managed Ownership = "managed"
	// RuntimeMutable files may change contents after commit, but retain their
	// regular-file type, owner, group and mode.
	RuntimeMutable Ownership = "runtime-mutable"
)

type Change struct {
	Path      string
	Data      []byte
	Mode      os.FileMode
	UID       uint32
	GID       uint32
	Ownership Ownership
	Delete    bool
	// ReplaceRuntimeMutable is a narrow migration capability. Ordinary
	// convergence must omit runtime files entirely; when true, the manager
	// still requires an existing receipt to own this path as RuntimeMutable.
	ReplaceRuntimeMutable bool
	// AdoptRuntimeMutable is the one-time migration path for runtime state
	// created before bootstrap owned it (for example bot peer files). The
	// manager still requires an existing regular file at an exact allowlisted
	// path; after commit the receipt owns it as RuntimeMutable.
	AdoptRuntimeMutable bool
	// ExpectedPriorDigest pins a runtime file to the exact bytes the caller
	// inspected while preparing a read-modify-write. Without it, a writer that
	// changes the file before Start could have its update silently overwritten
	// by data derived from the older snapshot. Empty means no caller-side
	// snapshot was taken.
	ExpectedPriorDigest string
}

type Receipt struct {
	APIVersion  string               `json:"apiVersion"`
	Sequence    uint64               `json:"sequence"`
	Transaction string               `json:"transaction"`
	Files       map[string]OwnedFile `json:"files"`
	// Firewall names the host-firewall rules this deployment opened and has
	// not retired, as "port/protocol".
	//
	// Recorded rather than derived, because the alternative is diffing the live
	// rule set against what the deployment wants — which would delete rules
	// somebody else added for something else entirely. Without this list a
	// migration that moves a port can open the new one but never close the old,
	// and the stale allow outlives every later generation.
	//
	// Absent in receipts written before this field existed; an empty list then
	// means "we have never recorded owning any", which is the safe reading: it
	// retires nothing.
	Firewall []string `json:"firewall,omitempty"`
	// RecreatePending says file recovery restored the previous generation after
	// a process may already have replaced its containers. The next apply must
	// force-recreate from the restored files; a live API sync cannot revert
	// top-level certificate, XDP or logging state.
	RecreatePending bool `json:"recreatePending,omitempty"`
}

// Generation is one successfully committed bootstrap transaction. It exposes
// only durable audit metadata; file contents remain behind GenerationFile so
// callers cannot accidentally trust an unchecked backup path from a journal.
type Generation struct {
	Sequence    uint64
	Transaction string
	CommittedAt time.Time
	Receipt     Receipt
}

type OwnedFile struct {
	Digest    string    `json:"digest"`
	Mode      uint32    `json:"mode"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	Ownership Ownership `json:"ownership"`
}

// firewallIntent is what a transaction is about to do to the host firewall,
// written down before it does it.
//
// This is what makes a killed apply's rules recoverable. Ownership is otherwise
// recorded only in the receipt, which is written at commit — so a process that
// died between opening a port and committing left that port open and owned by
// nobody, and because an already-allowed rule is indistinguishable from one the
// operator opened, no later apply could ever adopt or retire it.
//
// Add lists only rules observed as BLOCKED when the transaction was planned.
// That restriction is what makes adoption safe rather than a guess: if a rule
// was blocked before we started and is allowed afterwards, we opened it.
type firewallIntent struct {
	Add    []string `json:"add,omitempty"`
	Retire []string `json:"retire,omitempty"`
	// Adopted records that recovery has already folded Add into the receipt,
	// so re-reading the journal cannot report it as outstanding work twice.
	Adopted bool `json:"adopted,omitempty"`
}

type recreateIntent struct {
	// Adopted records that recovery durably copied the intent into the current
	// receipt. A later successful recreate clears the receipt without this old
	// rolled-back journal resurrecting it.
	Adopted bool `json:"adopted,omitempty"`
}

type journal struct {
	APIVersion  string          `json:"apiVersion"`
	ID          string          `json:"id"`
	Sequence    uint64          `json:"sequence"`
	Status      status          `json:"status"`
	CreatedAt   time.Time       `json:"createdAt"`
	CommittedAt *time.Time      `json:"committedAt,omitempty"`
	Operations  []operation     `json:"operations"`
	Firewall    *firewallIntent `json:"firewall,omitempty"`
	Recreate    *recreateIntent `json:"recreate,omitempty"`
	Receipt     *Receipt        `json:"receipt,omitempty"`
}

type status string

const (
	statusPreparing          status = "preparing"
	statusPrepared           status = "prepared"
	statusApplying           status = "applying"
	statusApplied            status = "applied"
	statusRollingBack        status = "rolling-back"
	statusRolledBack         status = "rolled-back"
	statusRollbackIncomplete status = "rollback-incomplete"
	statusCommitted          status = "committed"
)

type operation struct {
	Path       string    `json:"path"`
	Delete     bool      `json:"delete"`
	Ownership  Ownership `json:"ownership"`
	NewDigest  string    `json:"newDigest"`
	NewMode    uint32    `json:"newMode"`
	NewUID     uint32    `json:"newUid"`
	NewGID     uint32    `json:"newGid"`
	Prior      priorFile `json:"prior"`
	BackupName string    `json:"backupName"`
	State      opState   `json:"state"`
	newData    []byte
	priorData  []byte
}

type priorFile struct {
	Exists bool   `json:"exists"`
	Digest string `json:"digest"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

type opState string

const (
	opPending     opState = "pending"
	opApplying    opState = "applying"
	opApplied     opState = "applied"
	opRollingBack opState = "rolling-back"
	opRolledBack  opState = "rolled-back"
)

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
