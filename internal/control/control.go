// Package control is the narrow, privileged control plane of phase 8: a root
// daemon on a local Unix socket that performs typed VPN operations for
// unprivileged front ends (the Telegram bot, a web UI, an operator's shell).
//
// The boundary is the point. A front end may ask for an allowed operation; it
// never gets the Docker socket, a shell, a host path or a raw desired-state
// document. Every request names its operation and typed arguments, every
// caller is identified by the kernel (SO_PEERCRED) rather than by anything it
// sends, and every mutating request is recorded in an append-only audit log.
//
// Mutations take two steps, mirroring the CLI's consent model: Prepare
// computes the plan and returns a single-use ticket bound to that plan's
// digests; Commit runs the ticket, and the engine recomputes the plan under its
// lock and refuses if anything moved in between.
package control

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const APIVersion = "spaiter-vpn/control/v1alpha1"

// Role is what a caller may do. Observers read; operators also change things.
type Role string

const (
	RoleObserver Role = "observer"
	RoleOperator Role = "operator"
)

// Operation names one typed request. There is no generic "run" operation and
// there never will be: a compromised front end is limited to this list.
type Operation string

const (
	OpStatus      Operation = "status"
	OpGenerations Operation = "generations"
	OpPreflight   Operation = "preflight"
	OpPrepare     Operation = "prepare"
	OpCommit      Operation = "commit"
	OpCancel      Operation = "cancel"
	OpSelfTest    Operation = "selftest"
)

// Requires reports the role an operation needs.
func (o Operation) Requires() (Role, bool) {
	switch o {
	case OpStatus, OpGenerations:
		return RoleObserver, true
	case OpPreflight, OpPrepare, OpCommit, OpCancel, OpSelfTest:
		// Preflight and prepare do not mutate, but they run host probes and
		// reveal planning detail; selftest briefly adds an endpoint.
		return RoleOperator, true
	}
	return "", false
}

// ChangeKind selects what a Prepare request changes.
type ChangeKind string

const (
	ChangeSettings ChangeKind = "settings"
	ChangeImage    ChangeKind = "image"
	ChangeRotate   ChangeKind = "rotate"
	ChangeRollback ChangeKind = "rollback"
)

// Change is a typed modification of the current deployment. Exactly the
// fields of its Kind may be set. Nothing here can name a host path, a
// certificate file, a credential reference or the relay directory: those are
// the operator's, set through the local CLI only.
type Change struct {
	Kind ChangeKind `json:"kind"`

	// settings
	Ports   map[string]uint16 `json:"ports,omitempty"`
	MTU     map[string]uint32 `json:"mtu,omitempty"`
	Enable  []string          `json:"enable,omitempty"`
	Disable []string          `json:"disable,omitempty"`

	// image: a new tag or digest of the image repository already deployed.
	Image string `json:"image,omitempty"`

	// rotate
	Users []string `json:"users,omitempty"`

	// rollback: zero selects the previous committed generation.
	Generation uint64 `json:"generation,omitempty"`
}

// Validate checks the shape, not the deployment: whether a port is free or a
// user exists is the planner's and the engine's to decide.
func (c Change) Validate() error {
	settings := len(c.Ports) > 0 || len(c.MTU) > 0 || len(c.Enable) > 0 || len(c.Disable) > 0
	switch c.Kind {
	case ChangeSettings:
		if !settings {
			return fmt.Errorf("a settings change names no port, MTU or protocol")
		}
		if c.Image != "" || len(c.Users) > 0 || c.Generation != 0 {
			return fmt.Errorf("a settings change carries fields of another kind")
		}
		for protocol, port := range c.Ports {
			if port == 0 {
				return fmt.Errorf("port for %s is zero", protocol)
			}
		}
		seen := map[string]bool{}
		for _, protocol := range append(append([]string(nil), c.Enable...), c.Disable...) {
			if seen[protocol] {
				return fmt.Errorf("protocol %s is both enabled and disabled, or named twice", protocol)
			}
			seen[protocol] = true
		}
	case ChangeImage:
		if c.Image == "" || settings || len(c.Users) > 0 || c.Generation != 0 {
			return fmt.Errorf("an image change names exactly one image reference")
		}
	case ChangeRotate:
		if len(c.Users) == 0 || settings || c.Image != "" || c.Generation != 0 {
			return fmt.Errorf("a rotation names its users and nothing else")
		}
	case ChangeRollback:
		if settings || c.Image != "" || len(c.Users) > 0 {
			return fmt.Errorf("a rollback names at most a generation")
		}
	default:
		return fmt.Errorf("unknown change kind %q", c.Kind)
	}
	return nil
}

// Summary is the change as the audit log records it: typed fields only, no
// values that could be secret.
func (c Change) Summary() string {
	var parts []string
	keys := func(m map[string]uint16) []string {
		out := make([]string, 0, len(m))
		for k, v := range m {
			out = append(out, fmt.Sprintf("%s=%d", k, v))
		}
		sort.Strings(out)
		return out
	}
	switch c.Kind {
	case ChangeSettings:
		if len(c.Ports) > 0 {
			parts = append(parts, "ports "+strings.Join(keys(c.Ports), ","))
		}
		if len(c.MTU) > 0 {
			mtu := map[string]uint16{}
			for k, v := range c.MTU {
				mtu[k] = uint16(v)
			}
			parts = append(parts, "mtu "+strings.Join(keys(mtu), ","))
		}
		if len(c.Enable) > 0 {
			parts = append(parts, "enable "+strings.Join(c.Enable, ","))
		}
		if len(c.Disable) > 0 {
			parts = append(parts, "disable "+strings.Join(c.Disable, ","))
		}
	case ChangeImage:
		parts = append(parts, "image "+c.Image)
	case ChangeRotate:
		parts = append(parts, "users "+strings.Join(c.Users, ","))
	case ChangeRollback:
		parts = append(parts, fmt.Sprintf("generation %d", c.Generation))
	}
	return string(c.Kind) + ": " + strings.Join(parts, "; ")
}

// Request is the single wire request. One shape for every operation keeps the
// decoder strict: unknown fields are refused.
type Request struct {
	APIVersion string    `json:"apiVersion"`
	Operation  Operation `json:"operation"`
	Change     *Change   `json:"change,omitempty"`
	Ticket     string    `json:"ticket,omitempty"`
}

// Response carries a result or an error, plus the engine's progress output.
type Response struct {
	APIVersion string          `json:"apiVersion"`
	OK         bool            `json:"ok"`
	Error      string          `json:"error,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	Output     string          `json:"output,omitempty"`
}

// Ticket is a prepared, not yet committed, change.
type Ticket struct {
	ID        string    `json:"id"`
	Change    Change    `json:"change"`
	Plan      any       `json:"plan"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Peer is who is on the other end of the socket, as the kernel says.
type Peer struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
	PID int32  `json:"pid"`
}
