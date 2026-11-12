package discover

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

// ObservationVersion is the schema identifier for the Observed payload.
const ObservationVersion = "spaiter-vpn/observation/v1alpha1"

// Observed is the read-only snapshot of the host that the planner compares
// against the desired state.
type Observed struct {
	APIVersion       string                   `json:"apiVersion"`
	Platform         Platform                 `json:"platform"`
	Privileges       Privileges               `json:"privileges"`
	Docker           Docker                   `json:"docker"`
	Network          Network                  `json:"network"`
	Firewall         Firewall                 `json:"firewall"`
	ExistingDesired  ExistingDesired          `json:"existingDesired"`
	Runtime          Runtime                  `json:"runtime"`
	Credentials      map[state.SecretRef]File `json:"credentials"`
	CertificateFiles map[string]File          `json:"certificateFiles"`
	Logrotate        File                     `json:"logrotate"`
	// ControlUnit is observed only when the desired state manages the daemon.
	ControlUnit *File `json:"controlUnit,omitempty"`
	// BotUser is observed only when the bot runs as its dedicated user.
	BotUser *SystemUser `json:"botUser,omitempty"`
}

// SystemUser is an account looked up by name.
type SystemUser struct {
	Name   string `json:"name"`
	Exists bool   `json:"exists"`
	UID    uint32 `json:"uid,omitempty"`
	GID    uint32 `json:"gid,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Platform identifies the host OS and architecture for compatibility checks.
type Platform struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	ID        string `json:"id"`
	VersionID string `json:"versionId"`
	Systemd   bool   `json:"systemd"`
}

// Supported reports whether the host matches the fixed set of platforms
// bootstrap is allowed to install on.
func (p Platform) Supported() bool {
	if p.OS != "linux" || p.Arch != "amd64" || !p.Systemd {
		return false
	}
	switch p.ID {
	case "ubuntu":
		return p.VersionID == "24.04"
	case "debian":
		return p.VersionID == "12" || p.VersionID == "13"
	default:
		return false
	}
}

// Privileges records the effective user ID of the bootstrap process.
type Privileges struct {
	EUID int `json:"euid"`
}

// Docker reports the availability and reachability of the Docker CLI and
// daemon, and whether sudo is required to talk to it.
type Docker struct {
	CLIAvailable     bool   `json:"cliAvailable"`
	DaemonReachable  bool   `json:"daemonReachable"`
	ComposeAvailable bool   `json:"composeAvailable"`
	ViaSudo          bool   `json:"viaSudo"`
	ServerVersion    string `json:"serverVersion"`
	Error            string `json:"error"`
	// Install is observed only when Docker or Compose is missing and the
	// desired state opts into installing them: what would make that unsafe.
	Install *DockerInstall `json:"install,omitempty"`
}

// DockerInstall lists the preconditions that would block a Docker or Compose
// installation.
type DockerInstall struct {
	Conflicts      []string `json:"conflicts"`
	ForeignSources []string `json:"foreignSources"`
	Error          string   `json:"error,omitempty"`
}

// Network identifies the default route interface, used to resolve "auto"
// XDP interfaces.
type Network struct {
	DefaultInterface string `json:"defaultInterface"`
	Error            string `json:"error"`
}

// Firewall reports the backend kind, whether it is active and readable, and
// the status of each rule the deployment requires.
type Firewall struct {
	Kind     string            `json:"kind"`
	Active   bool              `json:"active"`
	Readable bool              `json:"readable"`
	Required []string          `json:"required"`
	Rules    map[string]string `json:"rules"`
	Detail   string            `json:"detail"`
}

// ExistingDesired reports the state of the on-disk desired.json file: whether
// it is absent, a regular file, or invalid (unreadable, unsafe or failing to
// parse), and its parsed content when it loaded.
type ExistingDesired struct {
	Status FileStatus   `json:"status"`
	Digest string       `json:"digest"`
	State  *state.State `json:"state,omitempty"`
	Error  string       `json:"error"`
}

// Runtime reports the state of the managed deployment files and whether a
// recreate is pending.
type Runtime struct {
	Config          File `json:"config"`
	Secrets         File `json:"secrets"`
	Compose         File `json:"compose"`
	Receipt         File `json:"receipt"`
	RecreatePending bool `json:"recreatePending,omitempty"`
}

// FileStatus classifies a filesystem path for the planner.
type FileStatus string

const (
	// FileAbsent means the path does not exist.
	FileAbsent FileStatus = "absent"
	// FileRegular means the path is a regular file.
	FileRegular FileStatus = "regular"
	// FileInvalid means the path exists but is not a usable regular file.
	FileInvalid FileStatus = "invalid"
)

// File is the observed state of a single filesystem path.
type File struct {
	Status FileStatus `json:"status"`
	Mode   uint32     `json:"mode"`
	UID    uint32     `json:"uid"`
	Size   int64      `json:"size"`
	Error  string     `json:"error"`
}

// MarshalCanonical returns a deterministic JSON encoding of the observation,
// with the required firewall rules sorted and the existing desired state
// canonicalised, so equal hosts always produce equal bytes.
func (o Observed) MarshalCanonical() ([]byte, error) {
	normalized := o
	normalized.Firewall.Required = append([]string(nil), o.Firewall.Required...)
	sort.Strings(normalized.Firewall.Required)
	if o.ExistingDesired.State != nil {
		canonical, err := o.ExistingDesired.State.Canonical()
		if err != nil {
			return nil, fmt.Errorf("canonicalise observed desired state: %w", err)
		}
		normalized.ExistingDesired.State = &canonical
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal host observation: %w", err)
	}
	return data, nil
}

// Digest returns the SHA-256 hex digest of the canonical observation. A plan
// records it so that apply can refuse a consent given against a host that has
// since changed (ErrStaleConsent).
func (o Observed) Digest() (string, error) {
	data, err := o.MarshalCanonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
