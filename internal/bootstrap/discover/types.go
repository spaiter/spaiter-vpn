package discover

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

const ObservationVersion = "spaiter-vpn/observation/v1alpha1"

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

type Platform struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	ID        string `json:"id"`
	VersionID string `json:"versionId"`
	Systemd   bool   `json:"systemd"`
}

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

type Privileges struct {
	EUID int `json:"euid"`
}

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

type DockerInstall struct {
	Conflicts      []string `json:"conflicts"`
	ForeignSources []string `json:"foreignSources"`
	Error          string   `json:"error,omitempty"`
}

type Network struct {
	DefaultInterface string `json:"defaultInterface"`
	Error            string `json:"error"`
}

type Firewall struct {
	Kind     string            `json:"kind"`
	Active   bool              `json:"active"`
	Readable bool              `json:"readable"`
	Required []string          `json:"required"`
	Rules    map[string]string `json:"rules"`
	Detail   string            `json:"detail"`
}

type ExistingDesired struct {
	Status FileStatus   `json:"status"`
	Digest string       `json:"digest"`
	State  *state.State `json:"state,omitempty"`
	Error  string       `json:"error"`
}

type Runtime struct {
	Config          File `json:"config"`
	Secrets         File `json:"secrets"`
	Compose         File `json:"compose"`
	Receipt         File `json:"receipt"`
	RecreatePending bool `json:"recreatePending,omitempty"`
}

type FileStatus string

const (
	FileAbsent  FileStatus = "absent"
	FileRegular FileStatus = "regular"
	FileInvalid FileStatus = "invalid"
)

type File struct {
	Status FileStatus `json:"status"`
	Mode   uint32     `json:"mode"`
	UID    uint32     `json:"uid"`
	Size   int64      `json:"size"`
	Error  string     `json:"error"`
}

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

func (o Observed) Digest() (string, error) {
	data, err := o.MarshalCanonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
