package discover

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	desiredstate "github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
)

// Layout is the fixed filesystem surface bootstrap is allowed to inspect and,
// in later phases, manage. Tests may point it at a temporary root; a future
// remote control API will not accept arbitrary replacements.
type Layout struct {
	ConfigRoot    string `json:"configRoot"`
	DataRoot      string `json:"dataRoot"`
	LogrotatePath string `json:"logrotatePath"`
	// ControlUnitPath is where the control daemon's systemd unit goes.
	ControlUnitPath string `json:"controlUnitPath,omitempty"`
}

func DefaultLayout() Layout {
	return Layout{
		ConfigRoot:      "/etc/spaiter-vpn",
		DataRoot:        "/var/lib/spaiter-vpn",
		LogrotatePath:   "/etc/logrotate.d/spaiter-vpn",
		ControlUnitPath: "/etc/systemd/system/spaiter-vpn-control.service",
	}
}

// ControlAccessPath is the daemon's uid allow-list.
func (l Layout) ControlAccessPath() string { return filepath.Join(l.ConfigRoot, "control.json") }

// ControlManagedAccessPath is the allow-list bootstrap keeps for its own
// service accounts, beside the operator's.
func (l Layout) ControlManagedAccessPath() string {
	return filepath.Join(l.ConfigRoot, "control.bootstrap.json")
}

// WebKeyPath signs the web UI's login links.
func (l Layout) WebKeyPath() string { return filepath.Join(l.ConfigRoot, "web.key") }

// WebUnitPath is the web UI's unit, beside the control daemon's.
func (l Layout) WebUnitPath() string {
	if l.ControlUnitPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(l.ControlUnitPath), "spaiter-vpn-web.service")
}

// DDNSUnitPath is the dynamic DNS updater's unit, beside the control daemon's.
func (l Layout) DDNSUnitPath() string {
	if l.ControlUnitPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(l.ControlUnitPath), "spaiter-vpn-ddns.service")
}

func (l Layout) DesiredPath() string   { return filepath.Join(l.ConfigRoot, "desired.json") }
func (l Layout) CredentialDir() string { return filepath.Join(l.ConfigRoot, "credentials") }
func (l Layout) DeploymentDir() string { return filepath.Join(l.ConfigRoot, "deployment") }
func (l Layout) ConfigPath() string    { return filepath.Join(l.DeploymentDir(), "config.json") }
func (l Layout) SecretsPath() string {
	return filepath.Join(l.DeploymentDir(), "secrets", "secrets.json")
}
func (l Layout) ComposePath() string { return filepath.Join(l.DeploymentDir(), "docker-compose.yml") }
func (l Layout) CurrentReceiptPath() string {
	return filepath.Join(l.DataRoot, "bootstrap", "current.json")
}

// The remaining paths are the rest of the managed surface. They live here so
// apply, discovery and the transaction allowlist cannot disagree about where a
// managed file is, and so no caller has to join paths itself.
func (l Layout) EnvPath() string       { return filepath.Join(l.DeploymentDir(), ".env") }
func (l Layout) BotConfigPath() string { return filepath.Join(l.DeploymentDir(), "bot.json") }

// BotManagementPath holds only the management endpoint and secret for a bot
// that runs without access to the core's configuration.
func (l Layout) BotManagementPath() string {
	return filepath.Join(l.DeploymentDir(), "bot-management.json")
}
func (l Layout) ReloadAgentPath() string {
	return filepath.Join(l.DeploymentDir(), "reload-agent.sh")
}

// CacheDir is mounted at /var/lib/sing-box: the core's own working directory,
// including ACME state, so it must survive a rollback rather than live beside
// the managed files.
func (l Layout) CacheDir() string { return filepath.Join(l.DataRoot, "cache") }

// BotDataDir holds the bot's token registry, per-user peers and reload markers.
func (l Layout) BotDataDir() string { return filepath.Join(l.DataRoot, "bot") }

// BootstrapStateDir holds the lock, the current receipt and the transaction
// journals.
func (l Layout) BootstrapStateDir() string { return filepath.Join(l.DataRoot, "bootstrap") }

// PlatformRecordPath is where bootstrap records host packages it installed.
// Outside the transaction directory on purpose: installing packages is not
// undone by a rollback, so its record must not be pruned or rolled back either.
func (l Layout) PlatformRecordPath() string {
	return filepath.Join(l.BootstrapStateDir(), "platform.json")
}

// ManagedFiles is every static path bootstrap may write, in a stable order.
func (l Layout) ManagedFiles() []string {
	files := []string{
		l.DesiredPath(),
		l.ConfigPath(),
		l.SecretsPath(),
		l.ComposePath(),
		l.EnvPath(),
		l.BotConfigPath(),
		l.BotManagementPath(),
		l.ReloadAgentPath(),
		l.LogrotatePath,
	}
	if l.ControlUnitPath != "" {
		files = append(files, l.ControlUnitPath, l.ControlAccessPath(), l.ControlManagedAccessPath(), l.WebUnitPath(), l.WebKeyPath(), l.DDNSUnitPath())
	}
	return files
}

// TransactionTargets returns ManagedFiles plus the dynamic bot peer and
// subscription-cache files that may join a subnet-migration transaction.
// Existing files cover normal operation; paths already recorded in the receipt
// cover a peer file that disappeared, so the transaction manager can read its
// own receipt instead of rejecting it as foreign.
func (l Layout) TransactionTargets() ([]string, error) {
	paths := append([]string(nil), l.ManagedFiles()...)
	botTargets, err := l.BotTransactionTargets()
	if err != nil {
		return nil, err
	}
	paths = append(paths, botTargets...)
	sort.Strings(paths)
	return slices.Compact(paths), nil
}

func (l Layout) BotTransactionTargets() ([]string, error) {
	markerPath := (deploy.Bot{DataDir: l.BotDataDir()}).WDTTReloadMarkerPath()
	paths := []string{markerPath}
	relayPasswordsPath := ""
	if desired, err := desiredstate.Load(l.DesiredPath()); err == nil && desired.Bot.WDTTConfigDirectory != "" {
		relayPasswordsPath = filepath.Join(desired.Bot.WDTTConfigDirectory, "passwords.json")
		paths = append(paths, relayPasswordsPath)
	}
	// wdtt/*.json holds the subscription registry and each user's relay
	// password, which a credential rotation rewrites. vk_hashes.json beside them
	// is the bot's call pool and is never part of a transaction.
	wdttDir := filepath.Join(l.BotDataDir(), "wdtt")
	vkHashes := filepath.Join(wdttDir, "vk_hashes.json")
	for _, pattern := range []string{
		filepath.Join(l.BotDataDir(), "awg", "*.json"),
		filepath.Join(l.BotDataDir(), "wdtt", "subs-cache", "*.json"),
		filepath.Join(wdttDir, "*.json"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			if match != vkHashes {
				paths = append(paths, match)
			}
		}
	}
	data, err := os.ReadFile(l.CurrentReceiptPath())
	if err == nil {
		var receipt struct {
			Files map[string]json.RawMessage `json:"files"`
		}
		if json.Unmarshal(data, &receipt) == nil {
			roots := []string{
				filepath.Join(l.BotDataDir(), "awg"),
				filepath.Join(l.BotDataDir(), "wdtt", "subs-cache"),
				wdttDir,
			}
			for path := range receipt.Files {
				if path == vkHashes {
					continue
				}
				if path == markerPath || relayPasswordsPath != "" && path == relayPasswordsPath {
					paths = append(paths, path)
					continue
				}
				for _, root := range roots {
					rel, relErr := filepath.Rel(root, path)
					if relErr == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && filepath.Dir(rel) == "." && strings.HasSuffix(rel, ".json") {
						paths = append(paths, path)
						break
					}
				}
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	sort.Strings(paths)
	return slices.Compact(paths), nil
}

// Delegation is a directory tree an unprivileged service owns, and the owner
// its directories may have; see transaction.Manager.Delegated.
type Delegation struct {
	Root     string
	UID, GID uint32
}

// BotDelegations returns the trees the bot's account may own: its data
// directory, and the relay directory it shares with root as its group. Keyed
// on the account existing rather than on the desired state, so switching the
// bot back to root can still move the files it owns.
func (l Layout) BotDelegations(account SystemUser, relayDir string) []Delegation {
	if !account.Exists {
		return nil
	}
	out := []Delegation{{Root: l.BotDataDir(), UID: account.UID, GID: account.GID}}
	if relayDir != "" {
		out = append(out, Delegation{Root: relayDir, UID: 0, GID: account.GID})
	}
	return out
}
