// Package plan turns secret-free desired state and a read-only host observation
// into an ordered, deterministic bootstrap plan.
package plan

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/dockerinstall"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
)

const APIVersionV1Alpha1 = "spaiter-vpn/plan/v1alpha1"

type Mode string

const (
	ModeFresh             Mode = "fresh"
	ModeReconcile         Mode = "reconcile"
	ModeMigrate           Mode = "migrate"
	ModeRestartMigrate    Mode = "restart-migrate"
	ModeSubnetMigrate     Mode = "subnet-migrate"
	ModeRestartRecover    Mode = "restart-recover"
	ModeMigrationRequired Mode = "migration-required"
	ModeConflict          Mode = "conflict"
)

type Disposition string

const (
	Verify  Disposition = "verify"
	Apply   Disposition = "apply"
	Manual  Disposition = "manual"
	Blocked Disposition = "blocked"
)

type Plan struct {
	APIVersion        string         `json:"apiVersion"`
	DesiredDigest     string         `json:"desiredDigest"`
	ObservationDigest string         `json:"observationDigest"`
	Mode              Mode           `json:"mode"`
	Blocked           bool           `json:"blocked"`
	Changes           []state.Change `json:"changes"`
	Actions           []Action       `json:"actions"`
}

type Action struct {
	ID          string      `json:"id"`
	Disposition Disposition `json:"disposition"`
	Mutates     bool        `json:"mutates"`
	Summary     string      `json:"summary"`
	Reason      string      `json:"reason"`
	Proof       string      `json:"proof"`
	Rollback    string      `json:"rollback"`
}

func Build(desired state.State, observed discover.Observed) (Plan, error) {
	if err := desired.Validate(); err != nil {
		return Plan{}, fmt.Errorf("desired state: %w", err)
	}
	if observed.APIVersion != discover.ObservationVersion {
		return Plan{}, fmt.Errorf("unsupported observation apiVersion %q", observed.APIVersion)
	}
	desiredDigest, err := desired.Digest()
	if err != nil {
		return Plan{}, err
	}
	observationDigest, err := observed.Digest()
	if err != nil {
		return Plan{}, err
	}
	result := Plan{
		APIVersion:        APIVersionV1Alpha1,
		DesiredDigest:     desiredDigest,
		ObservationDigest: observationDigest,
		Changes:           []state.Change{},
		Actions:           []Action{},
	}

	result.planPlatform(observed)
	result.planExisting(desired, observed)
	if result.Mode == ModeMigrationRequired || result.Mode == ModeConflict {
		return result, result.validate()
	}
	result.planCredentials(observed)
	result.planDocker(desired, observed)
	result.planNetwork(desired, observed)

	result.add(Action{
		ID: "preflight", Disposition: Verify,
		Summary: "run the complete host preflight",
		Reason:  "port, kernel, XDP, certificate and writable-directory checks must pass before any credential is generated",
		Proof:   "preflight has zero FAIL findings", Rollback: "none; read-only",
	})
	result.planDeployment()
	result.planLogrotate(desired, observed)
	result.planFirewall(desired, observed)
	result.planDesiredState()
	result.planComposeAndHealth()
	result.planBotOwnership(desired)
	result.planControl(desired, observed)
	result.planWeb(desired)
	result.planDDNS(desired)
	result.planBotUser(desired, observed)

	if result.Mode == "" {
		result.Mode = ModeConflict
	}
	return result, result.validate()
}

func (p *Plan) planPlatform(observed discover.Observed) {
	platform := observed.Platform
	if !platform.Supported() {
		p.block("platform", "unsupported bootstrap platform",
			fmt.Sprintf("found os=%s arch=%s id=%s version=%s systemd=%t; phase 7 supports Ubuntu 24.04 or Debian 12/13 on amd64 with systemd", platform.OS, platform.Arch, platform.ID, platform.VersionID, platform.Systemd))
	} else {
		p.add(Action{
			ID: "platform", Disposition: Verify,
			Summary: fmt.Sprintf("use supported %s %s on %s", platform.ID, platform.VersionID, platform.Arch),
			Reason:  "phase 7 intentionally has one narrow platform adapter",
			Proof:   "OS, architecture and systemd match the supported matrix", Rollback: "none; read-only",
		})
	}

	rootSummary := "apply is already running as root"
	if observed.Privileges.EUID != 0 {
		rootSummary = fmt.Sprintf("re-run apply as root (current euid %d)", observed.Privileges.EUID)
	}
	p.add(Action{
		ID: "root", Disposition: Verify, Summary: rootSummary,
		Reason: "planning is read-only, while apply writes /etc, manages firewall rules and runs the self-test",
		Proof:  "effective uid is 0 at apply time", Rollback: "none; privilege check only",
	})
}

func (p *Plan) planExisting(desired state.State, observed discover.Observed) {
	switch observed.ExistingDesired.Status {
	case discover.FileAbsent:
		p.Mode = ModeFresh
		if runtimePresent(observed.Runtime) {
			p.Mode = ModeConflict
			p.block("existing-runtime", "refuse to adopt an untracked deployment",
				"desired.json is absent but config, secrets, Compose or a receipt already exists; an explicit import is required")
		}
	case discover.FileInvalid:
		p.Mode = ModeConflict
		p.block("desired-state", "existing desired state is invalid", observed.ExistingDesired.Error)
	case discover.FileRegular:
		if observed.ExistingDesired.State == nil {
			p.Mode = ModeConflict
			p.block("desired-state", "existing desired state was not decoded", "discovery returned a regular desired file without its parsed state")
			return
		}
		actualDigest, digestErr := observed.ExistingDesired.State.Digest()
		if digestErr != nil || actualDigest != observed.ExistingDesired.Digest {
			p.Mode = ModeConflict
			p.block("desired-state", "existing desired-state digest is inconsistent",
				fmt.Sprintf("observed=%s computed=%s error=%v", observed.ExistingDesired.Digest, actualDigest, digestErr))
			return
		}
		changes, err := state.Diff(*observed.ExistingDesired.State, desired)
		if err != nil {
			p.Mode = ModeConflict
			p.block("desired-state-diff", "cannot compare desired states", err.Error())
			return
		}
		p.Changes = changes
		if state.RequiresMigration(changes) {
			var unsupported []string
			restart := false
			subnet := false
			seedUsers := false
			subnetMoves, subnetErr := desired.AuthorizedSubnetMigrations(*observed.ExistingDesired.State)
			seedUserMove, seedUserErr := desired.AuthorizedSeedUserMigration(*observed.ExistingDesired.State)
			rotation, rotationErr := desired.AuthorizedCredentialRotation(*observed.ExistingDesired.State)
			for _, change := range changes {
				if change.Class != state.Migration {
					continue
				}
				switch {
				case supportedMigration(change.Path):
				case restartMigration(change.Path):
					restart = true
				case strings.HasPrefix(change.Path, "/deployment/subnets/") && subnetErr == nil:
					subnet = true
				case change.Path == "/bootstrap/seedUsers" && seedUserErr == nil:
					seedUsers = true
				case change.Path == "/migrationPolicy" && subnetErr == nil && seedUserErr == nil && rotationErr == nil && (len(subnetMoves) > 0 || seedUserMove != nil || rotation != nil):
				default:
					unsupported = append(unsupported, change.Path)
				}
			}
			if subnetErr != nil && hasSubnetMigrationChange(changes) {
				unsupported = append(unsupported, subnetErr.Error())
			}
			if seedUserErr != nil && hasSeedUserMigrationChange(changes) {
				unsupported = append(unsupported, seedUserErr.Error())
			}
			if rotationErr != nil && hasMigrationPolicyChange(changes) {
				unsupported = append(unsupported, rotationErr.Error())
			}
			if rotation != nil {
				// One reason per generation. A rotation folded into a reshaping
				// apply would make a failed apply ambiguous about which half to
				// retry, and its rollback would undo both.
				for _, change := range changes {
					if change.Class == state.Migration && change.Path != "/migrationPolicy" {
						unsupported = append(unsupported, "credential rotation must be applied on its own, without "+change.Path)
					}
				}
			}
			if len(unsupported) > 0 {
				p.Mode = ModeMigrationRequired
				p.block("migration", "migration needs an explicit operator procedure", "unsupported changes: "+strings.Join(unsupported, ", "))
			} else if subnet {
				if len(subnetMoves) == 0 {
					p.Mode = ModeMigrationRequired
					p.block("migration", "subnet policy authorizes no move", "provide exact from/to entries for every changed subnet")
				} else {
					p.Mode = ModeSubnetMigrate
				}
			} else if restart {
				p.Mode = ModeRestartMigrate
			} else if seedUsers && seedUserMove == nil {
				p.Mode = ModeMigrationRequired
				p.block("migration", "seedUsers policy authorizes no move", "provide exact from/to entries for bootstrap.seedUsers")
			} else {
				p.Mode = ModeMigrate
			}
			if rotation != nil && !p.Blocked {
				p.add(Action{ID: "rotate-credentials", Disposition: Apply, Mutates: true,
					Summary:  "reissue every per-user credential of " + strings.Join(rotation.Users, ", "),
					Reason:   "migrationPolicy.rotateCredentials " + rotation.ID + " requests it; existing client configurations of these users stop working",
					Proof:    "every rotated credential slot differs, every other user's credentials are byte-identical, and the deployment passes health and self-test",
					Rollback: "restore the previous credential stores and re-apply them through the management API"})
			}
		} else {
			p.Mode = ModeReconcile
		}
		if !runtimeComplete(observed.Runtime) {
			p.Mode = ModeConflict
			p.block("runtime-state", "managed runtime state is incomplete", runtimeSummary(observed.Runtime))
		} else if observed.Runtime.RecreatePending {
			switch p.Mode {
			case ModeReconcile:
				p.Mode = ModeRestartRecover
			case ModeMigrate:
				// A restart is already owed, so applying a compatible live diff
				// through the API would still leave the crash boundary unresolved.
				p.Mode = ModeRestartMigrate
			case ModeSubnetMigrate:
				// Already restart-based; recovery follows the same recreation.
			}
		}
	default:
		p.Mode = ModeConflict
		p.block("desired-state", "unknown desired-state observation", string(observed.ExistingDesired.Status))
	}
}

func (p *Plan) planCredentials(observed discover.Observed) {
	refs := make([]string, 0, len(observed.Credentials))
	for reference := range observed.Credentials {
		refs = append(refs, string(reference))
	}
	sort.Strings(refs)
	for _, name := range refs {
		file := observed.Credentials[state.SecretRef(name)]
		switch file.Status {
		case discover.FileRegular:
			p.add(Action{ID: "credential-" + name, Disposition: Verify, Summary: "use credential " + name, Reason: "desired state contains only this logical reference", Proof: "root-owned regular file with no group/other permissions", Rollback: "none; credential is read-only"})
		case discover.FileAbsent:
			p.block("credential-"+name, "credential is missing: "+name, "create the root-only credential before apply")
		default:
			p.block("credential-"+name, "credential is unsafe: "+name, file.Error)
		}
	}

	paths := make([]string, 0, len(observed.CertificateFiles))
	for path := range observed.CertificateFiles {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for index, path := range paths {
		file := observed.CertificateFiles[path]
		id := fmt.Sprintf("certificate-file-%d", index+1)
		if file.Status == discover.FileRegular {
			p.add(Action{ID: id, Disposition: Verify, Summary: "use certificate material " + path, Reason: "files certificate mode delegates renewal to an external owner", Proof: "path is a regular file", Rollback: "none; file is read-only"})
		} else {
			p.block(id, "certificate material is unavailable: "+path, file.Error)
		}
	}
}

func (p *Plan) planDocker(desired state.State, observed discover.Observed) {
	docker := observed.Docker
	switch {
	case !docker.CLIAvailable:
		if desired.Bootstrap.InstallDocker {
			p.planDockerInstall(observed, false)
		} else {
			p.block("docker", "Docker is not installed", "set bootstrap.installDocker=true or install Docker Engine and the Compose plugin yourself")
		}
	case !docker.DaemonReachable:
		p.block("docker", "Docker daemon is not reachable", docker.Error)
	case !docker.ComposeAvailable:
		if desired.Bootstrap.InstallDocker {
			p.planDockerInstall(observed, true)
		} else {
			p.block("docker-compose", "Docker Compose plugin is unavailable", "install docker-compose-plugin or opt into bootstrap Docker package management")
		}
	default:
		access := "directly"
		if docker.ViaSudo {
			access = "through passwordless sudo"
		}
		p.add(Action{ID: "docker", Disposition: Verify, Summary: "use Docker " + docker.ServerVersion + " " + access, Reason: "Compose remains the source of truth for service lifecycle", Proof: "daemon and Compose version queries succeeded", Rollback: "none; read-only discovery"})
	}
}

// planDockerInstall names the exact packages an apply would install, or why it
// will not install any. Every refusal here is one Installer.Install repeats
// under the lock; seeing it in the plan is what lets an operator fix the host
// before consenting to anything.
func (p *Plan) planDockerInstall(observed discover.Observed, composeOnly bool) {
	id, summary := "docker-install", "install Docker Engine and the Compose plugin"
	if composeOnly {
		id, summary = "docker-compose-install", "install the Docker Compose plugin"
	}
	release, err := dockerinstall.For(observed.Platform.ID, observed.Platform.VersionID)
	if err != nil {
		p.block(id, "Docker cannot be installed on this platform", err.Error())
		return
	}
	install := observed.Docker.Install
	switch {
	case install == nil:
		p.block(id, "Docker installation preconditions were not observed", "rerun discovery with bootstrap.installDocker enabled")
		return
	case install.Error != "":
		p.block(id, "Docker installation preconditions cannot be read", install.Error)
		return
	case len(install.ForeignSources) > 0:
		p.block(id, "a Docker apt repository is already configured", "remove it or install Docker yourself: "+strings.Join(install.ForeignSources, ", "))
		return
	}
	var conflicts []string
	for _, name := range install.Conflicts {
		if !composeOnly || name == "docker-compose" || name == "docker-compose-v2" {
			conflicts = append(conflicts, name)
		}
	}
	if len(conflicts) > 0 {
		p.block(id, "packages that conflict with Docker's are installed", "remove them or install Docker yourself: "+strings.Join(conflicts, ", "))
		return
	}
	p.add(Action{ID: id, Disposition: Apply, Mutates: true,
		Summary:  summary + " from " + dockerinstall.RepositoryHost + ": " + strings.Join(release.Packages(composeOnly), " "),
		Reason:   "desired state opts into platform package installation and the host lacks them",
		Proof:    "the daemon and Compose report exactly the pinned versions",
		Rollback: "none automatic: installed packages and the repository entry are recorded in platform.json, and removing them is the operator's decision"})
}

func (p *Plan) planNetwork(desired state.State, observed discover.Observed) {
	if len(desired.Deployment.XDPInterfaces) != 1 || desired.Deployment.XDPInterfaces[0] != "auto" {
		return
	}
	if observed.Network.DefaultInterface == "" {
		p.block("xdp-interface", "cannot resolve the XDP interface automatically", observed.Network.Error)
		return
	}
	p.add(Action{ID: "xdp-interface", Disposition: Verify, Summary: "resolve XDP auto to " + observed.Network.DefaultInterface, Reason: "the blocker must attach where default-route client traffic arrives", Proof: "preflight confirms the interface exists and is up", Rollback: "none; resolution is read-only"})
}

func (p *Plan) planDeployment() {
	if p.Mode == ModeFresh {
		p.add(Action{ID: "stage-deployment", Disposition: Apply, Mutates: true, Summary: "generate credentials and stage the deployment once", Reason: "this is a fresh tracked install and preflight runs first", Proof: "staged config passes sing-box check", Rollback: "retain credentials and remove only files created by the failed transaction"})
		return
	}
	if p.Mode == ModeReconcile || p.Mode == ModeRestartRecover {
		p.add(Action{ID: "preserve-runtime", Disposition: Verify, Summary: "preserve config.json and secrets.json byte-for-byte", Reason: "the core and bot own live users and keys", Proof: "post-apply digests equal pre-apply digests", Rollback: "restore transaction backups"})
		p.add(Action{ID: "stage-managed-files", Disposition: Apply, Mutates: true, Summary: "render reconcilable Compose and bot files", Reason: "surrounding deployment files converge without regenerating runtime state", Proof: "staged files validate and ownership checks pass", Rollback: "restore the previous managed files"})
		if p.Mode == ModeReconcile {
			p.add(Action{ID: "management-sync", Disposition: Apply, Mutates: true, Summary: "synchronise the running core with config.json", Reason: "an interrupted earlier migration may have rolled its file back after the live API had already applied it", Proof: "the management API accepts the current file and health settles", Rollback: "restore the previous files, start the previous project and synchronise it again"})
		}
	}
	if p.Mode == ModeMigrate {
		p.add(Action{ID: "stage-migration", Disposition: Apply, Mutates: true, Summary: "re-render the live configuration without reissuing credentials", Reason: "config.json is the server-side credential store, including users provisioned by the bot", Proof: "the staged config passes sing-box check and every existing server credential is preserved", Rollback: "restore the previous config and re-apply it through the management API"})
		p.add(Action{ID: "management-apply", Disposition: Apply, Mutates: true, Summary: "apply the configuration diff through the live management API", Reason: "supported inbound and endpoint changes can be made without replacing the running deployment", Proof: "the API accepts the diff, health settles and the live self-test passes", Rollback: "restore the previous config and apply its reverse diff"})
	}
	if p.Mode == ModeRestartMigrate {
		p.add(Action{ID: "stage-restart-migration", Disposition: Apply, Mutates: true, Summary: "re-render the live configuration without reissuing credentials", Reason: "the requested top-level changes are loaded only when the core starts", Proof: "the staged config passes sing-box check and every existing server credential is preserved", Rollback: "restore the previous config and force-recreate the previous Compose project"})
	}
	if p.Mode == ModeSubnetMigrate {
		p.add(Action{ID: "stage-subnet-migration", Disposition: Apply, Mutates: true, Summary: "reassign endpoint and peer addresses while preserving host numbers and every key", Reason: "the exact migration policy authorizes the selected subnet prefixes", Proof: "config.json and secrets.json agree on the moved addresses and all credential material is unchanged", Rollback: "restore both credential stores and force-recreate the previous Compose project"})
	}
}

func (p *Plan) planLogrotate(desired state.State, observed discover.Observed) {
	if !desired.Bootstrap.ManageLogrotate {
		return
	}
	if observed.Logrotate.Status == discover.FileInvalid {
		p.block("logrotate", "logrotate target is not a safe regular file", observed.Logrotate.Error)
		return
	}
	p.add(Action{ID: "logrotate", Disposition: Apply, Mutates: true, Summary: "install or reconcile the logrotate configuration", Reason: "the core's append-only log otherwise grows until the disk fills", Proof: "logrotate --debug accepts the staged configuration", Rollback: "restore the previous owned file or remove the newly created one"})
}

func (p *Plan) planFirewall(desired state.State, observed discover.Observed) {
	if !desired.Bootstrap.ManageFirewall {
		return
	}
	fw := observed.Firewall
	if fw.Kind == "none" || !fw.Active {
		p.add(Action{ID: "firewall", Disposition: Verify, Summary: "make no host-firewall change", Reason: "no active host firewall was detected; provider firewalls remain external", Proof: "external probe is still required", Rollback: "none"})
		return
	}
	if fw.Kind != "ufw" || !fw.Readable {
		p.manualBlock("firewall", "inspect firewall rules manually", "phase 7 can mutate only a readable active UFW backend; found "+fw.Kind)
		return
	}
	var missing []string
	for _, rule := range fw.Required {
		if fw.Rules[rule] != "allowed" {
			missing = append(missing, rule)
		}
	}
	sort.Strings(missing)
	if len(missing) == 0 {
		p.add(Action{ID: "firewall", Disposition: Verify, Summary: "keep existing UFW allow rules", Reason: "all required ports are already allowed", Proof: "UFW reports every required rule", Rollback: "none"})
		return
	}
	p.add(Action{ID: "firewall", Disposition: Apply, Mutates: true, Summary: "add missing UFW allow rules: " + strings.Join(missing, ", "), Reason: "the deployment would start but remain unreachable without them", Proof: "UFW reports each exact port/protocol as allowed", Rollback: "remove only rules recorded as added by this transaction"})
}

func (p *Plan) planDesiredState() {
	if p.Mode == ModeFresh || ((p.Mode == ModeReconcile || p.Mode == ModeMigrate || p.Mode == ModeRestartMigrate || p.Mode == ModeSubnetMigrate || p.Mode == ModeRestartRecover) && len(p.Changes) > 0) {
		p.add(Action{ID: "desired-state", Disposition: Apply, Mutates: true, Summary: "persist canonical desired.json", Reason: "future plans need an immutable operator-intent baseline", Proof: "stored digest equals desiredDigest", Rollback: "restore the previous file or remove the newly created one"})
	} else if p.Mode == ModeReconcile || p.Mode == ModeRestartRecover {
		p.add(Action{ID: "desired-state", Disposition: Verify, Summary: "keep unchanged desired.json", Reason: "the stored intent already has the requested digest", Proof: "stored digest equals desiredDigest", Rollback: "none"})
	}
}

func (p *Plan) planComposeAndHealth() {
	if p.Mode != ModeFresh && p.Mode != ModeReconcile && p.Mode != ModeMigrate && p.Mode != ModeRestartMigrate && p.Mode != ModeSubnetMigrate && p.Mode != ModeRestartRecover {
		return
	}
	p.add(Action{ID: "compose-pull", Disposition: Apply, Mutates: true, Summary: "pull the immutable core image", Reason: "startup and validation must use the image named by desired state", Proof: "local image reference resolves after pull", Rollback: "keep the image; restore the previous Compose reference"})
	if p.Mode != ModeRestartMigrate && p.Mode != ModeSubnetMigrate && p.Mode != ModeRestartRecover {
		p.add(Action{ID: "compose-up", Disposition: Apply, Mutates: true, Summary: "converge the Compose project", Reason: "Compose is the service lifecycle source of truth", Proof: "all expected services remain running through the settle window", Rollback: "restore previous files and run the previous Compose project"})
	} else if p.Mode == ModeRestartRecover {
		p.add(Action{ID: "compose-recreate", Disposition: Apply, Mutates: true, Summary: "force-recreate the deployment from the recovered generation", Reason: "an interrupted restart migration may have left the container running configuration that file recovery already rolled back", Proof: "the recovered deployment becomes healthy and passes the live self-test", Rollback: "restore the previous files and force-recreate the previous project"})
	} else {
		p.add(Action{ID: "compose-recreate", Disposition: Apply, Mutates: true, Summary: "force-recreate the deployment with the migrated configuration", Reason: "Compose does not restart a container when only a bind-mounted config changes", Proof: "the replacement deployment becomes healthy and passes the live self-test", Rollback: "restore the previous files and force-recreate the previous project"})
	}
	p.add(Action{ID: "health", Disposition: Verify, Summary: "wait for the local management endpoint", Reason: "a running container is not proof that the VPN loaded its configuration", Proof: "authenticated localhost management request succeeds", Rollback: "trigger transaction compensation on failure"})
	p.add(Action{ID: "selftest", Disposition: Verify, Summary: "run the live BitTorrent self-test", Reason: "the deployment must prove detection, rejection and cleanup against the running core", Proof: "selftest reports PASS and removes its temporary endpoint", Rollback: "trigger transaction compensation on failure"})
	p.add(Action{ID: "external-checks", Disposition: Manual, Summary: "verify reachability from another network", Reason: "provider firewalls, NAT and ISP filtering are invisible from this host", Proof: "spaiter-vpn probe succeeds externally and a client imports the generated configuration", Rollback: "none; external verification"})
}

// planControl installs the local control daemon when asked. A unit file that
// is not a regular file is refused here; one bootstrap does not own is refused
// by the transaction, which knows the receipt.
func (p *Plan) planControl(desired state.State, observed discover.Observed) {
	if !desired.Bootstrap.ManageControl {
		return
	}
	if observed.ControlUnit != nil && observed.ControlUnit.Status == discover.FileInvalid {
		p.block("control-daemon", "the control daemon's unit path is not a safe regular file", observed.ControlUnit.Error)
		return
	}
	summary := "install and run the local control daemon"
	if desired.Bot.Enabled {
		summary += ", with its socket mounted into the bot"
	}
	p.add(Action{ID: "control-daemon", Disposition: Apply, Mutates: true, Summary: summary,
		Reason:   "bootstrap.manageControl lets unprivileged callers perform typed operations without the Docker socket",
		Proof:    "the daemon answers a status request on its socket",
		Rollback: "stop the daemon and restore or remove its unit file"})
}

// planBotUser runs the bot as its own account. The account is created when it
// is missing; what it may read is narrowed to the management endpoint.
func (p *Plan) planBotUser(desired state.State, observed discover.Observed) {
	if !desired.Bot.Enabled || !desired.Bot.DedicatedUser {
		return
	}
	account := observed.BotUser
	switch {
	case account == nil:
		p.block("bot-user", "the bot's account was not observed", "rerun discovery")
	case account.Error != "":
		p.block("bot-user", "the bot's account cannot be used", account.Error)
	case !account.Exists:
		p.add(Action{ID: "bot-user", Disposition: Apply, Mutates: true,
			Summary:  "create the system account " + account.Name + " and run the bot as it",
			Reason:   "a bot running as root inside its container has more than it needs; as its own account it reads only the management endpoint",
			Proof:    "the account resolves to an unprivileged uid and the bot's state is handed to it",
			Rollback: "none automatic: the account is recorded in platform.json and removing it is the operator's decision"})
	default:
		p.add(Action{ID: "bot-user", Disposition: Verify,
			Summary:  fmt.Sprintf("run the bot as %s (uid %d)", account.Name, account.UID),
			Reason:   "the bot reads only the management endpoint, not the core's keys",
			Proof:    "the bot's state files are owned by that account",
			Rollback: "none; the account is not changed"})
	}
}

// planWeb runs the web UI as its own account, a client of the control daemon.
func (p *Plan) planWeb(desired state.State) {
	if !desired.Bootstrap.ManageWeb {
		return
	}
	p.add(Action{ID: "web-ui", Disposition: Apply, Mutates: true,
		Summary:  "install and run the web UI on " + desired.WebListen() + " as " + deploy.WebUserName,
		Reason:   "bootstrap.manageWeb; it reaches the server only through the control daemon",
		Proof:    "it answers and asks an anonymous visitor to log in",
		Rollback: "stop it and restore or remove its unit; its account and key are kept"})
}

// planDDNS keeps the public name on a changing address.
func (p *Plan) planDDNS(desired state.State) {
	d := desired.DDNS
	if d == nil {
		return
	}
	records := "A"
	if d.IPv6 {
		records = "A and AAAA"
	}
	p.add(Action{ID: "ddns", Disposition: Apply, Mutates: true,
		Summary:  fmt.Sprintf("keep the %s records of %s on this server's public address through %s", records, desired.Bot.PublicHost, d.Provider),
		Reason:   "ddns: the address changes, and clients are given the name",
		Proof:    "its first round finds the address and the provider accepts the token",
		Rollback: "stop it and restore or remove its unit; DNS records are left as they are"})
}

// planBotOwnership names the step that makes a bot without configured admins
// administrable: nobody owns it until a code issued on this host is claimed.
func (p *Plan) planBotOwnership(desired state.State) {
	if !desired.Bot.Enabled || len(desired.Bot.AdminIDs) > 0 {
		return
	}
	p.add(Action{ID: "bot-claim", Disposition: Manual, Summary: "claim the bot's admin role with a one-time code",
		Reason:   "bot.adminIds is empty, and messaging the bot first grants nothing",
		Proof:    "run `spaiter-vpn bot claim-code` on this host and send `/claim <code>` to the bot",
		Rollback: "none; ownership is recorded by the bot"})
}

// supportedMigration names the desired-state changes the core's management
// API can enact by diffing inbounds and endpoints. Tier/domain/certificate
// changes also alter the top-level certificate provider, which that API does
// not reload. Subnet moves would reassign peers; XDP and log changes live
// outside those resources; seed users are an initial-install concept.
func supportedMigration(path string) bool {
	switch path {
	case "/deployment/protocols", "/deployment/realityHandshake",
		"/deployment/shadowTlsHandshake", "/deployment/mtprotoFrontDomain",
		"/deployment/retireSharedMtproto", "/deployment/mtprotoPerUser":
		return true
	}
	return strings.HasPrefix(path, "/deployment/ports/") ||
		strings.HasPrefix(path, "/deployment/mtu/")
}

// restartMigration names changes that are safe to render with preserved
// credentials but sit outside the management API's live resource boundary.
// They take effect only when Compose replaces the core container.
func restartMigration(path string) bool {
	switch path {
	case "/deployment/tier", "/deployment/xdpInterfaces", "/deployment/logLevel",
		"/deployment/domain", "/deployment/certificates":
		return true
	default:
		return false
	}
}

func subnetMigration(path string) bool {
	return path == "/migrationPolicy" || strings.HasPrefix(path, "/deployment/subnets/")
}

func hasSubnetMigrationChange(changes []state.Change) bool {
	for _, change := range changes {
		if subnetMigration(change.Path) {
			return true
		}
	}
	return false
}

func hasMigrationPolicyChange(changes []state.Change) bool {
	for _, change := range changes {
		if change.Path == "/migrationPolicy" {
			return true
		}
	}
	return false
}

func hasSeedUserMigrationChange(changes []state.Change) bool {
	for _, change := range changes {
		if change.Path == "/migrationPolicy" || change.Path == "/bootstrap/seedUsers" {
			return true
		}
	}
	return false
}

func (p *Plan) add(action Action) { p.Actions = append(p.Actions, action) }
func (p *Plan) block(id, summary, reason string) {
	p.Blocked = true
	p.add(Action{ID: id, Disposition: Blocked, Summary: summary, Reason: reason, Proof: "resolve the blocker and recompute the plan", Rollback: "none; apply is refused"})
}
func (p *Plan) manualBlock(id, summary, reason string) {
	p.Blocked = true
	p.add(Action{ID: id, Disposition: Manual, Summary: summary, Reason: reason, Proof: "complete the manual action and recompute the plan", Rollback: "outside bootstrap"})
}

func (p Plan) MarshalIndent() ([]byte, error) {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal bootstrap plan: %w", err)
	}
	return append(data, '\n'), nil
}

func (p Plan) validate() error {
	seen := map[string]bool{}
	for _, action := range p.Actions {
		if action.ID == "" {
			return fmt.Errorf("plan contains an action with no id")
		}
		if seen[action.ID] {
			return fmt.Errorf("plan contains duplicate action id %q", action.ID)
		}
		seen[action.ID] = true
		if action.Disposition == Blocked && !p.Blocked {
			return fmt.Errorf("blocked action %q did not mark the plan blocked", action.ID)
		}
	}
	return nil
}

func runtimePresent(runtime discover.Runtime) bool {
	return runtime.Config.Status != discover.FileAbsent || runtime.Secrets.Status != discover.FileAbsent || runtime.Compose.Status != discover.FileAbsent || runtime.Receipt.Status != discover.FileAbsent
}

func runtimeComplete(runtime discover.Runtime) bool {
	return runtime.Config.Status == discover.FileRegular && runtime.Secrets.Status == discover.FileRegular && runtime.Compose.Status == discover.FileRegular && runtime.Receipt.Status == discover.FileRegular
}

func runtimeSummary(runtime discover.Runtime) string {
	return fmt.Sprintf("config=%s secrets=%s compose=%s receipt=%s", runtime.Config.Status, runtime.Secrets.Status, runtime.Compose.Status, runtime.Receipt.Status)
}
