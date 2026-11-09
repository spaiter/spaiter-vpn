// Package apply executes a consented bootstrap plan.
//
// It is the only place that mutates the host for a bootstrap, and it owns the
// order in which that happens: lock, re-plan, check the host, generate, write
// files inside a crash-recoverable transaction, then start containers. Nothing
// here accepts a shell string or an arbitrary path, so the same engine can sit
// behind the later privileged reconciler without becoming a root-command
// endpoint.
//
// It applies a first install and converges an existing one. Convergence is
// deliberately narrower than "apply whatever the document says": the operator's
// intent is reviewable, while config.json is the authoritative server-side
// credential store, including users the bot provisioned. A convergence leaves
// it alone; a supported migration recovers those credentials and re-renders
// around them. Resource-local diffs go through the management API; top-level
// changes use a journalled, force-recreated Compose generation.
//
// Docker installation is refused by name rather than skipped silently: an apply
// that quietly omits a step the operator just approved is worse than one that
// stops.
package apply

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/dockerinstall"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/health"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/logrotate"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/secret"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	"github.com/spaiter/spaiter-vpn/internal/compose"
	"github.com/spaiter/spaiter-vpn/internal/config"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/firewall"
	"github.com/spaiter/spaiter-vpn/internal/manage"
	"github.com/spaiter/spaiter-vpn/internal/preflight"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// ErrStaleConsent reports that the host changed between the plan the operator
// approved and the plan recomputed under the lock.
var ErrStaleConsent = errors.New("the host changed after the plan was approved")

// ErrNotImplemented reports an approved action this slice cannot perform.
var ErrNotImplemented = errors.New("the plan contains an action this release cannot apply")

// implemented lists the mutating action IDs this slice performs. Keeping it as
// an allowlist rather than a list of exclusions means a future planner action
// is refused until someone implements it, instead of being ignored.
var implemented = map[string]bool{
	"stage-deployment":        true,
	"stage-managed-files":     true,
	"desired-state":           true,
	"compose-pull":            true,
	"compose-up":              true,
	"logrotate":               true,
	"firewall":                true,
	"stage-migration":         true,
	"management-apply":        true,
	"management-sync":         true,
	"stage-restart-migration": true,
	"stage-subnet-migration":  true,
	"control-daemon":          true,
	"web-ui":                  true,
	"ddns":                    true,
	"bot-user":                true,
	"docker-install":          true,
	"docker-compose-install":  true,
	"rotate-credentials":      true,
	"compose-recreate":        true,
}

// Options is everything apply needs. The host-touching parts are interfaces or
// functions so the engine itself is testable without Docker, root or a real
// /etc.
type Options struct {
	Layout  discover.Layout
	Desired state.State

	// Approved is the plan the operator consented to. Apply recomputes it and
	// refuses to act on a plan whose inputs have since changed.
	Approved plan.Plan

	// Discover re-reads host state under the lock.
	Discover func(context.Context, state.State) (discover.Observed, error)

	// Secrets resolves credential references. Apply reads them only after
	// preflight has passed.
	Secrets secret.Store

	// Restore, on a first install, carries the deployment from a backup
	// instead of minting a new one: every key and every user, including the
	// ones the bot added, is recovered from the backed-up configuration and
	// rendered for this host. Nil generates as usual.
	Restore *Restore

	// Compose runs the generated project. Restart migrations use the typed
	// Recreate operation; Down is used only to undo a failed first install.
	Compose compose.Runner

	// CheckConfig validates the generated configuration, normally through
	// sing-box check. Required: an unvalidated config turns a generator bug
	// into a server that does not start.
	CheckConfig func(context.Context, []byte) error

	// Preflight checks the host. Required.
	Preflight func(context.Context, preflight.Options) *preflight.Report

	// Health waits for the started deployment to become usable. Required: a
	// running container is not proof that the core loaded its configuration,
	// and committing the receipt on that evidence would record a broken
	// deployment as the generation to roll back to.
	Health func(context.Context, health.Options) (*health.Report, error)

	// Probe is the authenticated localhost management request the health wait
	// makes. Apply builds it from the generated config when this is nil, which
	// is what a real install wants; tests supply their own.
	Probe func(context.Context) error

	// SelfTest proves detection, rejection and cleanup against the running
	// core. Required for the same reason: nothing else here exercises the
	// deployment's actual purpose.
	SelfTest func(context.Context, io.Writer) error

	// ApplyRuntime asks the running core to diff config.json against its live
	// inbounds and endpoints. Tests inject it; production builds the client
	// from config.json so its address and bearer secret cannot disagree.
	ApplyRuntime func(context.Context) error

	// InstallDocker installs the pinned Docker packages when the approved plan
	// says to. Nil uses dockerinstall.Installer against the real host.
	InstallDocker func(ctx context.Context, release dockerinstall.Release, composeOnly bool) (dockerinstall.Record, error)

	// Systemd manages the control daemon's unit when bootstrap.manageControl
	// is set; nil uses systemctl. ProbeControl replaces the socket check.
	Systemd      Systemd
	ProbeControl func(context.Context) error

	// CreateUser creates a system account; nil runs useradd. LookupUser
	// replaces the system account database.
	CreateUser func(ctx context.Context, name string) error
	LookupUser func(name string) discover.SystemUser
	// LookupGroup and RunAccountCommand replace the group database and
	// groupadd/useradd for the service accounts; ProbeWeb the web UI's check.
	LookupGroup       func(name string) (uint32, bool, error)
	RunAccountCommand func(ctx context.Context, name string, args ...string) error
	ProbeWeb          func(context.Context) error
	// ProbeDDNS replaces waiting for the dynamic DNS updater's first round.
	ProbeDDNS func(context.Context) error

	// botUser is the bot's resolved account once Run has ensured it.
	botUser *fileOwner
	// accounts are the service group and web account once Run has them.
	accounts serviceAccounts

	// HealthTuning overrides the wait's timings. Zero values take the defaults.
	HealthTuning health.Options

	// Firewall adds the missing allow rules. Required when the plan asks for
	// them: a nil applier would mean starting a deployment that is running
	// correctly and reachable by nobody.
	Firewall firewall.Applier

	// ValidateLogrotate parses the generated rotation configuration. Defaults
	// to the real logrotate.
	ValidateLogrotate func(context.Context, []byte) error

	// Strict treats preflight warnings as failures.
	Strict bool

	// BotBinary is the host path to this binary, mounted into the bot's
	// container. Empty resolves to the running executable.
	BotBinary string
	// CheckBotBinary refuses a BotBinary the container cannot run; nil is
	// requireStatic.
	CheckBotBinary func(path string) error

	// SingBoxBinary, when set, replaces the image in preflight's runtime
	// checks.
	SingBoxBinary string

	// Manager performs the file transaction. Apply fills in the allowlist and
	// ownership from the layout when it is nil.
	Manager *transaction.Manager

	// Out receives progress. Never secrets.
	Out io.Writer
}

// Result describes what an apply did. It carries no secret values: the client
// credentials stay in the 0600 file the transaction wrote.
type Result struct {
	Mode        plan.Mode
	Transaction string
	Files       []string
	// Health records what the readiness wait observed.
	Health *health.Report
	// FirewallAdded names the allow rules this apply opened.
	FirewallAdded []string
	// FirewallRetired names the rules it closed because this deployment had
	// opened them earlier and no longer uses them.
	FirewallRetired []string
	// Manual names the checks that cannot be proved from this host.
	Manual []string
}

// Run applies the plan. On any failure after the first host write it restores
// the previous state and reports both the original failure and the outcome of
// that restoration, never one in place of the other.
func Run(ctx context.Context, options Options) (result *Result, err error) {
	if options.Out == nil {
		options.Out = io.Discard
	}
	if options.Discover == nil {
		return nil, fmt.Errorf("apply needs a discovery function")
	}
	if options.Preflight == nil {
		return nil, fmt.Errorf("apply needs a preflight function")
	}
	if options.CheckConfig == nil {
		return nil, fmt.Errorf("apply needs a configuration validator; an unvalidated config is not installable")
	}
	if options.Compose == nil {
		return nil, fmt.Errorf("apply needs a compose runner")
	}
	if options.Health == nil {
		options.Health = health.Wait
	}
	if options.SelfTest == nil {
		return nil, fmt.Errorf("apply needs a self-test; a started container is not evidence that the deployment works")
	}
	if options.ValidateLogrotate == nil {
		options.ValidateLogrotate = logrotate.Validate
	}
	manager := options.Manager
	if manager == nil {
		manager = &transaction.Manager{
			StateDir:       options.Layout.BootstrapStateDir(),
			AllowedTargets: options.Layout.ManagedFiles(),
		}
	}
	botTargets, err := options.Layout.BotTransactionTargets()
	if err != nil {
		return nil, err
	}
	manager.AllowedTargets = appendUniquePaths(manager.AllowedTargets, botTargets...)
	for _, delegation := range options.Layout.BotDelegations(options.lookupUser(deploy.BotUserName), options.Desired.Bot.WDTTConfigDirectory) {
		manager.Delegated = append(manager.Delegated, transaction.Delegation{Root: delegation.Root, UID: delegation.UID, GID: delegation.GID})
	}
	if options.Desired.Bot.WDTTConfigDirectory != "" {
		wdttBot := deploy.Bot{
			DataDir:             options.Layout.BotDataDir(),
			WDTTConfigDirectory: options.Desired.Bot.WDTTConfigDirectory,
		}
		manager.AllowedTargets = appendUniquePaths(manager.AllowedTargets,
			wdttBot.WDTTPasswordsPath(), wdttBot.WDTTReloadMarkerPath())
	}

	guard, err := manager.Lock()
	if err != nil {
		return nil, err
	}
	defer guard.Release()

	current, err := options.recomputePlan(ctx)
	if err != nil {
		return nil, err
	}
	switch current.Mode {
	case plan.ModeFresh, plan.ModeReconcile, plan.ModeMigrate, plan.ModeRestartMigrate, plan.ModeSubnetMigrate, plan.ModeRestartRecover:
	default:
		return nil, fmt.Errorf("apply handles a first install, convergence and supported migration; the recomputed plan is %q", current.Mode)
	}
	if err := refuseUnimplemented(current.Plan); err != nil {
		return nil, err
	}
	if current, err = options.installDockerIfPlanned(ctx, current); err != nil {
		return nil, err
	}

	// Preflight before generation. Minting a deployment's worth of private keys
	// and only then discovering a port is taken leaves the operator holding
	// credentials for a server that never starts.
	resolvedXDP := resolveXDP(options.Desired, current.observed)
	if err := options.runPreflight(ctx, resolvedXDP, current.Mode); err != nil {
		return nil, err
	}
	if err := options.validateWDTTConfigPath(); err != nil {
		return nil, err
	}

	// A subnet or seedUsers migration reads and rewrites runtime user/peer
	// state, so the bot must stop writing it BEFORE it is read, not merely
	// before it is written: a peer the bot created between the read and the
	// stop would be left out of the transaction, and one it deleted would be
	// resurrected by our write. Until the transaction exists nothing else
	// will bring the bot back, so a failure on the way there restarts it.
	var subnetMigrations map[profile.Protocol]state.SubnetMigration
	var seedUserMigration *state.SeedUsersMigration
	var rotation *state.CredentialRotation
	if current.observed.ExistingDesired.State != nil {
		subnetMigrations, err = options.Desired.AuthorizedSubnetMigrations(*current.observed.ExistingDesired.State)
		if err != nil {
			return nil, err
		}
		seedUserMigration, err = options.Desired.AuthorizedSeedUserMigration(*current.observed.ExistingDesired.State)
		if err != nil {
			return nil, err
		}
		rotation, err = options.Desired.AuthorizedCredentialRotation(*current.observed.ExistingDesired.State)
		if err != nil {
			return nil, err
		}
	}
	txStarted := false
	if (current.Mode == plan.ModeSubnetMigrate || seedUserMigration != nil || rotation != nil) && current.observed.ExistingDesired.State != nil && current.observed.ExistingDesired.State.Bot.Enabled {
		if err := options.Compose.StopService(ctx, options.Layout.ComposePath(), deploy.BotServiceName, options.Out, options.Out); err != nil {
			return nil, errors.Join(
				fmt.Errorf("quiesce bot state before migration: %w", err),
				options.restartBot(ctx),
			)
		}
		fmt.Fprintln(options.Out, "bot: stopped while peer state is migrated")
		defer func() {
			if err != nil && !txStarted {
				err = errors.Join(err, options.restartBot(ctx))
			}
		}()
	}

	spec, err := options.Desired.DeploymentSpec(resolvedXDP, options.Secrets.Resolver())
	if err != nil {
		return nil, err
	}
	// Generate once on a first install. A migration instead recovers every
	// server-side credential from config.json and re-renders the requested
	// shape around it; secrets.json is only the original handover snapshot.
	//
	// A convergence validates the live config and leaves it alone. Calling the
	// generator again would mint a new set of private keys and a new clash
	// secret, and writing those over a running deployment would lock out every
	// user it has.
	var rendered *profile.Rendered
	var preserved *runtimeState
	if current.Mode == plan.ModeFresh && options.Restore != nil {
		if rendered, err = options.renderRestored(ctx, spec); err != nil {
			return nil, err
		}
	} else if current.Mode == plan.ModeFresh {
		if rendered, err = profile.Render(ctx, spec); err != nil {
			return nil, err
		}
		if err := options.CheckConfig(ctx, rendered.ConfigJSON); err != nil {
			return nil, fmt.Errorf("the generated configuration is not usable: %w", err)
		}
		fmt.Fprintln(options.Out, "generated configuration: validated")
	} else {
		if preserved, err = options.readRuntimeState(ctx); err != nil {
			return nil, err
		}
		if current.Mode == plan.ModeMigrate || current.Mode == plan.ModeRestartMigrate || current.Mode == plan.ModeSubnetMigrate {
			var migratedSecrets []byte
			if current.Mode == plan.ModeSubnetMigrate {
				if len(subnetMigrations) == 0 {
					return nil, fmt.Errorf("subnet migration plan has no active subnet migration policy")
				}
				migratedSecrets, preserved.subnetChanges, err = options.migrateSubnets(preserved, manager, subnetMigrations)
				if err != nil {
					return nil, err
				}
			}
			spec.Users = preserved.credentials.Names()
			if seedUserMigration != nil {
				var seedUserChanges []transaction.Change
				spec.Users, seedUserChanges, err = options.prepareSeedUserMigration(preserved, *seedUserMigration, manager, current.Mode == plan.ModeSubnetMigrate)
				if err != nil {
					return nil, err
				}
				preserved.subnetChanges = append(preserved.subnetChanges, seedUserChanges...)
			}
			var pendingRotation *pendingRotation
			if rotation != nil {
				if current.Mode != plan.ModeMigrate && current.Mode != plan.ModeRestartMigrate {
					return nil, fmt.Errorf("credential rotation runs as its own migration; the recomputed plan is %q", current.Mode)
				}
				if pendingRotation, err = options.prepareCredentialRotation(preserved, *rotation); err != nil {
					return nil, err
				}
			}
			for _, change := range preserved.subnetChanges {
				manager.AllowedTargets = appendUniquePaths(manager.AllowedTargets, change.Path)
			}
			// Users the bot provisioned keep what they hold and are issued
			// nothing new: the bot mints their accounts and peers on demand and
			// stores the private halves, which a peer minted here would lack.
			// Rotated users are reissued exactly the slots they held.
			spec.Mint = map[string]map[string]bool{}
			for _, name := range spec.Users {
				if !slices.Contains(options.Desired.Bootstrap.SeedUsers, name) {
					spec.Mint[name] = map[string]bool{}
				}
			}
			if pendingRotation != nil {
				for _, user := range pendingRotation.before.Users {
					if pendingRotation.users[user.Name] {
						spec.Mint[user.Name] = user.HeldSlots()
					}
				}
			}
			bundle, regenErr := profile.Regenerate(spec, preserved.credentials)
			if regenErr != nil {
				return nil, fmt.Errorf("re-render the live configuration: %w", regenErr)
			}
			if seedUserMigration != nil {
				migratedSecrets, err = finishSeedUserMigration(preserved, bundle.Secrets, *seedUserMigration)
				if err != nil {
					return nil, err
				}
				preserved.users = len(bundle.Secrets.Users)
			}
			if pendingRotation != nil {
				var rotationChanges []transaction.Change
				migratedSecrets, rotationChanges, err = options.finishCredentialRotation(preserved, pendingRotation, bundle.Secrets, manager)
				if err != nil {
					return nil, err
				}
				for _, change := range rotationChanges {
					manager.AllowedTargets = appendUniquePaths(manager.AllowedTargets, change.Path)
				}
				preserved.subnetChanges = append(preserved.subnetChanges, rotationChanges...)
				preserved.rotated = append([]string(nil), rotation.Users...)
				fmt.Fprintf(options.Out, "credential rotation %s: reissued %s\n", rotation.ID, strings.Join(rotation.Users, ", "))
			}
			refreshed, refreshErr := refreshHandover(preserved.handover, bundle.Secrets)
			if refreshErr != nil {
				return nil, refreshErr
			}
			refreshedJSON, marshalErr := json.MarshalIndent(refreshed, "", "  ")
			if marshalErr != nil {
				return nil, marshalErr
			}
			refreshedJSON = append(refreshedJSON, '\n')
			if digestOf(refreshedJSON) != preserved.secretsDigest || migratedSecrets != nil {
				migratedSecrets = refreshedJSON
				preserved.handover = refreshed
				preserved.expectedSecretsDigest = digestOf(refreshedJSON)
			}
			configJSON, marshalErr := config.Marshal(ctx, bundle.Options)
			if marshalErr != nil {
				return nil, marshalErr
			}
			rendered = &profile.Rendered{Bundle: bundle, ConfigJSON: configJSON, SecretsJSON: migratedSecrets}
			if err := options.CheckConfig(ctx, rendered.ConfigJSON); err != nil {
				return nil, fmt.Errorf("the migrated configuration is not usable: %w", err)
			}
			fmt.Fprintf(options.Out, "migrated configuration: validated, %d live users preserved\n", preserved.users)
		} else {
			// Validated against the image the convergence is moving to: an image
			// that no longer accepts the live configuration would otherwise be
			// found out by the container failing to start.
			if err := options.CheckConfig(ctx, preserved.config); err != nil {
				return nil, fmt.Errorf("the live configuration is not usable with the requested image: %w", err)
			}
			fmt.Fprintf(options.Out, "live configuration: validated, %d live users to preserve\n", preserved.users)
		}
	}

	// The bot's account exists before anything names it: the compose file
	// runs the bot as it and the state files below are handed to it.
	owner := fileOwner{uid: manager.UID, gid: manager.GID}
	if options.dedicatedBot() {
		if owner, err = options.ensureBotUser(ctx); err != nil {
			return nil, err
		}
		options.botUser = &owner
		// Delegations were derived before the account existed; the first
		// isolation creates it here and then hands directories to it, which a
		// rollback must still be able to write into.
		for _, delegation := range options.Layout.BotDelegations(options.lookupUser(deploy.BotUserName), options.Desired.Bot.WDTTConfigDirectory) {
			manager.Delegated = append(manager.Delegated, transaction.Delegation{Root: delegation.Root, UID: delegation.UID, GID: delegation.GID})
		}
	}
	accounts, err := options.ensureServiceAccounts(ctx)
	if err != nil {
		return nil, err
	}
	options.accounts = accounts
	params, err := options.deployParams(spec, resolvedXDP)
	if err != nil {
		return nil, err
	}
	artifacts, err := deploy.Render(params)
	if err != nil {
		return nil, err
	}
	if options.Desired.Bootstrap.ManageLogrotate {
		if err := options.ValidateLogrotate(ctx, artifacts.Logrotate.Data); err != nil {
			if errors.Is(err, logrotate.ErrUnavailable) {
				// Not fatal: the host has no logrotate to validate with, and
				// installing a file for a tool that is absent changes nothing.
				// Said out loud rather than passed over, because the operator
				// asked for rotation and is not getting it.
				fmt.Fprintln(options.Out, "logrotate: not installed, so the generated configuration was not validated and rotation will not run")
			} else {
				return nil, err
			}
		} else {
			fmt.Fprintln(options.Out, "logrotate: configuration accepted")
		}
	}
	// The last receipt is what makes retirement possible: it names the rules
	// this deployment opened, which is the only safe basis for closing one.
	previousReceipt, _, err := manager.Current()
	if err != nil {
		return nil, fmt.Errorf("read the recorded firewall ownership: %w", err)
	}
	firewallWork, err := options.planFirewall(current.observed, previousReceipt)
	if err != nil {
		return nil, err
	}

	desiredJSON, err := canonicalDesiredJSON(options.Desired)
	if err != nil {
		return nil, err
	}
	var extraChanges []transaction.Change
	if preserved != nil {
		extraChanges = preserved.subnetChanges
	}
	unitPlans, controlChanges, err := options.planUnits(manager, previousReceipt, params.Bot.Binary, accounts)
	if err != nil {
		return nil, err
	}
	for _, change := range controlChanges {
		manager.AllowedTargets = appendUniquePaths(manager.AllowedTargets, change.Path)
	}
	extraChanges = append(append([]transaction.Change(nil), extraChanges...), controlChanges...)
	changes, err := options.changes(manager, current.Mode, desiredJSON, rendered, artifacts, extraChanges)
	if err != nil {
		return nil, err
	}
	var coreConfig []byte
	if rendered != nil {
		coreConfig = rendered.ConfigJSON
	} else if preserved != nil {
		coreConfig = preserved.config
	}
	managementChanges, err := options.managementChange(manager, previousReceipt, coreConfig, owner)
	if err != nil {
		return nil, err
	}
	changes = append(changes, managementChanges...)
	if options.Desired.Bot.Enabled {
		if changes, err = options.botStateChanges(changes, previousReceipt, owner); err != nil {
			return nil, err
		}
	}
	botFiles := map[string]bool{}
	for path := range previousReceipt.Files {
		botFiles[path] = true
	}
	for _, change := range changes {
		manager.AllowedTargets = appendUniquePaths(manager.AllowedTargets, change.Path)
		botFiles[change.Path] = true
	}

	// Directories the containers bind-mount. Created before the transaction
	// because Docker creates a DIRECTORY where a missing bind source should be
	// a file, which silently breaks the reload marker, and because an empty
	// directory left behind by a rollback is harmless while a wrongly typed
	// mount point is not.
	if err := options.prepareRuntimeDirectories(manager, params); err != nil {
		return nil, err
	}

	tx, err := guard.Start(changes)
	if err != nil {
		return nil, err
	}
	// From here a failure is undone by the compensation, whose force-recreate
	// of the previous generation brings the bot back with everything else.
	txStarted = true
	undo := &compensation{tx: tx, mode: current.Mode, units: unitPlans}
	// A retired unit is stopped while its file still exists: disabling a unit
	// whose file is already gone fails.
	if err := options.stopRetired(ctx, unitPlans); err != nil {
		return nil, errors.Join(err, undo.run(ctx, options))
	}
	if err := tx.Apply(); err != nil {
		return nil, errors.Join(err, undo.run(ctx, options))
	}
	fmt.Fprintf(options.Out, "wrote %d managed files\n", len(changes))
	if options.Desired.Bot.Enabled {
		if err := options.chownBotState(botFiles, owner); err != nil {
			return nil, errors.Join(err, undo.run(ctx, options))
		}
	}

	// Written down before any of it happens. A process that dies between
	// opening a port and committing would otherwise leave that port open and
	// owned by nobody, and no later apply could tell it from a rule the
	// operator opened — so it could never be retired.
	if err := tx.PlanFirewall(rulesAsText(firewallWork.add), rulesAsText(firewallWork.retire)); err != nil {
		return nil, errors.Join(fmt.Errorf("record the intended firewall changes: %w", err), undo.run(ctx, options))
	}

	// After the files, before the containers. The deployment would start and be
	// reachable by nobody otherwise, and each change is recorded so a failure
	// undoes exactly what this apply did and nothing else.
	for _, rule := range firewallWork.add {
		if err := options.Firewall.Add(ctx, rule); err != nil {
			return nil, errors.Join(fmt.Errorf("open %s: %w", rule, err), undo.run(ctx, options))
		}
		undo.added = append(undo.added, rule)
		fmt.Fprintf(options.Out, "firewall: allowed %s\n", rule)
	}
	// Closed after opening, so a port that is both wanted and recorded is
	// never briefly shut, and so a migration that moves a listener opens the
	// new door before closing the old one.
	for _, rule := range firewallWork.retire {
		if err := options.Firewall.Remove(ctx, rule); err != nil {
			return nil, errors.Join(fmt.Errorf("close %s: %w", rule, err), undo.run(ctx, options))
		}
		undo.retired = append(undo.retired, rule)
		fmt.Fprintf(options.Out, "firewall: closed %s, which this deployment no longer uses\n", rule)
	}
	tx.SetFirewall(firewallWork.owned)

	if err := options.Compose.Pull(ctx, options.Layout.ComposePath(), options.Out, options.Out); err != nil {
		return nil, errors.Join(fmt.Errorf("pull the core image: %w", err), undo.run(ctx, options))
	}
	if current.Mode == plan.ModeRestartMigrate || current.Mode == plan.ModeSubnetMigrate || current.Mode == plan.ModeRestartRecover {
		if err := tx.PlanRecreate(); err != nil {
			return nil, errors.Join(fmt.Errorf("record the intended container recreation: %w", err), undo.run(ctx, options))
		}
		if err := options.Compose.Recreate(ctx, options.Layout.ComposePath(), options.Out, options.Out); err != nil {
			return nil, errors.Join(fmt.Errorf("recreate the compose project: %w", err), undo.run(ctx, options))
		}
	} else if err := options.Compose.Up(ctx, options.Layout.ComposePath(), options.Out, options.Out); err != nil {
		return nil, errors.Join(fmt.Errorf("start the compose project: %w", err), undo.run(ctx, options))
	}
	if current.Mode == plan.ModeReconcile || current.Mode == plan.ModeMigrate {
		if err := options.applyRuntime(ctx); err != nil {
			return nil, errors.Join(fmt.Errorf("synchronise the running configuration: %w", err), undo.run(ctx, options))
		}
		fmt.Fprintln(options.Out, "management API: running configuration synchronised")
	}
	if err := options.applyUnits(ctx, unitPlans); err != nil {
		return nil, errors.Join(err, undo.run(ctx, options))
	}

	// Proof before the receipt. The receipt names the generation a later
	// rollback restores, so recording one for a deployment that never answered
	// would make the broken state the thing we roll back TO.
	waited, err := options.waitHealthy(ctx, params.Services())
	if err != nil {
		return nil, errors.Join(err, undo.run(ctx, options))
	}
	if err := options.SelfTest(ctx, options.Out); err != nil {
		return nil, errors.Join(fmt.Errorf("self-test: %w", err), undo.run(ctx, options))
	}
	fmt.Fprintln(options.Out, "self-test: passed")

	// The preservation proof goes before the receipt, like every other proof:
	// a generation recorded after the credentials were disturbed would be the
	// generation a rollback restores.
	if preserved != nil {
		if err := options.verifyPreserved(preserved, current.Mode); err != nil {
			return nil, errors.Join(err, undo.run(ctx, options))
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("record the apply receipt: %w", err)
	}

	result = &Result{
		Mode:            current.Mode,
		Transaction:     tx.ID(),
		Files:           changedPaths(changes),
		Health:          waited,
		FirewallAdded:   rulesAsText(undo.added),
		FirewallRetired: rulesAsText(undo.retired),
	}
	for _, action := range current.Actions {
		if action.Disposition == plan.Manual {
			result.Manual = append(result.Manual, action.ID)
		}
	}
	return result, nil
}

func (o Options) validateWDTTConfigPath() error {
	dir := o.Desired.Bot.WDTTConfigDirectory
	if dir == "" {
		return nil
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect bot.wdttConfigDirectory %s: %w", dir, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("bot.wdttConfigDirectory %s is not a real directory", dir)
	}
	path := filepath.Join(dir, "passwords.json")
	info, err = os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect WG-over-VK relay passwords %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("WG-over-VK relay passwords %s is not a regular file", path)
	}
	return nil
}

// restartBot brings a quiesced bot back when an apply fails before its
// transaction exists. Nothing was written yet, so `up` against the unchanged
// project restarts exactly the stopped service; the error is reported in its
// own right because "migration refused" and "migration refused and the bot is
// still down" ask different things of an operator.
func (o Options) restartBot(ctx context.Context) error {
	if err := o.Compose.Up(ctx, o.Layout.ComposePath(), o.Out, o.Out); err != nil {
		return fmt.Errorf("restart the quiesced bot: %w", err)
	}
	fmt.Fprintln(o.Out, "bot: restarted, nothing was migrated")
	return nil
}

func appendUniquePaths(existing []string, additions ...string) []string {
	seen := make(map[string]bool, len(existing)+len(additions))
	for _, path := range existing {
		seen[path] = true
	}
	for _, path := range additions {
		if !seen[path] {
			existing = append(existing, path)
			seen[path] = true
		}
	}
	return existing
}

type recomputed struct {
	plan.Plan
	observed discover.Observed
}

// recomputePlan re-reads the host under the lock and refuses consent that no
// longer describes it. Without this, a plan reviewed minutes ago could be
// applied against a host where a port was taken, a credential was removed or
// another deployment appeared.
func (o Options) recomputePlan(ctx context.Context) (recomputed, error) {
	observed, err := o.Discover(ctx, o.Desired)
	if err != nil {
		return recomputed{}, err
	}
	current, err := plan.Build(o.Desired, observed)
	if err != nil {
		return recomputed{}, err
	}
	if current.Blocked {
		var blockers []string
		for _, action := range current.Actions {
			if action.Disposition == plan.Blocked || action.Disposition == plan.Manual && current.Blocked && action.Rollback == "outside bootstrap" {
				blockers = append(blockers, fmt.Sprintf("%s: %s (%s)", action.ID, action.Summary, action.Reason))
			}
		}
		return recomputed{}, fmt.Errorf("the plan is blocked:\n  %s", strings.Join(blockers, "\n  "))
	}
	if o.Approved.APIVersion == "" {
		return recomputed{}, fmt.Errorf("apply needs the approved plan; stdin not being a terminal is not consent")
	}
	if current.DesiredDigest != o.Approved.DesiredDigest {
		return recomputed{}, fmt.Errorf("%w: desired state digest is %s, approved %s", ErrStaleConsent, current.DesiredDigest, o.Approved.DesiredDigest)
	}
	if current.ObservationDigest != o.Approved.ObservationDigest {
		return recomputed{}, fmt.Errorf("%w: host observation digest is %s, approved %s; review the plan again", ErrStaleConsent, current.ObservationDigest, o.Approved.ObservationDigest)
	}
	return recomputed{Plan: current, observed: observed}, nil
}

// installDockerIfPlanned runs the approved package installation before
// preflight, which needs a working daemon, and then observes the host again.
//
// The consent covered installing Docker and nothing else, so the new
// observation may differ from the approved one only in what Docker reports.
// Anything else that moved in the meantime is the stale-consent refusal every
// other apply gets.
func (o Options) installDockerIfPlanned(ctx context.Context, current recomputed) (recomputed, error) {
	composeOnly := false
	planned := false
	for _, action := range current.Actions {
		switch action.ID {
		case "docker-install":
			planned = action.Disposition == plan.Apply
		case "docker-compose-install":
			planned, composeOnly = action.Disposition == plan.Apply, true
		}
	}
	if !planned {
		return current, nil
	}
	release, err := dockerinstall.For(current.observed.Platform.ID, current.observed.Platform.VersionID)
	if err != nil {
		return current, err
	}
	install := o.InstallDocker
	if install == nil {
		install = func(ctx context.Context, release dockerinstall.Release, composeOnly bool) (dockerinstall.Record, error) {
			return dockerinstall.Installer{Out: o.Out}.Install(ctx, release, composeOnly)
		}
	}
	record, installErr := install(ctx, release, composeOnly)
	// Recorded even when the proof afterwards failed: the packages are on the
	// host either way, and an operator deciding what to remove needs to know.
	if len(record.Packages) > 0 {
		if err := dockerinstall.WriteRecord(o.Layout.PlatformRecordPath(), record); err != nil {
			return current, errors.Join(installErr, fmt.Errorf("record the Docker installation: %w", err))
		}
	}
	if installErr != nil {
		return current, fmt.Errorf("install Docker: %w", installErr)
	}

	observed, err := o.Discover(ctx, o.Desired)
	if err != nil {
		return current, err
	}
	if !sameExceptDocker(current.observed, observed) {
		return current, fmt.Errorf("%w: the host changed beyond the Docker installation while it ran; review the plan again", ErrStaleConsent)
	}
	rebuilt, err := plan.Build(o.Desired, observed)
	if err != nil {
		return current, err
	}
	if rebuilt.Blocked || rebuilt.Mode != current.Mode {
		return current, fmt.Errorf("after installing Docker the plan is %q (blocked=%v), not the approved %q; review it again", rebuilt.Mode, rebuilt.Blocked, current.Mode)
	}
	for _, action := range rebuilt.Actions {
		if action.ID == "docker-install" || action.ID == "docker-compose-install" {
			return current, fmt.Errorf("Docker still reports missing components after installation: %s", action.Summary)
		}
	}
	return recomputed{Plan: rebuilt, observed: observed}, nil
}

func sameExceptDocker(a, b discover.Observed) bool {
	a.Docker, b.Docker = discover.Docker{}, discover.Docker{}
	left, errA := json.Marshal(a)
	right, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(left, right)
}

func refuseUnimplemented(current plan.Plan) error {
	var unsupported []string
	for _, action := range current.Actions {
		if action.Disposition == plan.Apply && !implemented[action.ID] {
			unsupported = append(unsupported, action.ID)
		}
	}
	if len(unsupported) == 0 {
		return nil
	}
	sort.Strings(unsupported)
	return fmt.Errorf("%w: %s; turn the corresponding desired-state option off to apply the rest, or wait for the slice that implements it",
		ErrNotImplemented, strings.Join(unsupported, ", "))
}

// resolveXDP turns the desired "auto" into the interface discovery found. An
// empty result is not substituted with a guess: the planner blocks on it, and
// silently generating a config with no XDP interface would disable the blocker
// while reporting success.
func resolveXDP(desired state.State, observed discover.Observed) []string {
	if len(desired.Deployment.XDPInterfaces) != 1 || desired.Deployment.XDPInterfaces[0] != "auto" {
		return append([]string(nil), desired.Deployment.XDPInterfaces...)
	}
	if observed.Network.DefaultInterface == "" {
		return nil
	}
	return []string{observed.Network.DefaultInterface}
}

func (o Options) runPreflight(ctx context.Context, resolvedXDP []string, mode plan.Mode) error {
	spec, err := o.Desired.PreflightSpec(resolvedXDP)
	if err != nil {
		return err
	}
	report := o.Preflight(ctx, preflight.Options{
		Spec:          spec,
		ConfigDir:     o.Layout.DeploymentDir(),
		CacheDir:      o.Layout.CacheDir(),
		Image:         o.Desired.Deployment.Image,
		SingBoxBinary: o.SingBoxBinary,
		// Preflight runs before anything is written, so the rotation it looks
		// for cannot be there yet. Saying so is what stops the check from
		// aborting the apply that installs it.
		LogrotateWillBeInstalled: o.Desired.Bootstrap.ManageLogrotate,
		FirewallRulesWillBeAdded: o.Desired.Bootstrap.ManageFirewall && o.Firewall != nil,
		// While converging, this deployment's own listeners are bound by the
		// deployment being converged, not by something in the way of it.
		OwnDeploymentRunning: mode == plan.ModeReconcile || mode == plan.ModeMigrate || mode == plan.ModeRestartMigrate || mode == plan.ModeSubnetMigrate || mode == plan.ModeRestartRecover,
	})
	if err := report.Err(o.Strict); err != nil {
		report.Write(o.Out)
		return fmt.Errorf("%w\n\nNothing was written and no credential was generated", err)
	}
	if report.Count(preflight.Warn) > 0 || report.Count(preflight.Unknown) > 0 {
		report.Write(o.Out)
	} else {
		fmt.Fprintf(o.Out, "preflight: %d checks passed\n", report.Count(preflight.Pass))
	}
	return nil
}

// requireStatic refuses a binary the bot's container could not start: it is
// mounted into an image with no C library, where a dynamically linked binary
// fails with "no such file or directory" and the bot restarts forever.
func requireStatic(binary string) error {
	file, err := elf.Open(binary)
	if err != nil {
		return fmt.Errorf("inspect %s, which the bot service runs: %w", binary, err)
	}
	defer file.Close()
	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			return fmt.Errorf("%s is dynamically linked and cannot run inside the bot's container; use a release build (CGO_ENABLED=0)", binary)
		}
	}
	return nil
}

func (o Options) deployParams(spec profile.Spec, resolvedXDP []string) (deploy.Params, error) {
	binary := o.BotBinary
	if binary == "" {
		executable, err := os.Executable()
		if err != nil {
			return deploy.Params{}, fmt.Errorf("locate this binary for the bot service: %w", err)
		}
		binary = executable
	}
	if o.Desired.Bot.Enabled {
		check := o.CheckBotBinary
		if check == nil {
			check = requireStatic
		}
		if err := check(binary); err != nil {
			return deploy.Params{}, err
		}
	}
	controlDir := ""
	if o.Desired.Bootstrap.ManageControl && o.Desired.Bot.Enabled {
		controlDir = deploy.ControlSocketDir
	}
	botAccount, managementFile := "", ""
	if o.botUser != nil {
		botAccount = fmt.Sprintf("%d:%d", o.botUser.uid, o.botUser.gid)
		managementFile = o.Layout.BotManagementPath()
	}
	webKey, webURL := "", ""
	if o.Desired.Bootstrap.ManageWeb {
		webKey, webURL = o.Layout.WebKeyPath(), o.Desired.WebURL()
	}
	var serviceGID uint32
	if o.botUser != nil {
		serviceGID = o.accounts.gid
	}
	bot := deploy.Bot{
		ServiceGID:          serviceGID,
		WebKey:              webKey,
		WebURL:              webURL,
		User:                botAccount,
		TelegramAPIURL:      o.Desired.Bot.TelegramAPIURL,
		ManagementFile:      managementFile,
		ControlSocketDir:    controlDir,
		Enabled:             o.Desired.Bot.Enabled,
		Binary:              binary,
		DataDir:             o.Layout.BotDataDir(),
		WDTTConfigDirectory: o.Desired.Bot.WDTTConfigDirectory,
		AdminIDs:            append([]int64(nil), o.Desired.Bot.AdminIDs...),
		PublicHost:          o.Desired.Bot.PublicHost,
		SubHostCF:           o.Desired.Bot.SubscriptionHost,
		PublicIPv4Host:      o.Desired.Bot.PublicIPv4Host,
		CDNHost:             o.Desired.Bot.CDNHost,
		SubHostDirect:       o.Desired.Bot.DirectSubscriptionHost,
		SubPort:             o.Desired.Bot.SubscriptionPort,
	}
	params := deploy.Params{
		Image:         o.Desired.Deployment.Image,
		ConfigDir:     o.Layout.DeploymentDir(),
		CacheDir:      o.Layout.CacheDir(),
		XDPInterfaces: resolvedXDP,
		Bot:           bot,
	}
	// The sidecar watches the marker the bot writes, derived from one place so
	// the two cannot be configured into silent disagreement.
	if bot.Enabled {
		params.Reload = deploy.Reload{
			Enabled:     true,
			MarkerPath:  bot.ReloadMarkerPath(),
			PollSeconds: deploy.DefaultPollSeconds,
		}
	}
	if spec.Certs.Source == profile.CertSourceFiles {
		params.CertificateDir = filepath.Dir(spec.Certs.CertificatePath)
	}
	return params, nil
}

// waitHealthy proves the started deployment is usable.
//
// The probe is built from the config that was just written rather than from
// anything the operator typed: the clash API address and secret come from the
// same file the core reads, so the check cannot be passing against a different
// endpoint than the one that is running.
func (o Options) waitHealthy(ctx context.Context, services []string) (*health.Report, error) {
	probe := o.Probe
	if probe == nil {
		client, err := manage.NewFromCoreConfig(o.Layout.ConfigPath())
		if err != nil {
			return nil, fmt.Errorf("build the management probe: %w", err)
		}
		probe = client.Version
	}
	options := o.HealthTuning
	options.Project = o.Layout.ComposePath()
	options.Services = services
	options.Compose = o.Compose
	options.Probe = probe
	options.Out = o.Out
	options.Redact = o.redactor()
	return o.Health(ctx, options)
}

func (o Options) applyRuntime(ctx context.Context) error {
	if o.ApplyRuntime != nil {
		return o.ApplyRuntime(ctx)
	}
	client, err := manage.NewFromCoreConfig(o.Layout.ConfigPath())
	if err != nil {
		return err
	}
	// A container Compose just recreated, for a new image say, is not
	// listening yet. Only a refused connection is retried: an answer that
	// rejects the config is the failure it reports.
	deadline := time.Now().Add(60 * time.Second)
	for {
		_, err = client.Apply(ctx)
		if err == nil || !errors.Is(err, syscall.ECONNREFUSED) || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// redactor scrubs the credentials this deployment holds out of captured logs. A
// container that fails to start often prints the environment it was handed, and
// the bot's contains a Telegram token.
func (o Options) redactor() func(string) string {
	var values []string
	for _, reference := range o.credentialRefs() {
		value, err := o.Secrets.Read(reference)
		if err != nil {
			continue
		}
		values = append(values, value)
	}
	if len(values) == 0 {
		return nil
	}
	return func(text string) string { return secret.Redact(text, values...) }
}

func (o Options) credentialRefs() []state.SecretRef {
	var refs []state.SecretRef
	if o.Desired.Bot.Enabled {
		refs = append(refs, o.Desired.Bot.TelegramToken)
	}
	if o.Desired.DDNS != nil {
		refs = append(refs, o.Desired.DDNS.Token)
	}
	if certs := o.Desired.Deployment.Certificates; certs != nil && certs.ACMEDNS != nil {
		if certs.ACMEDNS.Cloudflare != nil {
			refs = append(refs, certs.ACMEDNS.Cloudflare.APIToken)
		}
		if certs.ACMEDNS.Account != nil {
			refs = append(refs, certs.ACMEDNS.Account.Password)
		}
	}
	return refs
}
