package apply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/firewall"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// canonicalDesiredJSON stores the operator's intent in canonical form, so the
// digest a later plan computes over the stored document matches the one that
// was approved. Storing the submitted bytes instead would make an innocuous
// reformat look like a changed intent.
func canonicalDesiredJSON(desired state.State) ([]byte, error) {
	canonical, err := desired.Canonical()
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(canonical, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal desired state: %w", err)
	}
	return append(data, '\n'), nil
}

// changes builds the file transaction.
//
// Two ownership modes, and the distinction is the whole reason a repeat apply
// can be safe: the generated files around the core are Managed, so drift in
// them is a conflict, while config.json and secrets.json are RuntimeMutable,
// because the core rewrites the first through config_output_path as users are
// provisioned and the second describes credentials that must never be
// regenerated underneath a live deployment.
func (o Options) changes(manager *transaction.Manager, mode plan.Mode, desiredJSON []byte, rendered *profile.Rendered, artifacts deploy.Artifacts, extra []transaction.Change) ([]transaction.Change, error) {
	uid, gid := manager.UID, manager.GID
	managed := func(path string, data []byte, mode os.FileMode) transaction.Change {
		return transaction.Change{Path: path, Data: data, Mode: mode, UID: uid, GID: gid, Ownership: transaction.Managed}
	}

	changes := []transaction.Change{
		managed(o.Layout.DesiredPath(), desiredJSON, 0o644),
	}
	// The runtime files are written exactly once, by the install that generated
	// them, and are absent from a convergence's transaction entirely.
	//
	// Not "written with identical content": there is no identical content to
	// write. The generator would produce different keys, and the core has
	// already rewritten the config since. Leaving them out is what makes the
	// preservation structural rather than a comparison that has to be got
	// right — and the transaction refuses to replace a runtime-mutable file
	// anyway, so including them would simply fail.
	if mode == plan.ModeFresh {
		// 0600 on both: between them they hold every private key, every user
		// credential and the clash API secret, which is remote control of the
		// running core.
		changes = append(changes,
			transaction.Change{Path: o.Layout.ConfigPath(), Data: rendered.ConfigJSON, Mode: 0o600, UID: uid, GID: gid, Ownership: transaction.RuntimeMutable},
			transaction.Change{Path: o.Layout.SecretsPath(), Data: rendered.SecretsJSON, Mode: 0o600, UID: uid, GID: gid, Ownership: transaction.RuntimeMutable},
		)
	} else if mode == plan.ModeMigrate || mode == plan.ModeRestartMigrate || mode == plan.ModeSubnetMigrate {
		changes = append(changes, transaction.Change{
			Path: o.Layout.ConfigPath(), Data: rendered.ConfigJSON, Mode: 0o600,
			UID: uid, GID: gid, Ownership: transaction.RuntimeMutable,
			ReplaceRuntimeMutable: true,
		})
		if len(rendered.SecretsJSON) > 0 {
			changes = append(changes, transaction.Change{
				Path: o.Layout.SecretsPath(), Data: rendered.SecretsJSON, Mode: 0o600,
				UID: uid, GID: gid, Ownership: transaction.RuntimeMutable,
				ReplaceRuntimeMutable: true,
			})
		}
	}

	byName := map[string]string{
		deploy.ComposeFileName:       o.Layout.ComposePath(),
		deploy.EnvFileName:           o.Layout.EnvPath(),
		deploy.BotConfigFileName:     o.Layout.BotConfigPath(),
		deploy.ReloadAgentScriptName: o.Layout.ReloadAgentPath(),
		deploy.LogrotateFileName:     o.Layout.LogrotatePath,
	}
	for _, artifact := range artifacts.Files() {
		if artifact.Name == deploy.LogrotateFileName && !o.Desired.Bootstrap.ManageLogrotate {
			// Rendered either way, installed only when asked. Writing it
			// unasked would put a file in /etc/logrotate.d that the operator
			// declined, and the transaction would then own it forever.
			continue
		}
		path, known := byName[artifact.Name]
		if !known {
			return nil, fmt.Errorf("rendered artifact %q has no managed path", artifact.Name)
		}
		changes = append(changes, managed(path, artifact.Data, artifact.Mode))
	}
	changes = append(changes, extra...)
	return changes, nil
}

func changedPaths(changes []transaction.Change) []string {
	paths := make([]string, 0, len(changes))
	for _, change := range changes {
		paths = append(paths, change.Path)
	}
	return paths
}

// prepareRuntimeDirectories creates the bind-mount sources the containers need.
//
// Not transaction targets: they are directories and a marker file rather than
// managed content, and they must survive a rollback. The core's cache holds
// ACME state, and the bot's data directory holds the users it has provisioned —
// deleting either to undo a failed apply would destroy exactly the state the
// rollback is supposed to protect.
func (o Options) prepareRuntimeDirectories(manager *transaction.Manager, params deploy.Params) error {
	dirs := []string{params.CacheDir}
	if params.Bot.Enabled {
		dirs = append(dirs, params.Bot.DataDir)
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := os.Chown(dir, int(manager.UID), int(manager.GID)); err != nil {
			return fmt.Errorf("own %s: %w", dir, err)
		}
	}
	if !params.Reload.Enabled {
		return nil
	}
	// The marker must exist as a FILE before compose starts. Docker creates a
	// directory at a missing bind source, after which the bot's attempt to
	// write the marker fails and reloads stop working with no visible error.
	marker := params.Reload.MarkerPath
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(marker), err)
	}
	info, err := os.Lstat(marker)
	switch {
	case err == nil && info.Mode().IsRegular():
		return nil
	case err == nil:
		return fmt.Errorf("reload marker %s exists but is not a regular file", marker)
	case !os.IsNotExist(err):
		return fmt.Errorf("inspect reload marker %s: %w", marker, err)
	}
	file, err := os.OpenFile(marker, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create reload marker %s: %w", marker, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close reload marker %s: %w", marker, err)
	}
	return os.Chown(marker, int(manager.UID), int(manager.GID))
}

// compensation records what a failed apply has to undo.
//
// The durable transaction records firewall and container-recreate intent before
// either mutation. This in-memory half performs immediate compensation while
// the process is alive; crash recovery carries unresolved ownership/recreate
// work into the receipt for the next approved apply.
type compensation struct {
	tx   *transaction.Transaction
	mode plan.Mode
	// added and retired are what this apply changed in the firewall, so the
	// undo is symmetric. Putting a retired rule back matters more than it
	// looks: a failed migration that closed the old port and then restores the
	// previous deployment would otherwise restore it unreachable on the only
	// port its clients know.
	added   []firewall.Rule
	retired []firewall.Rule
	// units is what this apply did to the units bootstrap manages, reversed
	// around the file restore.
	units []unitPlan
}

// run undoes a failed apply and reports the outcome of that undoing as its own
// error.
//
// Never collapsed into the original failure: "apply failed" and "apply failed
// and the rollback did not finish" need different responses from the operator,
// and hiding the second behind the first is how a half-restored host gets
// retried.
func (c *compensation) run(ctx context.Context, options Options) error {
	var problems []error

	// A first install and a convergence have opposite correct endings, and
	// using one procedure for both is how a failed update takes a working
	// server offline.
	//
	// Fresh: nothing of value existed before, so the services this run created
	// are removed. `down` is first because it reads the compose file, so
	// stopping after the file rollback would leave containers running with no
	// project left to manage them.
	//
	// Convergence: something of value was running before, and it must be
	// running again at the end. The files are restored FIRST — which puts back
	// the previous compose project and image reference — and then the project
	// is started again from it. Calling `down` here would stop a deployment
	// whose only problem was that an update to it failed.
	if c.mode == plan.ModeFresh {
		if err := options.Compose.Down(ctx, options.Layout.ComposePath(), options.Out, options.Out); err != nil {
			problems = append(problems, fmt.Errorf("stop the compose project: %w", err))
		}
	}
	// Only what this transaction changed, one rule at a time. Nothing here
	// touches a default policy or a rule somebody else added.
	for _, rule := range c.added {
		if err := options.Firewall.Remove(ctx, rule); err != nil {
			problems = append(problems, fmt.Errorf("close %s: %w", rule, err))
		}
	}
	for _, rule := range c.retired {
		if err := options.Firewall.Add(ctx, rule); err != nil {
			problems = append(problems, fmt.Errorf("re-open %s: %w", rule, err))
		}
	}
	// Stopped while their unit files still exist; the restore removes them.
	problems = append(problems, options.stopStarted(ctx, c.units)...)
	rolledBack := true
	if err := c.tx.Rollback(); err != nil {
		rolledBack = false
		problems = append(problems, fmt.Errorf("restore managed files: %w", err))
	}
	if rolledBack {
		problems = append(problems, options.undoUnits(ctx, c.units)...)
	}
	if c.mode == plan.ModeReconcile || c.mode == plan.ModeMigrate || c.mode == plan.ModeRestartMigrate || c.mode == plan.ModeSubnetMigrate || c.mode == plan.ModeRestartRecover {
		if !rolledBack {
			problems = append(problems, errors.New("not restarting the previous deployment: its files were not restored, so there is nothing trustworthy to start"))
		} else {
			recreate := c.mode == plan.ModeRestartMigrate || c.mode == plan.ModeSubnetMigrate || c.mode == plan.ModeRestartRecover
			if err := options.restorePrevious(ctx, recreate); err != nil {
				problems = append(problems, err)
			} else if recreate {
				if err := c.tx.ResolveRecreate(); err != nil {
					problems = append(problems, fmt.Errorf("record restored container generation: %w", err))
				}
			}
		}
	}
	if len(problems) == 0 {
		fmt.Fprintln(options.Out, "rolled back: "+c.summary())
		return nil
	}
	return fmt.Errorf("rollback incomplete: %w", errors.Join(problems...))
}

func (c *compensation) summary() string {
	if c.mode == plan.ModeMigrate {
		return "previous configuration re-applied, managed files restored, added firewall rules removed and the previous deployment is running again"
	}
	if c.mode == plan.ModeRestartMigrate || c.mode == plan.ModeSubnetMigrate {
		return "previous configuration force-recreated, managed files restored, added firewall rules removed and the previous deployment is running again"
	}
	if c.mode == plan.ModeRestartRecover {
		return "recovered configuration force-recreated, managed files restored, added firewall rules removed and the previous deployment is running again"
	}
	if c.mode == plan.ModeReconcile {
		return "managed files restored, added firewall rules removed and the previous deployment is running again"
	}
	return "managed files restored, added firewall rules removed and the compose project stopped"
}

// restorePrevious brings the previous generation back up and proves it answers.
//
// Running `up` is not the claim; the claim is that the deployment works again,
// and only the health wait can make it. Reported as its own failure because
// "the update failed" and "the update failed and the server is still down" ask
// different things of an operator.
func (o Options) restorePrevious(ctx context.Context, recreate bool) error {
	var err error
	if recreate {
		err = o.Compose.Recreate(ctx, o.Layout.ComposePath(), o.Out, o.Out)
	} else {
		err = o.Compose.Up(ctx, o.Layout.ComposePath(), o.Out, o.Out)
	}
	if err != nil {
		return fmt.Errorf("restart the previous deployment: %w", err)
	}
	if !recreate {
		if err := o.applyRuntime(ctx); err != nil {
			return fmt.Errorf("synchronise the restored configuration: %w", err)
		}
	}
	// The restored project, not the desired state: a convergence that was
	// turning the bot on or off changes which services exist, and waiting for
	// the set the failed apply wanted would either hang on a service that is
	// no longer defined or ignore one that is.
	project, err := os.ReadFile(o.Layout.ComposePath())
	if err != nil {
		return fmt.Errorf("read the restored compose project: %w", err)
	}
	services := deploy.ServicesInProject(project)
	if len(services) == 0 {
		return fmt.Errorf("the restored compose project defines none of this deployment's services")
	}
	waited, err := o.waitHealthy(ctx, services)
	if err != nil {
		return fmt.Errorf("the previous deployment did not come back: %w", err)
	}
	fmt.Fprintf(o.Out, "previous deployment healthy again after %s\n", waited.Waited.Truncate(1e6))
	return nil
}

func rulesAsText(rules []firewall.Rule) []string {
	if len(rules) == 0 {
		return nil
	}
	text := make([]string, 0, len(rules))
	for _, rule := range rules {
		text = append(text, rule.String())
	}
	return text
}

// firewallPlan is what this apply will do to the host firewall, and what the
// next receipt should say the deployment owns afterwards.
type firewallPlan struct {
	add    []firewall.Rule
	retire []firewall.Rule
	// owned is the rule set to record on commit: what we owned, plus what we
	// are adding, minus what we are retiring.
	owned []string
}

// planFirewall decides what to open and what to close, from the observation the
// recomputed plan was built on and the rules the last receipt says are ours.
//
// Read from the observation rather than probed again so the plan the operator
// approved and the rules we change cannot differ, and restricted to an active,
// readable UFW for the same reason the planner refuses anything else: an
// unreadable ruleset is not permission to write to it.
//
// Retirement is the half that needs the receipt. A rule is closed only if the
// deployment is recorded as having opened it and no longer wants it — never
// because it is present and unwanted, which would delete whatever the operator
// opened for their own reasons. The consequence of getting this wrong in either
// direction is ugly: too eager and it cuts somebody's SSH, too timid and a
// migrated port leaves an allow rule open forever.
func (o Options) planFirewall(observed discover.Observed, receipt transaction.Receipt) (firewallPlan, error) {
	ownedBefore := append([]string(nil), receipt.Firewall...)
	if !o.Desired.Bootstrap.ManageFirewall {
		// Still carried over: the operator turning management off is not the
		// same as the deployment disowning rules it opened earlier, and
		// forgetting them here would strand them permanently.
		return firewallPlan{owned: ownedBefore}, nil
	}
	fw := observed.Firewall
	if fw.Kind != string(firewall.UFW) || !fw.Active || !fw.Readable {
		return firewallPlan{owned: ownedBefore}, nil
	}
	spec, err := o.Desired.PreflightSpec(resolveXDP(o.Desired, observed))
	if err != nil {
		return firewallPlan{}, err
	}

	statuses := map[string]firewall.Status{}
	for rule, status := range fw.Rules {
		if status == "allowed" {
			statuses[rule] = firewall.Allowed
		} else {
			statuses[rule] = firewall.Blocked
		}
	}
	wanted := discover.FirewallRules(o.Desired, spec)
	wantedSet := map[string]bool{}
	for _, rule := range wanted {
		wantedSet[rule.String()] = true
	}

	plan := firewallPlan{add: firewall.Missing(wanted, statuses)}
	ownedSet := map[string]bool{}
	for _, text := range ownedBefore {
		if wantedSet[text] {
			ownedSet[text] = true
			continue
		}
		rule, parseErr := firewall.ParseRule(text)
		if parseErr != nil {
			// An unreadable entry is kept rather than acted on: we cannot close
			// what we cannot name, and dropping it would disown a rule that is
			// still open.
			ownedSet[text] = true
			continue
		}
		plan.retire = append(plan.retire, rule)
	}
	for _, rule := range plan.add {
		ownedSet[rule.String()] = true
	}

	if (len(plan.add) > 0 || len(plan.retire) > 0) && o.Firewall == nil {
		return firewallPlan{}, fmt.Errorf("%d firewall rules need opening and %d need closing, but no firewall applier was supplied; the deployment would start and be reachable by nobody",
			len(plan.add), len(plan.retire))
	}
	plan.owned = make([]string, 0, len(ownedSet))
	for text := range ownedSet {
		plan.owned = append(plan.owned, text)
	}
	sort.Strings(plan.owned)
	return plan, nil
}
