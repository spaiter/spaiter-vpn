package apply

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/spaiter/spaiter-vpn/internal/ddns"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	"github.com/spaiter/spaiter-vpn/internal/control"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/web"
)

// Systemd is the narrow set of unit operations the control daemon needs. It
// names one unit at a time and takes no arbitrary arguments.
type Systemd interface {
	Reload(ctx context.Context) error
	Start(ctx context.Context, unit string) error
	Restart(ctx context.Context, unit string) error
	Stop(ctx context.Context, unit string) error
}

type execSystemd struct{}

func (execSystemd) run(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
func (s execSystemd) Reload(ctx context.Context) error { return s.run(ctx, "daemon-reload") }
func (s execSystemd) Start(ctx context.Context, unit string) error {
	return s.run(ctx, "enable", "--now", unit)
}
func (s execSystemd) Restart(ctx context.Context, unit string) error {
	return s.run(ctx, "restart", unit)
}
func (s execSystemd) Stop(ctx context.Context, unit string) error {
	return s.run(ctx, "disable", "--now", unit)
}

// controlStep is what this apply does to the daemon.
type controlStep string

const (
	controlNone    controlStep = ""
	controlStart   controlStep = "start"   // newly installed
	controlRestart controlStep = "restart" // unit changed
	controlEnsure  controlStep = "ensure"  // unchanged; make sure it runs
	controlRetire  controlStep = "retire"  // no longer managed
)

// unitPlan is what this apply does to one bootstrap-managed systemd unit.
type unitPlan struct {
	name  string
	step  controlStep
	probe func(context.Context) error
}

// managedUnit describes a unit bootstrap may run.
type managedUnit struct {
	name, path string
	data       []byte
	wanted     bool
	// restartOn are files whose new content the running service must load.
	restartOn []transaction.Change
	probe     func(context.Context) error
}

// planUnits decides each unit's step from the previous receipt and returns
// the file changes that go with them: the units, the allow-list bootstrap
// keeps for its service accounts, and the files created once for the
// operator (control.json) or the web UI (its login-link key).
func (o Options) planUnits(manager *transaction.Manager, receipt transaction.Receipt, binary string, accounts serviceAccounts) ([]unitPlan, []transaction.Change, error) {
	if (o.Desired.Bootstrap.ManageControl || o.Desired.Bootstrap.ManageWeb) && o.Layout.ControlUnitPath == "" {
		return nil, nil, fmt.Errorf("bootstrap.manageControl needs a control unit path in the layout")
	}
	var changes []transaction.Change
	managedAccess := o.Layout.ControlManagedAccessPath()
	var accessChange []transaction.Change
	if o.Desired.Bootstrap.ManageControl && accounts.gid != 0 {
		access := control.Access{APIVersion: control.APIVersion, Observers: []uint32{}, Operators: []uint32{}, SocketGroup: accounts.gid}
		if o.botUser != nil {
			access.Operators = append(access.Operators, o.botUser.uid)
		}
		if accounts.webUID != 0 {
			access.Operators = append(access.Operators, accounts.webUID)
		}
		data, err := json.MarshalIndent(access, "", "  ")
		if err != nil {
			return nil, nil, err
		}
		accessChange = []transaction.Change{{Path: managedAccess, Data: append(data, '\n'), Mode: 0o644, UID: manager.UID, GID: manager.GID, Ownership: transaction.Managed}}
	} else if _, owned := receipt.Files[managedAccess]; owned {
		accessChange = []transaction.Change{{Path: managedAccess, Delete: true, Ownership: transaction.Managed}}
	}
	changes = append(changes, accessChange...)

	if o.Desired.Bootstrap.ManageControl {
		// The operator's allow-list: created once, root-only, then theirs.
		if _, err := os.Lstat(o.Layout.ControlAccessPath()); os.IsNotExist(err) {
			data, err := json.MarshalIndent(control.Access{APIVersion: control.APIVersion, Observers: []uint32{}, Operators: []uint32{}}, "", "  ")
			if err != nil {
				return nil, nil, err
			}
			changes = append(changes, transaction.Change{Path: o.Layout.ControlAccessPath(), Data: append(data, '\n'), Mode: 0o600, UID: manager.UID, GID: manager.GID, Ownership: transaction.RuntimeMutable})
		} else if err != nil {
			return nil, nil, err
		}
	}
	keyPath := o.Layout.WebKeyPath()
	if o.Desired.Bootstrap.ManageWeb {
		if _, err := os.Lstat(keyPath); os.IsNotExist(err) {
			key, err := web.NewKey()
			if err != nil {
				return nil, nil, err
			}
			changes = append(changes, transaction.Change{Path: keyPath, Data: []byte(key), Mode: 0o640, UID: manager.UID, GID: accounts.gid, Ownership: transaction.RuntimeMutable})
		} else if err != nil {
			return nil, nil, err
		}
	} else if owned, ok := receipt.Files[keyPath]; ok && owned.Ownership == transaction.RuntimeMutable {
		// Removing the key invalidates every link and session it signed.
		changes = append(changes, transaction.Change{Path: keyPath, Delete: true, Ownership: transaction.RuntimeMutable})
	}

	units := []managedUnit{
		{name: deploy.ControlUnitName, path: o.Layout.ControlUnitPath, data: deploy.ControlUnit(binary), wanted: o.Desired.Bootstrap.ManageControl, restartOn: accessChange, probe: o.probeControl},
		{name: deploy.WebUnitName, path: o.Layout.WebUnitPath(), wanted: o.Desired.Bootstrap.ManageWeb, probe: o.probeWeb},
	}
	if d := o.Desired.DDNS; d != nil {
		if o.Layout.ControlUnitPath == "" {
			return nil, nil, fmt.Errorf("ddns needs a unit directory in the layout")
		}
		ipv4Hosts := []string{}
		if host := o.Desired.Bot.PublicIPv4Host; host != "" && host != o.Desired.Bot.PublicHost {
			ipv4Hosts = append(ipv4Hosts, host)
		}
		credential := filepath.Join(o.Layout.CredentialDir(), string(d.Token))
		revision := "unknown"
		if info, err := os.Stat(credential); err == nil {
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				revision = fmt.Sprintf("%d-%d", st.Ino, info.ModTime().UnixNano())
			}
		}
		units = append(units, managedUnit{
			name: deploy.DDNSUnitName, path: o.Layout.DDNSUnitPath(), wanted: true,
			data: deploy.DDNSUnit(binary, deploy.DDNS{
				Provider: d.Provider, Hosts: []string{o.Desired.Bot.PublicHost}, IPv4Hosts: ipv4Hosts,
				CredentialPath: credential, CredentialRevision: revision,
				HiddenPaths: []string{o.Layout.ConfigRoot, o.Layout.DataRoot},
				Username:    d.Username, Server: d.Server, IPv6: d.IPv6,
			}),
		})
	} else {
		units = append(units, managedUnit{name: deploy.DDNSUnitName, path: o.Layout.DDNSUnitPath()})
	}
	if o.Desired.Bootstrap.ManageWeb {
		units[1].data = deploy.WebUnit(binary, keyPath, o.Desired.WebListen(), strings.HasPrefix(o.Desired.WebURL(), "https://"))
	}
	var plans []unitPlan
	for _, unit := range units {
		if unit.path == "" {
			continue
		}
		owned, wasOwned := receipt.Files[unit.path]
		plan := unitPlan{name: unit.name, probe: unit.probe}
		switch {
		case !unit.wanted && wasOwned:
			plan.step = controlRetire
			changes = append(changes, transaction.Change{Path: unit.path, Delete: true, Ownership: transaction.Managed})
		case !unit.wanted:
			continue
		case !wasOwned:
			plan.step = controlStart
		case owned.Digest != digestOf(unit.data) || filesChanged(receipt, unit.restartOn):
			plan.step = controlRestart
		default:
			plan.step = controlEnsure
		}
		if unit.wanted {
			changes = append(changes, transaction.Change{Path: unit.path, Data: unit.data, Mode: 0o644, UID: manager.UID, GID: manager.GID, Ownership: transaction.Managed})
		}
		if unit.name == deploy.DDNSUnitName && unit.wanted {
			// A unit left running reports on its own schedule; only a started
			// or restarted one owes a round from this apply.
			fresh := plan.step != controlEnsure
			plan.probe = func(ctx context.Context) error { return o.probeDDNS(ctx, fresh) }
		}
		plans = append(plans, plan)
	}
	return plans, changes, nil
}

// filesChanged reports whether any of changes writes something other than
// what the receipt recorded.
func filesChanged(receipt transaction.Receipt, changes []transaction.Change) bool {
	for _, change := range changes {
		owned, ok := receipt.Files[change.Path]
		if !ok || change.Delete || owned.Digest != digestOf(change.Data) {
			return true
		}
	}
	return false
}

func (o Options) systemd() Systemd {
	if o.Systemd == nil {
		return execSystemd{}
	}
	return o.Systemd
}

// stopRetired stops units that are going away while their files still exist:
// disabling a unit whose file is already gone fails. The web UI goes first.
func (o Options) stopRetired(ctx context.Context, plans []unitPlan) error {
	for i := len(plans) - 1; i >= 0; i-- {
		if plans[i].step == controlRetire {
			if err := o.systemd().Stop(ctx, plans[i].name); err != nil {
				return fmt.Errorf("stop %s: %w", plans[i].name, err)
			}
		}
	}
	return nil
}

// applyUnits runs after the files are written, the daemon before the web UI
// that talks to it, and proves each one answers.
func (o Options) applyUnits(ctx context.Context, plans []unitPlan) error {
	if len(plans) == 0 {
		return nil
	}
	sd := o.systemd()
	if err := sd.Reload(ctx); err != nil {
		return err
	}
	for _, plan := range plans {
		switch plan.step {
		case controlRetire, controlNone:
			continue
		case controlRestart:
			if err := sd.Restart(ctx, plan.name); err != nil {
				return err
			}
		}
		if err := sd.Start(ctx, plan.name); err != nil {
			return err
		}
		fmt.Fprintf(o.Out, "%s: %s\n", plan.name, map[controlStep]string{
			controlStart: "installed and started", controlRestart: "restarted with its new configuration", controlEnsure: "running",
		}[plan.step])
		if err := plan.probe(ctx); err != nil {
			return err
		}
	}
	return nil
}

// stopStarted stops units this apply started, before the restore removes
// their files.
func (o Options) stopStarted(ctx context.Context, plans []unitPlan) []error {
	var problems []error
	for i := len(plans) - 1; i >= 0; i-- {
		if plans[i].step == controlStart {
			if err := o.systemd().Stop(ctx, plans[i].name); err != nil {
				problems = append(problems, fmt.Errorf("stop %s: %w", plans[i].name, err))
			}
		}
	}
	return problems
}

// undoUnits reverses applyUnits after the files were restored.
func (o Options) undoUnits(ctx context.Context, plans []unitPlan) []error {
	touched := false
	for _, plan := range plans {
		if plan.step != controlNone && plan.step != controlEnsure {
			touched = true
		}
	}
	if !touched {
		return nil
	}
	sd := o.systemd()
	if err := sd.Reload(ctx); err != nil {
		return []error{err}
	}
	var problems []error
	for _, plan := range plans {
		var err error
		switch plan.step {
		case controlRestart:
			err = sd.Restart(ctx, plan.name)
		case controlRetire:
			err = sd.Start(ctx, plan.name)
		}
		if err != nil {
			problems = append(problems, fmt.Errorf("restore %s: %w", plan.name, err))
		}
	}
	return problems
}

// probeControl is the daemon's proof: its socket answers a status request.
func (o Options) probeControl(ctx context.Context) error {
	if o.ProbeControl != nil {
		return o.ProbeControl(ctx)
	}
	socket := filepath.Join(deploy.ControlSocketDir, deploy.ControlSocketName)
	return retryFor(ctx, 20*time.Second, func() error {
		response, err := control.Client{Socket: socket}.Do(ctx, control.Request{Operation: control.OpStatus})
		if err == nil && !response.OK {
			err = fmt.Errorf("%s", response.Error)
		}
		if err != nil {
			return fmt.Errorf("the control daemon did not answer on %s: %w", socket, err)
		}
		return nil
	})
}

// probeWeb is the web UI's proof: it answers, and asks a stranger to log in.
func (o Options) probeWeb(ctx context.Context) error {
	if o.ProbeWeb != nil {
		return o.ProbeWeb(ctx)
	}
	target := "http://" + o.Desired.WebListen() + "/"
	return retryFor(ctx, 20*time.Second, func() error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return err
		}
		response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
		if err != nil {
			return fmt.Errorf("the web UI did not answer on %s: %w", target, err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			return fmt.Errorf("the web UI answered %d to an anonymous request, want 401", response.StatusCode)
		}
		return nil
	})
}

// probeDDNS waits for the updater's first round after this apply. A rejected
// token or an unknown zone fails the apply: a server whose name silently stops
// following it is the failure dynamic DNS exists to prevent. A network
// problem is only reported: the updater keeps trying, and the record may well
// still be right.
//
// fresh asks for a round after this apply began; otherwise the latest stands.
func (o Options) probeDDNS(ctx context.Context, fresh bool) error {
	if o.ProbeDDNS != nil {
		return o.ProbeDDNS(ctx)
	}
	started := time.Now().Add(-time.Second)
	if !fresh {
		started = time.Time{}
	}
	var status ddns.Status
	err := retryFor(ctx, 90*time.Second, func() error {
		read, err := ddns.ReadStatus(deploy.DDNSStatusPath)
		if err != nil {
			return fmt.Errorf("the dynamic DNS updater has not reported yet: %w", err)
		}
		if read.Time.Before(started) {
			return fmt.Errorf("the dynamic DNS updater has not run since this apply")
		}
		status = read
		return nil
	})
	if err != nil {
		return err
	}
	switch {
	case status.OK:
		fmt.Fprintf(o.Out, "ddns: %s on %s\n", o.Desired.Bot.PublicHost, status.IPv4)
	case status.Permanent:
		return fmt.Errorf("dynamic DNS: %s", status.Error)
	default:
		fmt.Fprintf(o.Out, "ddns: warning, first update did not complete and will be retried: %s\n", status.Error)
	}
	return nil
}

func retryFor(ctx context.Context, limit time.Duration, attempt func() error) error {
	deadline := time.Now().Add(limit)
	for {
		err := attempt()
		if err == nil || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}
