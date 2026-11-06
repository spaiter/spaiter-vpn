package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/apply"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/secret"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/compose"
	"github.com/spaiter/spaiter-vpn/internal/config"
	"github.com/spaiter/spaiter-vpn/internal/control"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/preflight"
	"github.com/spaiter/spaiter-vpn/internal/profile"
	"github.com/spaiter/spaiter-vpn/internal/selftest"
)

const (
	defaultControlSocket = "/run/spaiter-vpn/control.sock"
	defaultControlAccess = "/etc/spaiter-vpn/control.json"
)

func runControl(ctx context.Context, out io.Writer, args []string) error {
	subcommands := map[string]func(context.Context, io.Writer, []string) error{
		"serve":       runControlServe,
		"status":      controlSimple(control.OpStatus),
		"generations": controlSimple(control.OpGenerations),
		"preflight":   controlSimple(control.OpPreflight),
		"selftest":    controlSimple(control.OpSelfTest),
		"prepare":     runControlPrepare,
		"commit":      controlTicket(control.OpCommit),
		"cancel":      controlTicket(control.OpCancel),
		"unit":        runControlUnit,
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "-help" || args[0] == "--help" {
		fmt.Fprintln(out, "usage: spaiter-vpn control <subcommand> [flags]")
		fmt.Fprintln(out, "\nThe local control plane: a root daemon on a Unix socket that performs typed")
		fmt.Fprintln(out, "VPN operations for unprivileged callers, identified by the kernel and checked")
		fmt.Fprintln(out, "against "+defaultControlAccess+". Changes take two steps: prepare shows")
		fmt.Fprintln(out, "the plan and a ticket, commit applies exactly that.")
		fmt.Fprintln(out, "\n  serve        run the daemon (root)")
		fmt.Fprintln(out, "  status       stored intent, generation and services")
		fmt.Fprintln(out, "  generations  committed generations")
		fmt.Fprintln(out, "  preflight    re-run the host checks")
		fmt.Fprintln(out, "  selftest     run the live BitTorrent self-test")
		fmt.Fprintln(out, "  prepare      plan a change: -port P=N, -mtu P=N, -enable P, -disable P,")
		fmt.Fprintln(out, "               -image REF, -rotate USERS or -rollback [-generation N]")
		fmt.Fprintln(out, "  commit ID    apply a prepared change")
		fmt.Fprintln(out, "  cancel ID    discard a prepared change")
		fmt.Fprintln(out, "  unit         print the systemd unit for the daemon")
		if len(args) == 0 {
			return ErrUsage
		}
		return nil
	}
	run, ok := subcommands[args[0]]
	if !ok {
		return fmt.Errorf("%w: unknown control subcommand %q", ErrUsage, args[0])
	}
	return run(ctx, out, args[1:])
}

func runControlServe(ctx context.Context, out io.Writer, args []string) error {
	var layoutOpts layoutFlags
	fs := newFlagSet("control serve", out)
	socket := fs.String("socket", defaultControlSocket, "Unix socket to listen on")
	accessPath := fs.String("access", defaultControlAccess, "root-owned file naming observer and operator uids")
	auditPath := fs.String("audit", "", "audit log (default: <data-root>/control/audit.log)")
	layoutOpts.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%w: serve takes flags only", ErrUsage)
	}
	layout, err := layoutOpts.layout()
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("the control daemon performs root operations, so it runs as root")
	}
	access, err := control.LoadAccess(*accessPath)
	if err != nil {
		return err
	}
	// The allow-list bootstrap keeps for its own service accounts, beside the
	// operator's. Absent unless bootstrap manages a service that needs one.
	managedPath := strings.TrimSuffix(*accessPath, ".json") + ".bootstrap.json"
	if managed, err := control.LoadAccess(managedPath); err == nil {
		access = control.MergeAccess(access, &managed)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", managedPath, err)
	}
	if *auditPath == "" {
		*auditPath = filepath.Join(layout.DataRoot, "control", "audit.log")
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	server := &control.Server{
		Socket:  *socket,
		Access:  access,
		Backend: &controlBackend{layout: layout},
		Audit: &control.Audit{Path: *auditPath, Failed: func(err error) {
			fmt.Fprintf(os.Stderr, "audit: %v\n", err)
		}},
	}
	fmt.Fprintf(out, "control: listening on %s, %d operator(s), %d observer(s), audit %s\n",
		*socket, len(access.Operators), len(access.Observers), *auditPath)
	return server.Serve(ctx)
}

func runControlUnit(_ context.Context, out io.Writer, _ []string) error {
	_, err := out.Write(deploy.ControlUnit(selfPathOrName()))
	return err
}

func controlClient(fs interface {
	String(string, string, string) *string
}) *string {
	return fs.String("socket", defaultControlSocket, "control daemon socket")
}

func controlSimple(op control.Operation) func(context.Context, io.Writer, []string) error {
	return func(ctx context.Context, out io.Writer, args []string) error {
		fs := newFlagSet("control "+string(op), out)
		socket := controlClient(fs)
		if err := fs.Parse(args); err != nil {
			return err
		}
		return controlCall(ctx, out, *socket, control.Request{Operation: op})
	}
}

func controlTicket(op control.Operation) func(context.Context, io.Writer, []string) error {
	return func(ctx context.Context, out io.Writer, args []string) error {
		fs := newFlagSet("control "+string(op), out)
		socket := controlClient(fs)
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return fmt.Errorf("%w: %s takes a ticket id", ErrUsage, op)
		}
		return controlCall(ctx, out, *socket, control.Request{Operation: op, Ticket: fs.Arg(0)})
	}
}

type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

func runControlPrepare(ctx context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("control prepare", out)
	socket := controlClient(fs)
	var ports, mtus, enable, disable repeated
	fs.Var(&ports, "port", "protocol=port, repeatable")
	fs.Var(&mtus, "mtu", "protocol=mtu, repeatable")
	fs.Var(&enable, "enable", "protocol to enable, repeatable")
	fs.Var(&disable, "disable", "protocol to disable, repeatable")
	image := fs.String("image", "", "new tag or digest of the deployed image repository")
	rotate := fs.String("rotate", "", "comma-separated users whose credentials to reissue")
	rollback := fs.Bool("rollback", false, "roll back to an earlier generation")
	generation := fs.Uint64("generation", 0, "rollback target (default: previous)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	change := control.Change{}
	switch {
	case *rollback:
		change = control.Change{Kind: control.ChangeRollback, Generation: *generation}
	case *rotate != "":
		users, err := parseRotationUsers(*rotate)
		if err != nil {
			return err
		}
		change = control.Change{Kind: control.ChangeRotate, Users: users}
	case *image != "":
		change = control.Change{Kind: control.ChangeImage, Image: *image}
	default:
		change = control.Change{Kind: control.ChangeSettings, Enable: enable, Disable: disable}
		for _, item := range ports {
			name, value, ok := strings.Cut(item, "=")
			port, err := strconv.ParseUint(value, 10, 16)
			if !ok || err != nil {
				return fmt.Errorf("%w: -port wants protocol=port, got %q", ErrUsage, item)
			}
			if change.Ports == nil {
				change.Ports = map[string]uint16{}
			}
			change.Ports[name] = uint16(port)
		}
		for _, item := range mtus {
			name, value, ok := strings.Cut(item, "=")
			mtu, err := strconv.ParseUint(value, 10, 32)
			if !ok || err != nil {
				return fmt.Errorf("%w: -mtu wants protocol=mtu, got %q", ErrUsage, item)
			}
			if change.MTU == nil {
				change.MTU = map[string]uint32{}
			}
			change.MTU[name] = uint32(mtu)
		}
	}
	if err := change.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	return controlCall(ctx, out, *socket, control.Request{Operation: control.OpPrepare, Change: &change})
}

func controlCall(ctx context.Context, out io.Writer, socket string, request control.Request) error {
	response, err := control.Client{Socket: socket}.Do(ctx, request)
	if err != nil {
		return err
	}
	if response.Output != "" {
		fmt.Fprint(out, response.Output)
		if !strings.HasSuffix(response.Output, "\n") {
			fmt.Fprintln(out)
		}
	}
	if len(response.Result) > 0 {
		var pretty any
		if json.Unmarshal(response.Result, &pretty) == nil {
			encoded, _ := json.MarshalIndent(pretty, "", "  ")
			fmt.Fprintln(out, string(encoded))
		}
	}
	if !response.OK {
		return errors.New(response.Error)
	}
	return nil
}

// controlBackend performs the daemon's operations with the same planner,
// engine and synthesis the bootstrap commands use.
type controlBackend struct {
	layout discover.Layout
}

type controlStatus struct {
	DesiredDigest string                 `json:"desiredDigest,omitempty"`
	Tier          string                 `json:"tier,omitempty"`
	Image         string                 `json:"image,omitempty"`
	SeedUsers     int                    `json:"seedUsers"`
	Bot           bool                   `json:"bot"`
	Generation    uint64                 `json:"generation,omitempty"`
	Transaction   string                 `json:"transaction,omitempty"`
	Services      []compose.ServiceState `json:"services,omitempty"`
	ServicesError string                 `json:"servicesError,omitempty"`
}

func (b *controlBackend) Status(ctx context.Context) (any, error) {
	var status controlStatus
	if desired, err := state.Load(b.layout.DesiredPath()); err == nil {
		digest, _ := desired.Digest()
		status.DesiredDigest, status.Tier, status.Image = digest, string(desired.Deployment.Tier), desired.Deployment.Image
		status.SeedUsers, status.Bot = len(desired.Bootstrap.SeedUsers), desired.Bot.Enabled
	}
	if receipt, ok, err := newTransactionManager(b.layout).Current(); err != nil {
		return nil, err
	} else if ok {
		status.Generation, status.Transaction = receipt.Sequence, receipt.Transaction
	}
	if runner, err := compose.Detect(ctx); err != nil {
		status.ServicesError = err.Error()
	} else if services, err := runner.Services(ctx, b.layout.ComposePath()); err != nil {
		status.ServicesError = err.Error()
	} else {
		status.Services = services
	}
	return status, nil
}

func (b *controlBackend) Generations(context.Context) (any, error) {
	return newTransactionManager(b.layout).Generations()
}

func (b *controlBackend) Preflight(ctx context.Context, out io.Writer) (any, error) {
	desired, err := state.Load(b.layout.DesiredPath())
	if err != nil {
		return nil, err
	}
	observed, err := discoverHost(ctx, desired, b.layout)
	if err != nil {
		return nil, err
	}
	var xdp []string
	if observed.Network.DefaultInterface != "" {
		xdp = []string{observed.Network.DefaultInterface}
	}
	if len(desired.Deployment.XDPInterfaces) != 1 || desired.Deployment.XDPInterfaces[0] != "auto" {
		xdp = desired.Deployment.XDPInterfaces
	}
	spec, err := desired.PreflightSpec(xdp)
	if err != nil {
		return nil, err
	}
	report := preflight.Run(ctx, preflight.Options{
		Spec: spec, ConfigDir: b.layout.DeploymentDir(), CacheDir: b.layout.CacheDir(),
		Image: desired.Deployment.Image, OwnDeploymentRunning: true,
		LogrotateWillBeInstalled: desired.Bootstrap.ManageLogrotate,
	})
	report.Write(out)
	return map[string]int{
		"pass": report.Count(preflight.Pass), "warn": report.Count(preflight.Warn),
		"fail": report.Count(preflight.Fail), "unknown": report.Count(preflight.Unknown),
	}, report.Err(false)
}

func (b *controlBackend) SelfTest(ctx context.Context, out io.Writer) error {
	options := selftest.DefaultOptions()
	options.ConfigPath = b.layout.ConfigPath()
	_, err := selftest.Run(ctx, out, options)
	return err
}

func (b *controlBackend) Prepare(ctx context.Context, change control.Change, out io.Writer) (control.Prepared, error) {
	var desired state.State
	var err error
	switch change.Kind {
	case control.ChangeRollback:
		desired, _, err = synthesizeRollback(b.layout, change.Generation)
	default:
		var current state.State
		current, err = state.Load(b.layout.DesiredPath())
		if err != nil {
			return control.Prepared{}, fmt.Errorf("read current desired state: %w", err)
		}
		desired, err = controlDesired(current, change, time.Now())
	}
	if err != nil {
		return control.Prepared{}, err
	}
	approved, err := buildPlan(ctx, desired, b.layout)
	if err != nil {
		return control.Prepared{}, err
	}
	if approved.Blocked {
		var blockers []string
		for _, action := range approved.Actions {
			if action.Disposition == plan.Blocked {
				blockers = append(blockers, action.Summary+" ("+action.Reason+")")
			}
		}
		return control.Prepared{}, fmt.Errorf("the plan is blocked: %s", strings.Join(blockers, "; "))
	}
	if installsDocker(approved) {
		return control.Prepared{}, errors.New("installing Docker is an operator decision made with `bootstrap apply`, not through the control socket")
	}
	return control.Prepared{
		Plan: approved,
		Commit: func(ctx context.Context, out io.Writer) (any, string, error) {
			options, err := applyOptions(ctx, b.layout, desired, approved, out, false, "")
			if err != nil {
				return nil, "", err
			}
			result, err := apply.Run(ctx, options)
			if err != nil {
				return nil, "", err
			}
			return result, result.Transaction, nil
		},
	}, nil
}

// controlDesired applies a typed change to the current intent. It touches
// only the fields the change kind names, and leaves every migration audit
// record in place.
func controlDesired(current state.State, change control.Change, now time.Time) (state.State, error) {
	desired := current
	switch change.Kind {
	case control.ChangeSettings:
		known := map[string]bool{}
		for _, protocol := range profile.AllProtocols {
			known[string(protocol)] = true
		}
		desired.Deployment.Ports = maps.Clone(current.Deployment.Ports)
		for name, port := range change.Ports {
			if !known[name] {
				return state.State{}, fmt.Errorf("unknown protocol %q", name)
			}
			desired.Deployment.Ports[profile.Protocol(name)] = port
		}
		desired.Deployment.MTU = maps.Clone(current.Deployment.MTU)
		for name, mtu := range change.MTU {
			if !known[name] {
				return state.State{}, fmt.Errorf("unknown protocol %q", name)
			}
			desired.Deployment.MTU[profile.Protocol(name)] = mtu
		}
		disabled := slices.Clone(current.Deployment.Protocols.Disabled)
		for _, name := range change.Enable {
			if !known[name] {
				return state.State{}, fmt.Errorf("unknown protocol %q", name)
			}
			disabled = slices.DeleteFunc(disabled, func(p profile.Protocol) bool { return string(p) == name })
		}
		for _, name := range change.Disable {
			if !known[name] {
				return state.State{}, fmt.Errorf("unknown protocol %q", name)
			}
			if !slices.Contains(disabled, profile.Protocol(name)) {
				disabled = append(disabled, profile.Protocol(name))
			}
		}
		sort.Slice(disabled, func(i, j int) bool { return disabled[i] < disabled[j] })
		desired.Deployment.Protocols.Disabled = disabled
	case control.ChangeImage:
		if imageRepository(change.Image) != imageRepository(current.Deployment.Image) {
			return state.State{}, fmt.Errorf("image %s is not from the deployed repository %s; changing registries is an operator decision made locally", change.Image, imageRepository(current.Deployment.Image))
		}
		desired.Deployment.Image = change.Image
	case control.ChangeRotate:
		id, err := newRotationID(now)
		if err != nil {
			return state.State{}, err
		}
		return rotationDesired(current, change.Users, id)
	default:
		return state.State{}, fmt.Errorf("change kind %q is not a desired-state edit", change.Kind)
	}
	if err := desired.Validate(); err != nil {
		return state.State{}, err
	}
	return desired, nil
}

// imageRepository strips a reference's tag or digest.
func imageRepository(reference string) string {
	if at := strings.Index(reference, "@"); at >= 0 {
		reference = reference[:at]
	}
	if colon := strings.LastIndex(reference, ":"); colon > strings.LastIndex(reference, "/") {
		reference = reference[:colon]
	}
	return reference
}

// Redact scrubs every stored credential and the management secret.
func (b *controlBackend) Redact(text string) string {
	var values []string
	if entries, err := os.ReadDir(b.layout.CredentialDir()); err == nil {
		store := secret.Store{Dir: b.layout.CredentialDir()}
		for _, entry := range entries {
			if value, err := store.Read(state.SecretRef(entry.Name())); err == nil {
				values = append(values, value)
			}
		}
	}
	if data, err := os.ReadFile(b.layout.ConfigPath()); err == nil {
		if parsed, err := config.Unmarshal(context.Background(), data); err == nil && parsed.Experimental != nil && parsed.Experimental.ClashAPI != nil {
			values = append(values, parsed.Experimental.ClashAPI.Secret)
		}
	}
	return secret.Redact(text, values...)
}
