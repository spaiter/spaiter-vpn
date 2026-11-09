package apply

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/dockerinstall"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/health"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/secret"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	"github.com/spaiter/spaiter-vpn/internal/bot/clientcfg"
	botstate "github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/compose"
	"github.com/spaiter/spaiter-vpn/internal/config"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/firewall"
	"github.com/spaiter/spaiter-vpn/internal/preflight"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

type fakeCompose struct {
	calls       []string
	pullErr     error
	upErr       error
	recreateErr error
	downErr     error
	states      []compose.ServiceState
	logs        string
	servicesErr error
	// onStop runs inside StopService, standing in for whatever the stopped
	// service was doing up to the moment it stopped.
	onStop func(service string)
}

func (f *fakeCompose) Pull(context.Context, string, io.Writer, io.Writer) error {
	f.calls = append(f.calls, "pull")
	return f.pullErr
}
func (f *fakeCompose) Up(context.Context, string, io.Writer, io.Writer) error {
	f.calls = append(f.calls, "up")
	return f.upErr
}
func (f *fakeCompose) Recreate(context.Context, string, io.Writer, io.Writer) error {
	f.calls = append(f.calls, "recreate")
	return f.recreateErr
}
func (f *fakeCompose) StopService(_ context.Context, _ string, service string, _, _ io.Writer) error {
	f.calls = append(f.calls, "stop:"+service)
	if f.onStop != nil {
		f.onStop(service)
	}
	return nil
}
func (f *fakeCompose) Down(context.Context, string, io.Writer, io.Writer) error {
	f.calls = append(f.calls, "down")
	return f.downErr
}
func (f *fakeCompose) Services(context.Context, string) ([]compose.ServiceState, error) {
	return f.states, f.servicesErr
}
func (f *fakeCompose) Logs(context.Context, string, string, int) (string, error) {
	return f.logs, nil
}
func (f *fakeCompose) DisplayName() string { return "fake" }

type harness struct {
	layout     discover.Layout
	desired    state.State
	observed   discover.Observed
	compose    *fakeCompose
	selfTested bool
	options    Options
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	layout := discover.Layout{
		ConfigRoot:    filepath.Join(root, "etc"),
		DataRoot:      filepath.Join(root, "var"),
		LogrotatePath: filepath.Join(root, "logrotate.d", "spaiter-vpn"),
	}
	desired := state.Default([]string{"owner"})
	// Logrotate and Docker installation are refused by this slice; the firewall
	// fixture already has every required rule, so that action stays a check.
	desired.Bootstrap.ManageLogrotate = false

	h := &harness{
		layout:   layout,
		desired:  desired,
		observed: readyObservation(t, desired),
		compose: &fakeCompose{
			states: []compose.ServiceState{{Service: deploy.CoreServiceName, Name: "sing-box", State: "running"}},
		},
	}
	approved, err := plan.Build(desired, h.observed)
	if err != nil {
		t.Fatal(err)
	}
	h.options = Options{
		Layout:   layout,
		Desired:  desired,
		Approved: approved,
		Discover: func(context.Context, state.State) (discover.Observed, error) { return h.observed, nil },
		Secrets:  secret.Store{Dir: layout.CredentialDir(), UID: uint32(os.Getuid())},
		Compose:  h.compose,
		CheckConfig: func(context.Context, []byte) error {
			return nil
		},
		Preflight: func(context.Context, preflight.Options) *preflight.Report {
			return &preflight.Report{Checks: []preflight.Check{{Name: "fixture", Severity: preflight.Pass}}}
		},
		// A probe and a self-test that pass, so a test that cares about the
		// file transaction is not also testing the network.
		Probe: func(context.Context) error { return nil },
		ApplyRuntime: func(context.Context) error {
			return nil
		},
		SelfTest: func(context.Context, io.Writer) error {
			h.selfTested = true
			return nil
		},
		// No settle window and no sleeping: the wait's own timing behaviour is
		// tested in its own package.
		HealthTuning: health.Options{
			Settle:   0,
			Interval: time.Millisecond,
			Deadline: time.Second,
		},
		BotBinary: filepath.Join(root, "spaiter-vpn"),
		// The bot's account is the test's own, so handing state to it works
		// without root.
		LookupUser: func(name string) discover.SystemUser {
			return discover.SystemUser{Name: name, Exists: true, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
		},
		LookupGroup:    func(string) (uint32, bool, error) { return uint32(os.Getgid()), true, nil },
		CheckBotBinary: func(string) error { return nil },
		RunAccountCommand: func(_ context.Context, name string, args ...string) error {
			t.Fatalf("a test ran %s %v", name, args)
			return nil
		},
		Manager: &transaction.Manager{
			StateDir:       layout.BootstrapStateDir(),
			AllowedTargets: layout.ManagedFiles(),
			UID:            uint32(os.Getuid()),
			GID:            uint32(os.Getgid()),
		},
		Out: io.Discard,
	}
	return h
}

// TestFreshApplyWritesAndStarts is the slice's main claim: a first install
// writes every managed file at the intended mode, starts the project through
// Compose, records a receipt, and reports the proofs it did NOT run.
func TestFreshApplyWritesAndStarts(t *testing.T) {
	h := newHarness(t)
	result, err := Run(context.Background(), h.options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != plan.ModeFresh {
		t.Fatalf("mode = %q, want fresh", result.Mode)
	}
	if got, want := strings.Join(h.compose.calls, ","), "pull,up"; got != want {
		t.Fatalf("compose calls = %s, want %s", got, want)
	}
	// Order matters, and not only for tidiness: starting containers before the
	// files are on disk would run the previous configuration.
	for path, mode := range map[string]os.FileMode{
		h.layout.DesiredPath(): 0o644,
		h.layout.ConfigPath():  0o600,
		h.layout.SecretsPath(): 0o600,
		h.layout.ComposePath(): 0o644,
		h.layout.EnvPath():     0o644,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if info.Mode().Perm() != mode {
			t.Errorf("%s has mode %04o, want %04o", path, info.Mode().Perm(), mode)
		}
	}
	// The bot is disabled in this fixture, so its config must not exist: a
	// bot.json present without the service is a file the operator has to
	// reason about for nothing.
	if _, err := os.Stat(h.layout.BotConfigPath()); !os.IsNotExist(err) {
		t.Errorf("bot.json exists although the bot is disabled: %v", err)
	}
	if _, err := os.Stat(h.layout.LogrotatePath); !os.IsNotExist(err) {
		t.Error("logrotate file was written by a slice that does not validate it")
	}
	if _, err := os.Stat(h.layout.CacheDir()); err != nil {
		t.Errorf("cache directory was not created: %v", err)
	}
	if result.Health == nil || result.Health.Samples == 0 {
		t.Error("apply reported success without a health observation")
	}
	if !h.selfTested {
		t.Error("apply committed without running the self-test")
	}

	// The stored intent must round-trip, or the next plan sees a changed
	// desired state and refuses to converge.
	stored, err := state.Load(h.layout.DesiredPath())
	if err != nil {
		t.Fatal(err)
	}
	storedDigest, err := stored.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if storedDigest != h.options.Approved.DesiredDigest {
		t.Fatalf("stored desired digest %s does not match the approved %s", storedDigest, h.options.Approved.DesiredDigest)
	}

	receipt, err := os.ReadFile(h.layout.CurrentReceiptPath())
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Files map[string]struct {
			Ownership string `json:"ownership"`
		} `json:"files"`
	}
	if err := json.Unmarshal(receipt, &parsed); err != nil {
		t.Fatal(err)
	}
	// config.json and secrets.json must be recorded as runtime-mutable, which
	// is what stops a later apply from treating the core's own rewrite of the
	// config as foreign drift and refusing to converge.
	for _, path := range []string{h.layout.ConfigPath(), h.layout.SecretsPath()} {
		if parsed.Files[path].Ownership != string(transaction.RuntimeMutable) {
			t.Errorf("%s is recorded as %q, want runtime-mutable", path, parsed.Files[path].Ownership)
		}
	}
	if parsed.Files[h.layout.ComposePath()].Ownership != string(transaction.Managed) {
		t.Error("the compose file is not recorded as managed, so drift in it would not be detected")
	}
}

// TestStaleConsentIsRefused. The operator approved a plan for one host state;
// applying it against another is applying something they never read.
func TestStaleConsentIsRefused(t *testing.T) {
	h := newHarness(t)
	h.observed.Docker.ServerVersion = "28.0.0"
	_, err := Run(context.Background(), h.options)
	if !errors.Is(err, ErrStaleConsent) {
		t.Fatalf("err = %v, want ErrStaleConsent", err)
	}
	assertNothingWritten(t, h)
}

// dockerlessHarness is a fresh host with no Docker and installDocker on.
func dockerlessHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	h.desired.Bootstrap.InstallDocker = true
	h.options.Desired = h.desired
	h.observed = readyObservation(t, h.desired)
	h.observed.Docker = discover.Docker{Install: &discover.DockerInstall{Conflicts: []string{}, ForeignSources: []string{}}}
	h.replan(t)
	return h
}

// TestDockerIsInstalledBeforePreflightAndRecorded. Preflight needs a daemon,
// so installation comes first, and the deployment proceeds against a fresh
// observation in which only Docker changed.
func TestDockerIsInstalledBeforePreflightAndRecorded(t *testing.T) {
	h := dockerlessHarness(t)
	if !slices.ContainsFunc(h.options.Approved.Actions, func(a plan.Action) bool {
		return a.ID == "docker-install" && a.Disposition == plan.Apply && strings.Contains(a.Summary, "docker-ce=5:29.9.3-1~ubuntu.24.04~noble")
	}) {
		t.Fatalf("plan does not name the pinned install: %#v", h.options.Approved.Actions)
	}
	var order []string
	h.options.InstallDocker = func(_ context.Context, release dockerinstall.Release, composeOnly bool) (dockerinstall.Record, error) {
		order = append(order, "install")
		if composeOnly || release.Codename != "noble" {
			t.Fatalf("install(%s, composeOnly=%v)", release.Codename, composeOnly)
		}
		h.observed.Docker = readyObservation(t, h.desired).Docker
		return dockerinstall.Record{Packages: map[string]string{"docker-ce": release.Versions.Engine}, Engine: release.EngineVersion}, nil
	}
	runPreflight := h.options.Preflight
	h.options.Preflight = func(ctx context.Context, options preflight.Options) *preflight.Report {
		order = append(order, "preflight")
		return runPreflight(ctx, options)
	}
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "install,preflight" {
		t.Fatalf("order = %v", order)
	}
	record, err := dockerinstall.ReadRecord(h.layout.PlatformRecordPath())
	if err != nil || record == nil || record.Packages["docker-ce"] == "" {
		t.Fatalf("installation record = %#v, %v", record, err)
	}
	if _, err := os.Stat(h.layout.ConfigPath()); err != nil {
		t.Fatalf("the deployment was not installed after Docker: %v", err)
	}
}

// TestFailedDockerInstallWritesNoDeploymentButKeepsItsRecord. The packages
// apt did install stay on the host, so the record of them must survive the
// failure that stops the deployment.
func TestFailedDockerInstallWritesNoDeploymentButKeepsItsRecord(t *testing.T) {
	h := dockerlessHarness(t)
	h.options.InstallDocker = func(context.Context, dockerinstall.Release, bool) (dockerinstall.Record, error) {
		return dockerinstall.Record{Packages: map[string]string{"docker-ce": "x"}}, errors.New("daemon did not answer")
	}
	if _, err := Run(context.Background(), h.options); err == nil || !strings.Contains(err.Error(), "daemon did not answer") {
		t.Fatalf("err = %v", err)
	}
	assertNothingWritten(t, h)
	if record, err := dockerinstall.ReadRecord(h.layout.PlatformRecordPath()); err != nil || record == nil {
		t.Fatalf("record of the partial install = %#v, %v", record, err)
	}
}

// TestDockerInstallRefusesAHostThatChangedMeanwhile. Consent covered
// installing Docker; anything else moving while apt ran is stale consent.
func TestDockerInstallRefusesAHostThatChangedMeanwhile(t *testing.T) {
	h := dockerlessHarness(t)
	h.options.InstallDocker = func(context.Context, dockerinstall.Release, bool) (dockerinstall.Record, error) {
		h.observed.Docker = readyObservation(t, h.desired).Docker
		h.observed.Network.DefaultInterface = "eth1"
		return dockerinstall.Record{}, nil
	}
	if _, err := Run(context.Background(), h.options); !errors.Is(err, ErrStaleConsent) {
		t.Fatalf("err = %v, want ErrStaleConsent", err)
	}
	assertNothingWritten(t, h)
}

func TestDockerInstallIsBlockedByConflictsAndForeignSources(t *testing.T) {
	h := dockerlessHarness(t)
	h.observed.Docker.Install = &discover.DockerInstall{Conflicts: []string{"containerd"}, ForeignSources: []string{}}
	approved, err := plan.Build(h.desired, h.observed)
	if err != nil || !approved.Blocked {
		t.Fatalf("conflicting containerd did not block: %v %#v", err, approved.Actions)
	}
	h.observed.Docker.Install = &discover.DockerInstall{Conflicts: []string{}, ForeignSources: []string{"/etc/apt/sources.list.d/docker.list"}}
	if approved, err = plan.Build(h.desired, h.observed); err != nil || !approved.Blocked {
		t.Fatalf("a foreign Docker repository did not block: %v", err)
	}
	h.observed.Docker = discover.Docker{CLIAvailable: true, DaemonReachable: true, ServerVersion: "27.5.1",
		Install: &discover.DockerInstall{Conflicts: []string{"docker.io"}, ForeignSources: []string{}}}
	approved, err = plan.Build(h.desired, h.observed)
	if err != nil || approved.Blocked || !slices.ContainsFunc(approved.Actions, func(a plan.Action) bool { return a.ID == "docker-compose-install" }) {
		t.Fatalf("a distribution engine should not block a Compose-only install: %v %#v", err, approved.Actions)
	}
	h.observed.Platform.VersionID = "22.04"
	if approved, err = plan.Build(h.desired, h.observed); err != nil || !approved.Blocked {
		t.Fatalf("an unpinned release did not block: %v", err)
	}
}

type fakeFirewall struct {
	added     []string
	removed   []string
	addErr    error
	removeErr error
}

func (f *fakeFirewall) Add(_ context.Context, rule firewall.Rule) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.added = append(f.added, rule.String())
	return nil
}
func (f *fakeFirewall) Remove(_ context.Context, rule firewall.Rule) error {
	f.removed = append(f.removed, rule.String())
	return f.removeErr
}
func (f *fakeFirewall) Name() string { return "fake" }

// blockFirewallRule makes one required rule missing, which is what turns the
// planner's firewall check into a mutation.
func blockFirewallRule(h *harness, t *testing.T) string {
	t.Helper()
	h.observed = readyObservation(t, h.desired)
	blocked := h.observed.Firewall.Required[0]
	h.observed.Firewall.Rules[blocked] = "blocked"
	approved, err := plan.Build(h.desired, h.observed)
	if err != nil {
		t.Fatal(err)
	}
	h.options.Desired = h.desired
	h.options.Approved = approved
	return blocked
}

// TestMissingFirewallRuleIsOpened. A deployment that starts correctly and is
// reachable by nobody is the failure this closes, and it has no local symptom
// at all.
func TestMissingFirewallRuleIsOpened(t *testing.T) {
	h := newHarness(t)
	blocked := blockFirewallRule(h, t)
	fw := &fakeFirewall{}
	h.options.Firewall = fw

	result, err := Run(context.Background(), h.options)
	if err != nil {
		t.Fatal(err)
	}
	if len(fw.added) != 1 || fw.added[0] != blocked {
		t.Fatalf("added = %v, want exactly the blocked rule %s", fw.added, blocked)
	}
	if len(fw.removed) != 0 {
		t.Fatalf("a successful apply removed firewall rules: %v", fw.removed)
	}
	if len(result.FirewallAdded) != 1 {
		t.Fatalf("the result does not record what was opened: %v", result.FirewallAdded)
	}
}

// TestFirewallAdditionsAreRemovedOnFailure, and only the additions. Removing
// anything else would be a tool adjusting a firewall it does not understand.
func TestFirewallAdditionsAreRemovedOnFailure(t *testing.T) {
	h := newHarness(t)
	blocked := blockFirewallRule(h, t)
	fw := &fakeFirewall{}
	h.options.Firewall = fw
	h.options.SelfTest = func(context.Context, io.Writer) error { return errors.New("no detection") }

	if _, err := Run(context.Background(), h.options); err == nil {
		t.Fatal("expected the self-test failure")
	}
	if len(fw.removed) != 1 || fw.removed[0] != blocked {
		t.Fatalf("removed = %v, want exactly %s", fw.removed, blocked)
	}
	assertNothingWritten(t, h)
}

// TestMissingFirewallApplierIsRefused rather than silently skipped: the plan
// said a port would be opened.
func TestMissingFirewallApplierIsRefused(t *testing.T) {
	h := newHarness(t)
	blockFirewallRule(h, t)
	h.options.Firewall = nil
	_, err := Run(context.Background(), h.options)
	if err == nil || !strings.Contains(err.Error(), "reachable by nobody") {
		t.Fatalf("err = %v, want a refusal naming the consequence", err)
	}
	assertNothingWritten(t, h)
}

// TestLogrotateIsInstalledOnlyWhenAsked. An unasked file in /etc/logrotate.d is
// one the transaction then owns forever.
func TestLogrotateIsInstalledOnlyWhenAsked(t *testing.T) {
	h := newHarness(t)
	h.desired.Bootstrap.ManageLogrotate = true
	h.observed = readyObservation(t, h.desired)
	approved, err := plan.Build(h.desired, h.observed)
	if err != nil {
		t.Fatal(err)
	}
	h.options.Desired = h.desired
	h.options.Approved = approved
	var validated []byte
	h.options.ValidateLogrotate = func(_ context.Context, data []byte) error {
		validated = data
		return nil
	}

	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if len(validated) == 0 {
		t.Fatal("the rotation configuration was installed without being validated")
	}
	installed, err := os.ReadFile(h.layout.LogrotatePath)
	if err != nil {
		t.Fatalf("logrotate file: %v", err)
	}
	if string(installed) != string(validated) {
		t.Fatal("the installed file is not the one that was validated")
	}
}

// TestRejectedLogrotateStopsTheApply before anything is written. A stanza
// logrotate cannot parse means the core's append-only log grows until the disk
// fills, which surfaces weeks later as the server going down.
func TestRejectedLogrotateStopsTheApply(t *testing.T) {
	h := newHarness(t)
	h.desired.Bootstrap.ManageLogrotate = true
	h.observed = readyObservation(t, h.desired)
	approved, err := plan.Build(h.desired, h.observed)
	if err != nil {
		t.Fatal(err)
	}
	h.options.Desired = h.desired
	h.options.Approved = approved
	h.options.ValidateLogrotate = func(context.Context, []byte) error {
		return errors.New("unknown option 'bogus'")
	}
	if _, err := Run(context.Background(), h.options); err == nil {
		t.Fatal("an unparseable rotation configuration was installed")
	}
	assertNothingWritten(t, h)
	if len(h.compose.calls) != 0 {
		t.Fatalf("compose ran despite the rejected configuration: %v", h.compose.calls)
	}
}

// TestPreflightFailureGeneratesNothing. Keys minted for a host that cannot run
// them are a credential the operator now has to rotate for no reason.
func TestPreflightFailureGeneratesNothing(t *testing.T) {
	h := newHarness(t)
	h.options.Preflight = func(context.Context, preflight.Options) *preflight.Report {
		return &preflight.Report{Checks: []preflight.Check{{
			Name: "ports", Severity: preflight.Fail, Detail: "10861 is in use",
		}}}
	}
	if _, err := Run(context.Background(), h.options); err == nil {
		t.Fatal("apply continued after a failed preflight")
	}
	assertNothingWritten(t, h)
	if len(h.compose.calls) != 0 {
		t.Fatalf("compose was called after a failed preflight: %v", h.compose.calls)
	}
}

// TestComposeFailureRollsBack. The point is that a failed start leaves no
// managed file behind, so a retry starts from a clean slate rather than from a
// half-written deployment.
func TestComposeFailureRollsBack(t *testing.T) {
	h := newHarness(t)
	h.compose.upErr = errors.New("no such image")
	_, err := Run(context.Background(), h.options)
	if err == nil {
		t.Fatal("apply reported success although the project did not start")
	}
	if !strings.Contains(err.Error(), "no such image") {
		t.Fatalf("the original failure was lost: %v", err)
	}
	if strings.Contains(err.Error(), "rollback incomplete") {
		t.Fatalf("rollback did not finish: %v", err)
	}
	assertNothingWritten(t, h)
	if got, want := strings.Join(h.compose.calls, ","), "pull,up,down"; got != want {
		t.Fatalf("compose calls = %s, want %s", got, want)
	}
	// The cache directory deliberately survives: it holds ACME state, and
	// deleting it to undo a failed apply would destroy what rollback protects.
	if _, err := os.Stat(h.layout.CacheDir()); err != nil {
		t.Errorf("rollback removed the core's cache directory: %v", err)
	}
}

// installed fabricates the observation a host presents after a successful
// install of `previous`, so a convergence to a different document can be
// planned against it.
//
// previous is passed explicitly rather than read back from the options, because
// state.State shares its maps: mutating desired.Deployment.Ports also mutates
// the copy a test took earlier, and the diff then comes out empty — which reads
// as "a port change is reconcilable" when nothing was compared at all.
func (h *harness) installed(t *testing.T, previous state.State) {
	t.Helper()
	digest, err := previous.Digest()
	if err != nil {
		t.Fatal(err)
	}
	existing := previous
	h.observed = readyObservation(t, h.options.Desired)
	h.observed.ExistingDesired = discover.ExistingDesired{
		Status: discover.FileRegular, Digest: digest, State: &existing,
	}
	h.observed.Runtime = discover.Runtime{
		Config:  discover.File{Status: discover.FileRegular, Mode: 0o600},
		Secrets: discover.File{Status: discover.FileRegular, Mode: 0o600},
		Compose: discover.File{Status: discover.FileRegular, Mode: 0o644},
		Receipt: discover.File{Status: discover.FileRegular, Mode: 0o600},
	}
}

func (h *harness) replan(t *testing.T) {
	t.Helper()
	approved, err := plan.Build(h.options.Desired, h.observed)
	if err != nil {
		t.Fatal(err)
	}
	h.options.Approved = approved
}

// TestConvergenceKeepsEveryKey is the point of the reconcile path, and the
// reason it is not simply "run the install again": regenerating would mint new
// private keys and a new clash secret over a live deployment and lock out every
// user it has.
func TestConvergenceKeepsEveryKey(t *testing.T) {
	h := newHarness(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	configBefore := digestFile(t, h.layout.ConfigPath())
	secretsBefore := digestFile(t, h.layout.SecretsPath())
	composeBefore := digestFile(t, h.layout.ComposePath())

	// A reconcilable change: a new immutable image reference.
	previous := h.options.Desired
	desired := h.options.Desired
	desired.Deployment.Image = "registry.example/spaiter-vpn-core:next"
	h.options.Desired = desired
	h.installed(t, previous)
	h.replan(t)
	if h.options.Approved.Mode != plan.ModeReconcile {
		t.Fatalf("mode = %q, want reconcile", h.options.Approved.Mode)
	}
	syncCalls := 0
	h.options.ApplyRuntime = func(context.Context) error {
		syncCalls++
		return nil
	}

	h.compose.calls = nil
	result, err := Run(context.Background(), h.options)
	if err != nil {
		t.Fatalf("the convergence failed: %v", err)
	}
	if result.Mode != plan.ModeReconcile {
		t.Fatalf("result mode = %q, want reconcile", result.Mode)
	}
	if got := digestFile(t, h.layout.ConfigPath()); got != configBefore {
		t.Error("config.json was rewritten by the convergence; the live keys were replaced")
	}
	if got := digestFile(t, h.layout.SecretsPath()); got != secretsBefore {
		t.Error("secrets.json was rewritten; every existing client would stop working")
	}
	if got := digestFile(t, h.layout.ComposePath()); got == composeBefore {
		t.Error("the compose file did not change, so the new image was never applied")
	}
	if !strings.Contains(string(mustRead(t, h.layout.ComposePath())), "spaiter-vpn-core:next") {
		t.Error("the compose file does not name the requested image")
	}
	// Structural, not comparative: the runtime files must be absent from the
	// transaction entirely rather than rewritten with equal content.
	for _, path := range result.Files {
		if path == h.layout.ConfigPath() || path == h.layout.SecretsPath() {
			t.Errorf("%s was part of the convergence transaction", path)
		}
	}
	if got, want := strings.Join(h.compose.calls, ","), "pull,up"; got != want {
		t.Fatalf("compose calls = %s, want %s", got, want)
	}
	if syncCalls != 1 {
		t.Fatalf("management sync calls = %d, want 1", syncCalls)
	}
}

// TestConvergenceStillRefusesAnUnsafeMigration. Moving a subnet would require
// reassigning every live peer address, which the management API cannot decide.
func TestConvergenceStillRefusesAnUnsafeMigration(t *testing.T) {
	h := newHarness(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	before := digestFile(t, h.layout.ComposePath())

	// A deep enough copy that moving one subnet does not also move it in the
	// state the host is supposed to be running.
	previous := h.options.Desired
	previous.Deployment.Subnets = maps.Clone(previous.Deployment.Subnets)
	desired := h.options.Desired
	desired.Deployment.Subnets[profile.AWG2] = "10.99.0.0/24"
	h.options.Desired = desired
	h.installed(t, previous)
	approved, err := plan.Build(h.options.Desired, h.observed)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Mode != plan.ModeMigrationRequired || !approved.Blocked {
		t.Fatalf("a subnet change was not classed as an unsafe migration: %#v", approved.Mode)
	}
	h.options.Approved = approved
	if _, err := Run(context.Background(), h.options); err == nil {
		t.Fatal("a migration was applied as a convergence")
	}
	if got := digestFile(t, h.layout.ComposePath()); got != before {
		t.Error("the refused migration still rewrote the compose file")
	}
}

func TestSubnetMigrationPreservesHostNumbersAndCredentials(t *testing.T) {
	h := newHarness(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	var before profile.Secrets
	if err := json.Unmarshal(mustRead(t, h.layout.SecretsPath()), &before); err != nil {
		t.Fatal(err)
	}

	previous := h.options.Desired
	previous.Deployment.Subnets = maps.Clone(previous.Deployment.Subnets)
	desired := h.options.Desired
	desired.Deployment.Subnets[profile.AWG2] = "10.99.0.0/24"
	desired.MigrationPolicy = &state.MigrationPolicy{Subnets: map[profile.Protocol]state.SubnetMigration{
		profile.AWG2: {From: previous.Deployment.Subnets[profile.AWG2], To: "10.99.0.0/24", Strategy: state.SubnetStrategyPreserveHost},
	}}
	h.options.Desired = desired
	h.installed(t, previous)
	h.replan(t)
	if h.options.Approved.Mode != plan.ModeSubnetMigrate {
		t.Fatalf("mode = %q, want subnet-migrate", h.options.Approved.Mode)
	}
	h.compose.calls = nil
	result, err := Run(context.Background(), h.options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != plan.ModeSubnetMigrate {
		t.Fatalf("result mode = %q", result.Mode)
	}
	if got, want := strings.Join(h.compose.calls, ","), "pull,recreate"; got != want {
		t.Fatalf("compose calls = %s, want %s", got, want)
	}

	var after profile.Secrets
	if err := json.Unmarshal(mustRead(t, h.layout.SecretsPath()), &after); err != nil {
		t.Fatal(err)
	}
	expected, err := profile.ReassignSubnetPreserveHost(before, profile.AWG2,
		netip.MustParsePrefix("10.10.0.0/24"), netip.MustParsePrefix("10.99.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, expected) {
		t.Fatal("client handover changed beyond the authorized addresses")
	}
	if after.Endpoints[profile.AWG2].Address.String() != "10.99.0.1/24" || after.Users[0].Peers[profile.AWG2].Address.String() != "10.99.0.2/32" {
		t.Fatalf("host numbers not preserved: endpoint=%s peer=%s", after.Endpoints[profile.AWG2].Address, after.Users[0].Peers[profile.AWG2].Address)
	}
}

func TestFailedSubnetMigrationRestoresBothCredentialStores(t *testing.T) {
	h := newHarness(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	configBefore := digestFile(t, h.layout.ConfigPath())
	secretsBefore := digestFile(t, h.layout.SecretsPath())
	previous := h.options.Desired
	previous.Deployment.Subnets = maps.Clone(previous.Deployment.Subnets)
	desired := h.options.Desired
	desired.Deployment.Subnets[profile.AWG2] = "10.99.0.0/24"
	desired.MigrationPolicy = &state.MigrationPolicy{Subnets: map[profile.Protocol]state.SubnetMigration{
		profile.AWG2: {From: previous.Deployment.Subnets[profile.AWG2], To: "10.99.0.0/24", Strategy: state.SubnetStrategyPreserveHost},
	}}
	h.options.Desired = desired
	h.installed(t, previous)
	h.replan(t)
	h.options.SelfTest = func(context.Context, io.Writer) error { return errors.New("subnet proof failed") }
	h.compose.calls = nil
	if _, err := Run(context.Background(), h.options); err == nil {
		t.Fatal("subnet migration succeeded despite failed proof")
	}
	if digestFile(t, h.layout.ConfigPath()) != configBefore || digestFile(t, h.layout.SecretsPath()) != secretsBefore {
		t.Fatal("failed subnet migration did not restore both credential stores")
	}
	if got, want := strings.Join(h.compose.calls, ","), "pull,recreate,recreate"; got != want {
		t.Fatalf("compose calls = %s, want %s", got, want)
	}
}

func TestSubnetMigrationRefusesUntrackedBotPeerFilesBeforeWriting(t *testing.T) {
	h := newHarness(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	configBefore := digestFile(t, h.layout.ConfigPath())
	secretsBefore := digestFile(t, h.layout.SecretsPath())
	previous := h.options.Desired
	previous.Deployment.Subnets = maps.Clone(previous.Deployment.Subnets)
	desired := h.options.Desired
	desired.Deployment.Subnets[profile.AWG2] = "10.99.0.0/24"
	desired.MigrationPolicy = &state.MigrationPolicy{Subnets: map[profile.Protocol]state.SubnetMigration{
		profile.AWG2: {From: previous.Deployment.Subnets[profile.AWG2], To: "10.99.0.0/24", Strategy: state.SubnetStrategyPreserveHost},
	}}
	h.options.Desired = desired
	h.installed(t, previous)
	h.replan(t)
	peerDir := filepath.Join(h.layout.BotDataDir(), "awg")
	if err := os.MkdirAll(peerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(peerDir, "42.json"), []byte(`{"priv":"private","pub":"public","ip":"10.10.0.17"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.compose.calls = nil
	if _, err := Run(context.Background(), h.options); err == nil || !strings.Contains(err.Error(), "no matching live peer") {
		t.Fatalf("error = %v", err)
	}
	if digestFile(t, h.layout.ConfigPath()) != configBefore || digestFile(t, h.layout.SecretsPath()) != secretsBefore {
		t.Fatal("refused bot-backed migration changed credential files")
	}
	if len(h.compose.calls) != 0 {
		t.Fatalf("refused migration called Compose: %v", h.compose.calls)
	}
}

func TestSubnetMigrationMovesBotPeerAndInvalidatesSubscriptionCache(t *testing.T) {
	h := newHarness(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	parsed, err := config.Unmarshal(context.Background(), mustRead(t, h.layout.ConfigPath()))
	if err != nil {
		t.Fatal(err)
	}
	live, err := profile.SecretsFromConfig(parsed)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := h.options.Desired.DeploymentSpec([]string{"eth0"}, h.options.Secrets.Resolver())
	if err != nil {
		t.Fatal(err)
	}
	spec.Users = append(live.Names(), "42")
	expanded, err := profile.Regenerate(spec, live)
	if err != nil {
		t.Fatal(err)
	}
	configJSON, err := config.Marshal(context.Background(), expanded.Options)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.layout.ConfigPath(), configJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	var botUser profile.UserSecrets
	for _, user := range expanded.Secrets.Users {
		if user.Name == "42" {
			botUser = user
		}
	}
	peer := botUser.Peers[profile.AWG2]
	peerDir := filepath.Join(h.layout.BotDataDir(), "awg")
	if err := os.MkdirAll(peerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	peerPath := filepath.Join(peerDir, "42.json")
	peerJSON, _ := json.Marshal(botstate.Peer{Priv: peer.PrivateKey, Pub: peer.PublicKey, IP: peer.Address.Addr().String()})
	if err := os.WriteFile(peerPath, peerJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(h.layout.BotDataDir(), "wdtt", "subs-cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(cacheDir, "token.json")
	if err := os.WriteFile(cachePath, []byte(`{"outbounds":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	previous := h.options.Desired
	previous.Deployment.Subnets = maps.Clone(previous.Deployment.Subnets)
	desired := h.options.Desired
	desired.Deployment.Subnets[profile.AWG2] = "10.99.0.0/24"
	desired.MigrationPolicy = &state.MigrationPolicy{Subnets: map[profile.Protocol]state.SubnetMigration{profile.AWG2: {From: "10.10.0.0/24", To: "10.99.0.0/24", Strategy: state.SubnetStrategyPreserveHost}}}
	h.options.Desired = desired
	h.installed(t, previous)
	h.replan(t)
	h.compose.calls = nil
	result, err := Run(context.Background(), h.options)
	if err != nil {
		t.Fatal(err)
	}
	data := mustRead(t, peerPath)
	var moved botstate.Peer
	if json.Unmarshal(data, &moved) != nil {
		t.Fatal("invalid migrated peer")
	}
	if moved.Priv != peer.PrivateKey || moved.Pub != peer.PublicKey || moved.IP != "10.99.0.3" {
		t.Fatalf("migrated peer = %#v", moved)
	}
	node, err := clientcfg.AWGNode(clientcfg.Endpoint{PrivateKey: expanded.Secrets.Endpoints[profile.AWG2].PrivateKey, ListenPort: 10863}, moved, "awg", "vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := node["address"].([]string); !slices.Equal(got, []string{"10.99.0.3/32"}) {
		t.Fatalf("rendered bot client address = %v, want [10.99.0.3/32]", got)
	}
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Fatalf("subscription cache was not invalidated: %v", err)
	}
	if !slices.Contains(result.Files, peerPath) || !slices.Contains(result.Files, cachePath) {
		t.Fatalf("bot files absent from transaction: %v", result.Files)
	}
	// The dynamic peer path is now in the receipt. A later process must rebuild
	// its exact allowlist from that receipt or it will reject its own bot state.
	h.installed(t, desired)
	h.replan(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatalf("convergence after adopting bot peer state: %v", err)
	}
}

func TestWGWDTTSubnetMigrationMovesRelayPasswordCopyTransactionally(t *testing.T) {
	h := newHarness(t)
	h.enableBot(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	parsed, err := config.Unmarshal(context.Background(), mustRead(t, h.layout.ConfigPath()))
	if err != nil {
		t.Fatal(err)
	}
	live, err := profile.SecretsFromConfig(parsed)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := h.options.Desired.DeploymentSpec([]string{"eth0"}, h.options.Secrets.Resolver())
	if err != nil {
		t.Fatal(err)
	}
	spec.Users = append(live.Names(), "42")
	expanded, err := profile.Regenerate(spec, live)
	if err != nil {
		t.Fatal(err)
	}
	configJSON, err := config.Marshal(context.Background(), expanded.Options)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.layout.ConfigPath(), configJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	var botUser profile.UserSecrets
	for _, user := range expanded.Secrets.Users {
		if user.Name == "42" {
			botUser = user
		}
	}
	peer := botUser.Peers[profile.WGWDTT]
	peerDir := filepath.Join(h.layout.BotDataDir(), "awg")
	if err := os.MkdirAll(peerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	peerPath := filepath.Join(peerDir, "42-wg-wdtt-in.json")
	peerJSON, _ := json.Marshal(botstate.Peer{Priv: peer.PrivateKey, Pub: peer.PublicKey, IP: peer.Address.Addr().String()})
	if err := os.WriteFile(peerPath, peerJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	wdttStateDir := filepath.Join(h.layout.BotDataDir(), "wdtt")
	if err := os.MkdirAll(wdttStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wdttStateDir, "42.json"), []byte(`{"password":"relay-secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	relayDir := filepath.Join(filepath.Dir(h.layout.DataRoot), "wdtt-relay")
	if err := os.MkdirAll(relayDir, 0o700); err != nil {
		t.Fatal(err)
	}
	relayPath := filepath.Join(relayDir, "passwords.json")
	relayBefore := map[string]any{
		"bot_token": "relay-owned-token",
		"devices":   map[string]any{"dev-1": map[string]any{"seen": 7}},
		"passwords": map[string]any{
			"relay-secret": map[string]any{
				"max_devices": 1,
				"wg_priv":     peer.PrivateKey,
				"wg_ip":       peer.Address.Addr().String(),
				"down_bytes":  1234,
				"device_id":   "dev-1",
			},
			"placeholder": map[string]any{"max_devices": 1},
		},
	}
	relayJSON, _ := json.MarshalIndent(relayBefore, "", "  ")
	if err := os.WriteFile(relayPath, append(relayJSON, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	previous := h.options.Desired
	previous.Deployment.Subnets = maps.Clone(previous.Deployment.Subnets)
	desired := h.options.Desired
	desired.Deployment.Subnets = maps.Clone(previous.Deployment.Subnets)
	desired.Deployment.Subnets[profile.WGWDTT] = "10.99.0.0/24"
	desired.Bot.WDTTConfigDirectory = relayDir
	desired.MigrationPolicy = &state.MigrationPolicy{Subnets: map[profile.Protocol]state.SubnetMigration{
		profile.WGWDTT: {From: previous.Deployment.Subnets[profile.WGWDTT], To: "10.99.0.0/24", Strategy: state.SubnetStrategyPreserveHost},
	}}
	h.options.Desired = desired
	h.installed(t, previous)
	h.observeBotCredential()
	h.replan(t)
	if h.options.Approved.Mode != plan.ModeSubnetMigrate {
		t.Fatalf("mode = %q, want subnet-migrate", h.options.Approved.Mode)
	}
	h.compose.calls = nil
	result, err := Run(context.Background(), h.options)
	if err != nil {
		t.Fatal(err)
	}

	var movedPeer botstate.Peer
	if err := json.Unmarshal(mustRead(t, peerPath), &movedPeer); err != nil {
		t.Fatal(err)
	}
	if movedPeer.IP != "10.99.0.3" || movedPeer.Priv != peer.PrivateKey || movedPeer.Pub != peer.PublicKey {
		t.Fatalf("migrated WDTT peer = %#v", movedPeer)
	}
	var relayAfter map[string]json.RawMessage
	if err := json.Unmarshal(mustRead(t, relayPath), &relayAfter); err != nil {
		t.Fatal(err)
	}
	if string(relayAfter["bot_token"]) != `"relay-owned-token"` || !bytes.Contains(relayAfter["devices"], []byte(`"dev-1"`)) {
		t.Fatalf("relay-owned top-level fields were lost: %s", mustRead(t, relayPath))
	}
	var entries map[string]map[string]json.RawMessage
	if err := json.Unmarshal(relayAfter["passwords"], &entries); err != nil {
		t.Fatal(err)
	}
	entry := entries["relay-secret"]
	if string(entry["wg_ip"]) != `"10.99.0.3"` || string(entry["down_bytes"]) != "1234" || string(entry["device_id"]) != `"dev-1"` {
		t.Fatalf("relay entry was not migrated losslessly: %v", entry)
	}
	markerPath := (deploy.Bot{DataDir: h.layout.BotDataDir()}).WDTTReloadMarkerPath()
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("WDTT reload marker was not touched: %v", err)
	}
	for _, path := range []string{peerPath, relayPath, markerPath} {
		if !slices.Contains(result.Files, path) {
			t.Fatalf("%s absent from migration transaction: %v", path, result.Files)
		}
	}
	if got, want := strings.Join(h.compose.calls, ","), "stop:vpn-bot,pull,recreate"; got != want {
		t.Fatalf("compose calls = %s, want %s", got, want)
	}

	// The retained host-path contract reconstructs the external allowlist on a
	// later process and keeps the adopted relay file in the receipt.
	h.installed(t, desired)
	h.observeBotCredential()
	h.replan(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatalf("convergence after adopting relay state: %v", err)
	}
}

// enableBot turns the bot on in the harness's desired state with everything a
// rendered bot service needs: its credential on disk, the observation of that
// credential and a running vpn-bot for the health wait.
func (h *harness) enableBot(t *testing.T) {
	t.Helper()
	const token = "123456:telegram-fixture"
	h.options.Desired.Bot.Enabled = true
	h.options.Desired.Bot.AdminIDs = []int64{1}
	h.options.Desired.Bot.PublicHost = "vpn.example.com"
	h.options.Desired.Bot.TelegramToken = "telegram-token"
	if err := os.MkdirAll(h.layout.CredentialDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.layout.CredentialDir(), "telegram-token"), []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.compose.states = append(h.compose.states,
		compose.ServiceState{Service: deploy.ReloadServiceName, Name: "sing-box-reload", State: "running"},
		compose.ServiceState{Service: deploy.BotServiceName, Name: "vpn-bot", State: "running"},
	)
	h.observed = readyObservation(t, h.options.Desired)
	h.observeBotCredential()
	h.replan(t)
}

func (h *harness) observeBotCredential() {
	h.observed.Credentials["telegram-token"] = discover.File{Status: discover.FileRegular, Mode: 0o600, UID: 0, Size: int64(len("123456:telegram-fixture"))}
}

// botSubnetMove installs the harness's current state as the previous
// generation and authorizes an AWG2 preserve-host move away from it.
func (h *harness) botSubnetMove(t *testing.T) {
	t.Helper()
	previous := h.options.Desired
	previous.Deployment.Subnets = maps.Clone(previous.Deployment.Subnets)
	desired := h.options.Desired
	desired.Deployment.Subnets = maps.Clone(previous.Deployment.Subnets)
	desired.Deployment.Subnets[profile.AWG2] = "10.99.0.0/24"
	desired.MigrationPolicy = &state.MigrationPolicy{Subnets: map[profile.Protocol]state.SubnetMigration{
		profile.AWG2: {From: previous.Deployment.Subnets[profile.AWG2], To: "10.99.0.0/24", Strategy: state.SubnetStrategyPreserveHost},
	}}
	h.options.Desired = desired
	h.installed(t, previous)
	h.observeBotCredential()
	h.replan(t)
	if h.options.Approved.Mode != plan.ModeSubnetMigrate {
		t.Fatalf("fixture did not plan a subnet migration: %s %#v", h.options.Approved.Mode, h.options.Approved)
	}
}

// TestSubnetMigrationQuiescesBotBeforeReadingPeerState is the ordering the
// bot-backed move depends on. The bot creates a peer file at the last moment
// before it stops; that file must be seen by the migration. Read before the
// stop, it would be left on the old subnet outside the transaction. Here the
// late peer has no live counterpart, so seeing it means refusing — and a
// refusal after the stop must bring the bot back without writing anything.
func TestSubnetMigrationQuiescesBotBeforeReadingPeerState(t *testing.T) {
	h := newHarness(t)
	h.enableBot(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	configBefore := digestFile(t, h.layout.ConfigPath())
	secretsBefore := digestFile(t, h.layout.SecretsPath())
	h.botSubnetMove(t)
	peerDir := filepath.Join(h.layout.BotDataDir(), "awg")
	h.compose.onStop = func(string) {
		if err := os.MkdirAll(peerDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(peerDir, "late.json"), []byte(`{"priv":"private","pub":"public","ip":"10.10.0.17"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h.compose.calls = nil
	_, err := Run(context.Background(), h.options)
	if err == nil || !strings.Contains(err.Error(), "no matching live peer") {
		t.Fatalf("a peer written just before the bot stopped was not seen: %v", err)
	}
	if got, want := strings.Join(h.compose.calls, ","), "stop:vpn-bot,up"; got != want {
		t.Fatalf("compose calls = %s, want %s", got, want)
	}
	if digestFile(t, h.layout.ConfigPath()) != configBefore || digestFile(t, h.layout.SecretsPath()) != secretsBefore {
		t.Fatal("refused bot-backed migration changed credential files")
	}
}

// TestBotBackedSubnetMigrationStopsBotThenRecreates pins the happy path's
// sequence: quiesce, write, then the force-recreate that restarts the bot on
// the migrated state.
func TestBotBackedSubnetMigrationStopsBotThenRecreates(t *testing.T) {
	h := newHarness(t)
	h.enableBot(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	h.botSubnetMove(t)
	h.compose.calls = nil
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(h.compose.calls, ","), "stop:vpn-bot,pull,recreate"; got != want {
		t.Fatalf("compose calls = %s, want %s", got, want)
	}
}

func TestSupportedMigrationPreservesLiveCredentials(t *testing.T) {
	h := newHarness(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	// Simulate a user provisioned after installation: it exists in the core's
	// authoritative config, but not in the one-time secrets.json handover.
	initial, err := config.Unmarshal(context.Background(), mustRead(t, h.layout.ConfigPath()))
	if err != nil {
		t.Fatal(err)
	}
	liveCredentials, err := profile.SecretsFromConfig(initial)
	if err != nil {
		t.Fatal(err)
	}
	liveSpec, err := h.options.Desired.DeploymentSpec([]string{"eth0"}, h.options.Secrets.Resolver())
	if err != nil {
		t.Fatal(err)
	}
	liveSpec.Users = append(liveCredentials.Names(), "bot-user")
	expanded, err := profile.Regenerate(liveSpec, liveCredentials)
	if err != nil {
		t.Fatal(err)
	}
	expandedJSON, err := config.Marshal(context.Background(), expanded.Options)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.layout.ConfigPath(), expandedJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	configBefore := mustRead(t, h.layout.ConfigPath())
	secretsBefore := digestFile(t, h.layout.SecretsPath())
	var handoverBefore profile.Secrets
	if err := json.Unmarshal(mustRead(t, h.layout.SecretsPath()), &handoverBefore); err != nil {
		t.Fatal(err)
	}
	parsedBefore, err := config.Unmarshal(context.Background(), configBefore)
	if err != nil {
		t.Fatal(err)
	}
	credentialsBefore, err := profile.SecretsFromConfig(parsedBefore)
	if err != nil {
		t.Fatal(err)
	}

	previous := h.options.Desired
	previous.Deployment.Ports = maps.Clone(previous.Deployment.Ports)
	desired := h.options.Desired
	desired.Deployment.Ports[profile.AWG2]++
	h.options.Desired = desired
	h.installed(t, previous)
	h.replan(t)
	if h.options.Approved.Mode != plan.ModeMigrate {
		t.Fatalf("port change mode = %q, want migrate", h.options.Approved.Mode)
	}

	applyCalls := 0
	h.options.ApplyRuntime = func(context.Context) error {
		applyCalls++
		if digestFile(t, h.layout.ConfigPath()) == digestOf(configBefore) {
			t.Fatal("management apply ran before the migrated config was written")
		}
		return nil
	}
	h.compose.calls = nil
	result, err := Run(context.Background(), h.options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != plan.ModeMigrate || applyCalls != 1 {
		t.Fatalf("result mode=%q management calls=%d", result.Mode, applyCalls)
	}
	// Every credential a client holds is unchanged; the facts it renders
	// links from follow the migration, or `clients` would hand out the old
	// port.
	_ = secretsBefore
	var handoverAfter profile.Secrets
	if err := json.Unmarshal(mustRead(t, h.layout.SecretsPath()), &handoverAfter); err != nil {
		t.Fatal(err)
	}
	if handoverAfter.Deployment.Ports[profile.AWG2] != desired.Deployment.Ports[profile.AWG2] {
		t.Fatalf("secrets.json still names port %d", handoverAfter.Deployment.Ports[profile.AWG2])
	}
	for i, user := range handoverBefore.Users {
		if !reflect.DeepEqual(user, handoverAfter.Users[i]) {
			t.Fatalf("migration changed %s's credentials in secrets.json", user.Name)
		}
	}
	if !reflect.DeepEqual(handoverBefore.Endpoints[profile.AWG2].PrivateKey, handoverAfter.Endpoints[profile.AWG2].PrivateKey) {
		t.Fatal("migration changed an endpoint key in secrets.json")
	}
	parsedAfter, err := config.Unmarshal(context.Background(), mustRead(t, h.layout.ConfigPath()))
	if err != nil {
		t.Fatal(err)
	}
	credentialsAfter, err := profile.SecretsFromConfig(parsedAfter)
	if err != nil {
		t.Fatal(err)
	}
	credentialsBefore.Deployment = profile.DeploymentFacts{}
	credentialsAfter.Deployment = profile.DeploymentFacts{}
	for protocol, endpoint := range credentialsBefore.Endpoints {
		endpoint.ListenPort = 0
		credentialsBefore.Endpoints[protocol] = endpoint
	}
	for protocol, endpoint := range credentialsAfter.Endpoints {
		endpoint.ListenPort = 0
		credentialsAfter.Endpoints[protocol] = endpoint
	}
	if !reflect.DeepEqual(credentialsBefore, credentialsAfter) {
		t.Fatal("migration changed an existing server-side credential")
	}
	if !reflect.DeepEqual(credentialsAfter.Names(), []string{"bot-user", "owner"}) {
		t.Fatalf("live users after migration = %v; bot-created user was lost", credentialsAfter.Names())
	}
	if got, want := strings.Join(h.compose.calls, ","), "pull,up"; got != want {
		t.Fatalf("compose calls = %s, want %s", got, want)
	}
}

func TestRestartMigrationRecreatesAndPreservesCredentials(t *testing.T) {
	h := newHarness(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	configBefore := digestFile(t, h.layout.ConfigPath())
	secretsBefore := digestFile(t, h.layout.SecretsPath())

	previous := h.options.Desired
	desired := h.options.Desired
	desired.Deployment.LogLevel = "trace"
	h.options.Desired = desired
	h.installed(t, previous)
	h.replan(t)
	if h.options.Approved.Mode != plan.ModeRestartMigrate {
		t.Fatalf("log-level change mode = %q, want restart-migrate", h.options.Approved.Mode)
	}
	managementCalls := 0
	h.options.ApplyRuntime = func(context.Context) error {
		managementCalls++
		return errors.New("management API must not apply a restart migration")
	}
	h.compose.calls = nil
	result, err := Run(context.Background(), h.options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != plan.ModeRestartMigrate {
		t.Fatalf("result mode = %q, want restart-migrate", result.Mode)
	}
	if got, want := strings.Join(h.compose.calls, ","), "pull,recreate"; got != want {
		t.Fatalf("compose calls = %s, want %s", got, want)
	}
	if managementCalls != 0 {
		t.Fatalf("management API calls = %d, want 0", managementCalls)
	}
	if digestFile(t, h.layout.ConfigPath()) == configBefore {
		t.Fatal("restart migration did not replace config.json")
	}
	if digestFile(t, h.layout.SecretsPath()) != secretsBefore {
		t.Fatal("restart migration rewrote the client handover snapshot")
	}
}

func TestFailedRestartMigrationRecreatesPreviousGeneration(t *testing.T) {
	h := newHarness(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	configBefore := digestFile(t, h.layout.ConfigPath())

	previous := h.options.Desired
	desired := h.options.Desired
	desired.Deployment.LogLevel = "trace"
	h.options.Desired = desired
	h.installed(t, previous)
	h.replan(t)
	h.options.SelfTest = func(context.Context, io.Writer) error { return errors.New("restart proof failed") }
	h.compose.calls = nil
	if _, err := Run(context.Background(), h.options); err == nil {
		t.Fatal("restart migration succeeded although its self-test failed")
	}
	if got := digestFile(t, h.layout.ConfigPath()); got != configBefore {
		t.Fatal("failed restart migration did not restore the previous config")
	}
	if got, want := strings.Join(h.compose.calls, ","), "pull,recreate,recreate"; got != want {
		t.Fatalf("compose calls = %s, want %s", got, want)
	}
}

func TestInterruptedRestartRecoveryRecreatesWithoutRewritingConfig(t *testing.T) {
	h := newHarness(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	configBefore := digestFile(t, h.layout.ConfigPath())
	previous := h.options.Desired
	h.installed(t, previous)
	h.observed.Runtime.RecreatePending = true
	h.replan(t)
	if h.options.Approved.Mode != plan.ModeRestartRecover {
		t.Fatalf("mode = %q, want restart-recover", h.options.Approved.Mode)
	}
	managementCalls := 0
	h.options.ApplyRuntime = func(context.Context) error {
		managementCalls++
		return errors.New("restart recovery must not use the live API")
	}
	h.compose.calls = nil
	result, err := Run(context.Background(), h.options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != plan.ModeRestartRecover {
		t.Fatalf("result mode = %q, want restart-recover", result.Mode)
	}
	if got, want := strings.Join(h.compose.calls, ","), "pull,recreate"; got != want {
		t.Fatalf("compose calls = %s, want %s", got, want)
	}
	if managementCalls != 0 {
		t.Fatalf("management calls = %d, want 0", managementCalls)
	}
	if digestFile(t, h.layout.ConfigPath()) != configBefore {
		t.Fatal("restart recovery rewrote the restored runtime config")
	}
	receipt, _, err := h.options.Manager.Current()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.RecreatePending {
		t.Fatal("successful restart recovery did not clear the receipt marker")
	}
}

func TestFailedMigrationRestoresAndResynchronisesThePreviousConfig(t *testing.T) {
	h := newHarness(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	configBefore := digestFile(t, h.layout.ConfigPath())

	previous := h.options.Desired
	previous.Deployment.Ports = maps.Clone(previous.Deployment.Ports)
	desired := h.options.Desired
	desired.Deployment.Ports[profile.AWG2]++
	h.options.Desired = desired
	h.installed(t, previous)
	h.replan(t)

	applyCalls := 0
	h.options.ApplyRuntime = func(context.Context) error {
		applyCalls++
		return nil
	}
	h.options.SelfTest = func(context.Context, io.Writer) error { return errors.New("no detection") }
	h.compose.calls = nil
	if _, err := Run(context.Background(), h.options); err == nil {
		t.Fatal("migration succeeded although its live proof failed")
	}
	if got := digestFile(t, h.layout.ConfigPath()); got != configBefore {
		t.Fatal("failed migration did not restore the previous config")
	}
	if applyCalls != 2 {
		t.Fatalf("management apply calls = %d, want migrated then restored", applyCalls)
	}
	if got, want := strings.Join(h.compose.calls, ","), "pull,up,up"; got != want {
		t.Fatalf("compose calls = %s, want %s", got, want)
	}
	stored, err := state.Load(h.layout.DesiredPath())
	if err != nil {
		t.Fatal(err)
	}
	storedDigest, err := stored.Digest()
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := previous.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if storedDigest != wantDigest {
		t.Fatal("failed migration did not restore the previous desired state")
	}
}

// TestFailedConvergenceRestartsThePreviousDeployment. A fresh install's failure
// ends with nothing running; a convergence's failure must end with the previous
// deployment running again. Using one procedure for both is how a failed update
// takes a working server offline.
func TestFailedConvergenceRestartsThePreviousDeployment(t *testing.T) {
	h := newHarness(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	configBefore := digestFile(t, h.layout.ConfigPath())
	composeBefore := digestFile(t, h.layout.ComposePath())

	previous := h.options.Desired
	desired := h.options.Desired
	desired.Deployment.Image = "registry.example/spaiter-vpn-core:next"
	h.options.Desired = desired
	h.installed(t, previous)
	h.replan(t)

	h.compose.calls = nil
	h.options.SelfTest = func(context.Context, io.Writer) error { return errors.New("no detection") }
	_, err := Run(context.Background(), h.options)
	if err == nil {
		t.Fatal("the convergence reported success although the self-test failed")
	}
	if strings.Contains(err.Error(), "rollback incomplete") {
		t.Fatalf("the rollback did not finish: %v", err)
	}
	if strings.Contains(strings.Join(h.compose.calls, ","), "down") {
		t.Fatalf("a failed convergence stopped the deployment: %v", h.compose.calls)
	}
	// pull, up (the new generation), then up again to restore the previous one.
	if got, want := strings.Join(h.compose.calls, ","), "pull,up,up"; got != want {
		t.Fatalf("compose calls = %s, want %s", got, want)
	}
	if got := digestFile(t, h.layout.ComposePath()); got != composeBefore {
		t.Error("the previous compose project was not restored")
	}
	if got := digestFile(t, h.layout.ConfigPath()); got != configBefore {
		t.Error("the failed convergence disturbed the live configuration")
	}
}

func digestFile(t *testing.T, path string) string {
	t.Helper()
	sum := sha256.Sum256(mustRead(t, path))
	return hex.EncodeToString(sum[:])
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertNothingWritten(t *testing.T, h *harness) {
	t.Helper()
	for _, path := range h.layout.ManagedFiles() {
		if _, err := os.Stat(path); err == nil {
			t.Errorf("%s exists although the apply did not succeed", path)
		} else if !os.IsNotExist(err) {
			t.Errorf("%s: %v", path, err)
		}
	}
}

func readyObservation(t *testing.T, desired state.State) discover.Observed {
	t.Helper()
	spec, err := desired.PreflightSpec([]string{"eth0"})
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]string{}
	required := []string{}
	for _, rule := range firewall.Rules(spec) {
		rules[rule.String()] = "allowed"
		required = append(required, rule.String())
	}
	var botUser *discover.SystemUser
	if desired.Bot.Enabled && desired.Bot.DedicatedUser {
		botUser = &discover.SystemUser{Name: "spaiter-vpn-bot", Exists: true, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	}
	return discover.Observed{
		BotUser:          botUser,
		APIVersion:       discover.ObservationVersion,
		Platform:         discover.Platform{OS: "linux", Arch: "amd64", ID: "ubuntu", VersionID: "24.04", Systemd: true},
		Privileges:       discover.Privileges{EUID: 0},
		Docker:           discover.Docker{CLIAvailable: true, DaemonReachable: true, ComposeAvailable: true, ServerVersion: "27.5.1"},
		Network:          discover.Network{DefaultInterface: "eth0"},
		Firewall:         discover.Firewall{Kind: "ufw", Active: true, Readable: true, Required: required, Rules: rules, Detail: "fixture"},
		ExistingDesired:  discover.ExistingDesired{Status: discover.FileAbsent},
		Runtime:          discover.Runtime{Config: absent(), Secrets: absent(), Compose: absent(), Receipt: absent()},
		Credentials:      map[state.SecretRef]discover.File{},
		CertificateFiles: map[string]discover.File{},
		Logrotate:        absent(),
	}
}

func absent() discover.File { return discover.File{Status: discover.FileAbsent} }

// TestCredentialIsResolvedNotPlaceheld. PreflightSpec fills credentials with a
// non-secret marker so a document can be reviewed without root, and generating
// from that spec would write "credential-present" into a live config as the
// Cloudflare token — a deployment that looks correct until its first renewal.
func TestCredentialIsResolvedNotPlaceheld(t *testing.T) {
	h := newHarness(t)
	const token = "cf-token-value-0123456789"

	desired := h.desired
	desired.Deployment.Tier = profile.TierB
	desired.Deployment.Domain = "vpn.example.com"
	desired.Deployment.Certificates = &state.Certificates{
		Source: profile.CertSourceACMEDNS,
		ACMEDNS: &state.ACMEDNS{
			Email:         "ops@example.com",
			Directory:     state.ACMEDefaultProvider,
			DataDirectory: profile.ACMEDefaultDataDirectory,
			Provider:      "cloudflare",
			Cloudflare:    &state.CloudflareDNS{APIToken: "cloudflare-token"},
		},
	}
	if err := os.MkdirAll(h.layout.CredentialDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.layout.CredentialDir(), "cloudflare-token"), []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	h.observed = readyObservation(t, desired)
	h.observed.Credentials["cloudflare-token"] = discover.File{
		Status: discover.FileRegular, Mode: 0o600, UID: 0, Size: int64(len(token)),
	}
	approved, err := plan.Build(desired, h.observed)
	if err != nil {
		t.Fatal(err)
	}
	h.options.Desired = desired
	h.options.Approved = approved

	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(h.layout.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), "credential-present") {
		t.Fatal("the validation placeholder was written into the generated config")
	}
	if !strings.Contains(string(config), token) {
		t.Fatal("the resolved credential did not reach the generated config")
	}
	// And it must not leak into the files that are not 0600.
	for _, path := range []string{h.layout.DesiredPath(), h.layout.ComposePath(), h.layout.EnvPath()} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), token) {
			t.Fatalf("%s contains the credential value", path)
		}
	}
}

// TestMigrationRetiresTheRuleItOpenedEarlier. A port move that opens the new
// door and leaves the old one open is the gap the receipt exists to close: the
// stale allow outlives every later generation, and it is misleading precisely
// when the reason for moving was that the port was blocked.
func TestMigrationRetiresTheRuleItOpenedEarlier(t *testing.T) {
	h := newHarness(t)
	blocked := blockFirewallRule(h, t)
	fw := &fakeFirewall{}
	h.options.Firewall = fw
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if len(fw.added) != 1 || fw.added[0] != blocked {
		t.Fatalf("added = %v, want %s", fw.added, blocked)
	}
	// The receipt must now say the deployment owns it; nothing else can make
	// closing it later safe.
	if !slices.Contains(ownedFirewall(t, h), blocked) {
		t.Fatalf("the receipt does not record %s as ours: %v", blocked, ownedFirewall(t, h))
	}

	// Move that protocol's port. The old rule is ours and unwanted, so it is
	// retired; the new one is wanted and absent, so it is opened.
	// Snapshot BEFORE moving the port, with the map cloned: state.State shares
	// its maps, so capturing afterwards gives a "previous" that already has the
	// change and the diff comes out empty — reconcile instead of migrate.
	previous := h.options.Desired
	previous.Deployment.Ports = maps.Clone(previous.Deployment.Ports)
	port, network, _ := strings.Cut(blocked, "/")
	moved := nextPortFor(t, h, port, network)
	h.installed(t, previous)
	// The new port is not allowed yet; the old one still is.
	h.observed.Firewall.Rules[blocked] = "allowed"
	h.observed.Firewall.Rules[moved] = "blocked"
	h.replan(t)
	if h.options.Approved.Mode != plan.ModeMigrate {
		t.Fatalf("mode = %q, want migrate", h.options.Approved.Mode)
	}

	fw.added, fw.removed = nil, nil
	result, err := Run(context.Background(), h.options)
	if err != nil {
		t.Fatalf("the port migration failed: %v", err)
	}
	if !slices.Contains(fw.added, moved) {
		t.Errorf("the new port was not opened: added=%v", fw.added)
	}
	if !slices.Contains(fw.removed, blocked) {
		t.Errorf("the old port was not closed: removed=%v", fw.removed)
	}
	if !slices.Contains(result.FirewallRetired, blocked) {
		t.Errorf("the result does not report the retirement: %v", result.FirewallRetired)
	}
	owned := ownedFirewall(t, h)
	if slices.Contains(owned, blocked) {
		t.Errorf("the receipt still claims the retired rule: %v", owned)
	}
	if !slices.Contains(owned, moved) {
		t.Errorf("the receipt does not claim the new rule: %v", owned)
	}
}

// TestARuleWeDoNotOwnIsNeverClosed. The operator's own rules are not ours to
// delete, however unwanted they look — that is the difference between managing
// a firewall and cutting somebody's SSH.
func TestARuleWeDoNotOwnIsNeverClosed(t *testing.T) {
	h := newHarness(t)
	fw := &fakeFirewall{}
	h.options.Firewall = fw
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}

	previous := h.options.Desired
	h.installed(t, previous)
	// Something the operator opened that this deployment never wanted.
	h.observed.Firewall.Rules["22/tcp"] = "allowed"
	h.replan(t)
	fw.added, fw.removed = nil, nil
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if len(fw.removed) != 0 {
		t.Fatalf("closed rules this deployment does not own: %v", fw.removed)
	}
}

// TestAFailedMigrationReopensWhatItClosed. Otherwise the previous deployment
// comes back unreachable on the only port its clients know, which is worse
// than the failure that triggered the rollback.
func TestAFailedMigrationReopensWhatItClosed(t *testing.T) {
	h := newHarness(t)
	blocked := blockFirewallRule(h, t)
	fw := &fakeFirewall{}
	h.options.Firewall = fw
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}

	// Snapshot BEFORE moving the port, with the map cloned: state.State shares
	// its maps, so capturing afterwards gives a "previous" that already has the
	// change and the diff comes out empty — reconcile instead of migrate.
	previous := h.options.Desired
	previous.Deployment.Ports = maps.Clone(previous.Deployment.Ports)
	port, network, _ := strings.Cut(blocked, "/")
	moved := nextPortFor(t, h, port, network)
	h.installed(t, previous)
	h.observed.Firewall.Rules[blocked] = "allowed"
	h.observed.Firewall.Rules[moved] = "blocked"
	h.replan(t)

	fw.added, fw.removed = nil, nil
	h.options.SelfTest = func(context.Context, io.Writer) error { return errors.New("no detection") }
	if _, err := Run(context.Background(), h.options); err == nil {
		t.Fatal("the migration reported success although the self-test failed")
	}
	// Undone symmetrically: the new rule closed again, the old one re-opened.
	if !slices.Contains(fw.removed, moved) {
		t.Errorf("the rule this apply opened was not closed again: removed=%v", fw.removed)
	}
	if !slices.Contains(fw.added, blocked) {
		t.Errorf("the rule this apply retired was not re-opened: added=%v", fw.added)
	}
}

func ownedFirewall(t *testing.T, h *harness) []string {
	t.Helper()
	data, err := os.ReadFile(h.layout.CurrentReceiptPath())
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		Firewall []string `json:"firewall"`
	}
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt.Firewall
}

// nextPortFor moves the protocol that binds the given port to a free one and
// returns the new rule string.
//
// A free one, not port+1: the generated defaults are consecutive, so bumping by
// one lands on the next protocol's port and the profile refuses the spec for
// assigning two protocols the same port — a failure that looks like the
// firewall logic being wrong.
func nextPortFor(t *testing.T, h *harness, port, network string) string {
	t.Helper()
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	desired := h.options.Desired
	desired.Deployment.Ports = maps.Clone(desired.Deployment.Ports)
	taken := map[uint16]bool{}
	for _, assigned := range desired.Deployment.Ports {
		taken[assigned] = true
	}
	free := uint16(29000)
	for taken[free] {
		free++
	}
	moved := false
	for protocol, assigned := range desired.Deployment.Ports {
		if assigned == uint16(value) {
			desired.Deployment.Ports[protocol] = free
			moved = true
		}
	}
	if !moved {
		t.Fatalf("no protocol binds port %s, so there is nothing to move", port)
	}
	h.options.Desired = desired
	return strconv.FormatUint(uint64(free), 10) + "/" + network
}

func TestSeedUserMigrationPreservesExistingAndBotUsersWhileAddingAndRetiring(t *testing.T) {
	h := newHarness(t)
	h.options.Desired = state.Default([]string{"owner", "guest"})
	h.enableBot(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}

	var beforeSecrets profile.Secrets
	if err := json.Unmarshal(mustRead(t, h.layout.SecretsPath()), &beforeSecrets); err != nil {
		t.Fatal(err)
	}
	ownerBefore := beforeSecrets.Users[0]

	// Add a bot-provisioned user "42" to the live config.json and bot/awg/42.json.
	parsed, err := config.Unmarshal(context.Background(), mustRead(t, h.layout.ConfigPath()))
	if err != nil {
		t.Fatal(err)
	}
	live, err := profile.SecretsFromConfig(parsed)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := h.options.Desired.DeploymentSpec([]string{"eth0"}, h.options.Secrets.Resolver())
	if err != nil {
		t.Fatal(err)
	}
	spec.Users = append(live.Names(), "42")
	expanded, err := profile.Regenerate(spec, live)
	if err != nil {
		t.Fatal(err)
	}
	configJSON, err := config.Marshal(context.Background(), expanded.Options)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.layout.ConfigPath(), configJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	var botUser profile.UserSecrets
	for _, user := range expanded.Secrets.Users {
		if user.Name == "42" {
			botUser = user
		}
	}
	peerDir := filepath.Join(h.layout.BotDataDir(), "awg")
	if err := os.MkdirAll(peerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	peerPath := filepath.Join(peerDir, "42.json")
	peer := botUser.Peers[profile.AWG2]
	peerJSON, _ := json.Marshal(botstate.Peer{Priv: peer.PrivateKey, Pub: peer.PublicKey, IP: peer.Address.Addr().String()})
	if err := os.WriteFile(peerPath, peerJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(h.layout.BotDataDir(), "wdtt", "subs-cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(cacheDir, "token.json")
	if err := os.WriteFile(cachePath, []byte(`{"outbounds":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	previous := h.options.Desired
	desired := previous
	desired.Bootstrap.SeedUsers = []string{"owner", "newcomer"}
	desired.MigrationPolicy = &state.MigrationPolicy{
		SeedUsers: &state.SeedUsersMigration{
			From:     []string{"owner", "guest"},
			To:       []string{"owner", "newcomer"},
			Strategy: state.SeedUsersStrategyPreserveExisting,
		},
	}
	h.options.Desired = desired
	h.installed(t, previous)
	h.observeBotCredential()
	h.replan(t)
	if h.options.Approved.Mode != plan.ModeMigrate {
		t.Fatalf("mode = %q, want migrate", h.options.Approved.Mode)
	}
	h.compose.calls = nil
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(h.compose.calls, ","), "stop:vpn-bot,pull,up"; got != want {
		t.Fatalf("compose calls = %s, want %s", got, want)
	}
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Fatalf("subscription cache was not invalidated after retiring seed user: %v", err)
	}

	var afterSecrets profile.Secrets
	if err := json.Unmarshal(mustRead(t, h.layout.SecretsPath()), &afterSecrets); err != nil {
		t.Fatal(err)
	}
	if got := afterSecrets.Names(); !slices.Equal(got, []string{"owner", "newcomer"}) {
		t.Fatalf("secrets.json users = %v, want [owner newcomer]", got)
	}
	if afterSecrets.Users[0].VLESSRealityUUID != ownerBefore.VLESSRealityUUID ||
		afterSecrets.Users[0].Peers[profile.AWG2] != ownerBefore.Peers[profile.AWG2] {
		t.Fatalf("owner credentials changed in secrets.json: got %#v, want %#v", afterSecrets.Users[0], ownerBefore)
	}
	newcomerSecrets := afterSecrets.Users[1]
	if newcomerSecrets.Peers[profile.AWG2].PrivateKey == "" ||
		newcomerSecrets.Peers[profile.AWG2].Address == ownerBefore.Peers[profile.AWG2].Address ||
		newcomerSecrets.Peers[profile.AWG2].Address == botUser.Peers[profile.AWG2].Address {
		t.Fatalf("newcomer AWG2 peer = %#v collides or lacks private key", newcomerSecrets.Peers[profile.AWG2])
	}

	afterParsed, err := config.Unmarshal(context.Background(), mustRead(t, h.layout.ConfigPath()))
	if err != nil {
		t.Fatal(err)
	}
	afterLive, err := profile.SecretsFromConfig(afterParsed)
	if err != nil {
		t.Fatal(err)
	}
	if got := afterLive.Names(); !slices.Equal(got, []string{"42", "newcomer", "owner"}) {
		t.Fatalf("live config.json users = %v, want [42 newcomer owner]", got)
	}

	// Retaining migrationPolicy.seedUsers as an audit record must not block a
	// subsequent live port migration.
	applied := desired
	followUp := applied
	followUp.Deployment.Ports = maps.Clone(applied.Deployment.Ports)
	followUp.Deployment.Ports[profile.AWG2]++
	h.options.Desired = followUp
	h.installed(t, applied)
	h.observeBotCredential()
	h.replan(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatalf("follow-up migration with retained seedUsers policy failed: %v", err)
	}
}

func TestFailedSeedUserMigrationRestoresBothConfigAndSecrets(t *testing.T) {
	h := newHarness(t)
	h.options.Desired = state.Default([]string{"owner", "guest"})
	h.replan(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	configBefore := digestFile(t, h.layout.ConfigPath())
	secretsBefore := digestFile(t, h.layout.SecretsPath())

	previous := h.options.Desired
	desired := previous
	desired.Bootstrap.SeedUsers = []string{"owner", "newcomer"}
	desired.MigrationPolicy = &state.MigrationPolicy{
		SeedUsers: &state.SeedUsersMigration{
			From:     []string{"owner", "guest"},
			To:       []string{"owner", "newcomer"},
			Strategy: state.SeedUsersStrategyPreserveExisting,
		},
	}
	h.options.Desired = desired
	h.installed(t, previous)
	h.replan(t)
	h.options.SelfTest = func(context.Context, io.Writer) error { return errors.New("selftest failed") }
	if _, err := Run(context.Background(), h.options); err == nil {
		t.Fatal("seedUsers migration succeeded despite failed self-test")
	}
	if digestFile(t, h.layout.ConfigPath()) != configBefore || digestFile(t, h.layout.SecretsPath()) != secretsBefore {
		t.Fatal("failed seedUsers migration did not restore both config.json and secrets.json")
	}
}
