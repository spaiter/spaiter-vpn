package apply

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/dockerinstall"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/health"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

func TestTheWDTTConfigDirectoryMustBeARealDirectoryHoldingARegularPasswordsFile(t *testing.T) {
	o := Options{}
	if err := o.validateWDTTConfigPath(); err != nil {
		t.Errorf("unset: %v", err)
	}
	set := func(dir string) Options {
		var desired state.State
		desired.Bot.WDTTConfigDirectory = dir
		return Options{Desired: desired}
	}

	root := t.TempDir()
	if err := set(filepath.Join(root, "absent")).validateWDTTConfigPath(); err == nil || !strings.Contains(err.Error(), "inspect bot.wdttConfigDirectory") {
		t.Errorf("absent directory: %v", err)
	}
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := set(file).validateWDTTConfigPath(); err == nil || !strings.Contains(err.Error(), "not a real directory") {
		t.Errorf("a file as directory: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if err := set(link).validateWDTTConfigPath(); err == nil || !strings.Contains(err.Error(), "not a real directory") {
		t.Errorf("a symlinked directory: %v", err)
	}

	dir := filepath.Join(root, "wdtt")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := set(dir).validateWDTTConfigPath(); err == nil || !strings.Contains(err.Error(), "inspect WG-over-VK relay passwords") {
		t.Errorf("no passwords file: %v", err)
	}
	passwords := filepath.Join(dir, "passwords.json")
	if err := os.Symlink(file, passwords); err != nil {
		t.Fatal(err)
	}
	if err := set(dir).validateWDTTConfigPath(); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("symlinked passwords: %v", err)
	}
	os.Remove(passwords)
	if err := os.WriteFile(passwords, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := set(dir).validateWDTTConfigPath(); err != nil {
		t.Errorf("valid: %v", err)
	}
}

func TestDesiredStateIsStoredInCanonicalForm(t *testing.T) {
	desired := state.Default([]string{"owner"})
	data, err := canonicalDesiredJSON(desired)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(data), "}\n") || !json.Valid(data) {
		t.Errorf("not an indented document ending in a newline: %q", data)
	}
	again, _ := canonicalDesiredJSON(desired)
	if string(again) != string(data) {
		t.Error("canonical form is not stable")
	}
	if _, err := canonicalDesiredJSON(state.State{}); err == nil {
		t.Error("an empty state was canonicalised")
	}
}

func TestTheReadinessWaitBuildsItsProbeFromTheLiveConfigOrFails(t *testing.T) {
	h := newHarness(t)
	o := h.options
	o.Probe = nil
	o.Health = func(context.Context, health.Options) (*health.Report, error) {
		t.Fatal("health ran without a probe")
		return nil, nil
	}
	if _, err := o.waitHealthy(context.Background(), []string{"sing-box"}); err == nil || !strings.Contains(err.Error(), "build the management probe") {
		t.Errorf("no config on disk: %v", err)
	}

	// With a probe supplied the wait hands everything to health, unchanged.
	var got health.Options
	want := &health.Report{}
	o.Probe = func(context.Context) error { return nil }
	o.Health = func(_ context.Context, options health.Options) (*health.Report, error) {
		got = options
		return want, nil
	}
	report, err := o.waitHealthy(context.Background(), []string{"sing-box", "bot"})
	if err != nil || report != want {
		t.Fatalf("report=%v err=%v", report, err)
	}
	if got.Project != o.Layout.ComposePath() || len(got.Services) != 2 || got.Probe == nil || got.Compose == nil {
		t.Errorf("health options = %+v", got)
	}
}

func TestApplyRuntimeUsesTheInjectedHookOrNeedsALiveConfig(t *testing.T) {
	h := newHarness(t)
	o := h.options
	boom := errors.New("hook failed")
	o.ApplyRuntime = func(context.Context) error { return boom }
	if err := o.applyRuntime(context.Background()); !errors.Is(err, boom) {
		t.Errorf("hook: %v", err)
	}
	o.ApplyRuntime = nil
	if err := o.applyRuntime(context.Background()); err == nil {
		t.Error("applyRuntime without a config succeeded")
	}
}

func dockerPlan(h *harness, id string) recomputed {
	current := h.options.Approved
	current.Actions = append(append([]plan.Action(nil), current.Actions...), plan.Action{ID: id, Disposition: plan.Apply})
	return recomputed{Plan: current, observed: h.observed}
}

func TestInstallingDockerIsSkippedWhenNoActionAsksForIt(t *testing.T) {
	h := newHarness(t)
	h.options.InstallDocker = func(context.Context, dockerinstall.Release, bool) (dockerinstall.Record, error) {
		t.Fatal("installed Docker unasked")
		return dockerinstall.Record{}, nil
	}
	current := recomputed{Plan: h.options.Approved, observed: h.observed}
	got, err := h.options.installDockerIfPlanned(context.Background(), current)
	if err != nil || got.Mode != current.Mode {
		t.Errorf("got %v, %v", got.Mode, err)
	}
	// A verify-only docker action is not a request either.
	current.Actions = append(current.Actions, plan.Action{ID: "docker-install", Disposition: plan.Verify})
	if _, err := h.options.installDockerIfPlanned(context.Background(), current); err != nil {
		t.Error(err)
	}
}

func TestInstallingDockerRefusesWhatItCannotPinAndWhatChangedBeneathIt(t *testing.T) {
	ctx := context.Background()
	noInstall := func(context.Context, dockerinstall.Release, bool) (dockerinstall.Record, error) {
		return dockerinstall.Record{}, nil
	}

	// A platform with no pinned packages.
	h := newHarness(t)
	h.observed.Platform.ID, h.observed.Platform.VersionID = "plan9", "4"
	h.options.InstallDocker = func(context.Context, dockerinstall.Release, bool) (dockerinstall.Record, error) {
		t.Fatal("installed on an unsupported platform")
		return dockerinstall.Record{}, nil
	}
	if _, err := h.options.installDockerIfPlanned(ctx, dockerPlan(h, "docker-install")); err == nil || !strings.Contains(err.Error(), "no pinned Docker packages") {
		t.Errorf("unsupported platform: %v", err)
	}

	// Discovery failing after the install.
	h = newHarness(t)
	h.options.InstallDocker = noInstall
	boom := errors.New("rediscovery failed")
	h.options.Discover = func(context.Context, state.State) (discover.Observed, error) { return discover.Observed{}, boom }
	if _, err := h.options.installDockerIfPlanned(ctx, dockerPlan(h, "docker-compose-install")); !errors.Is(err, boom) {
		t.Errorf("rediscovery: %v", err)
	}

	// Something other than Docker moved while it ran.
	h = newHarness(t)
	h.options.InstallDocker = noInstall
	h.options.Discover = func(context.Context, state.State) (discover.Observed, error) {
		moved := h.observed
		moved.Network.DefaultInterface = "eth9"
		return moved, nil
	}
	if _, err := h.options.installDockerIfPlanned(ctx, dockerPlan(h, "docker-install")); !errors.Is(err, ErrStaleConsent) {
		t.Errorf("host changed: %v", err)
	}

	// The plan no longer matches the one approved.
	h = newHarness(t)
	h.options.InstallDocker = noInstall
	current := dockerPlan(h, "docker-install")
	current.Mode = plan.Mode("something-else")
	if _, err := h.options.installDockerIfPlanned(ctx, current); err == nil || !strings.Contains(err.Error(), "not the approved") {
		t.Errorf("mode drift: %v", err)
	}

	// Docker is installed and the plan matches: the new plan replaces the old.
	h = newHarness(t)
	h.options.InstallDocker = noInstall
	current = dockerPlan(h, "docker-install")
	got, err := h.options.installDockerIfPlanned(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range got.Actions {
		if action.ID == "docker-install" {
			t.Error("the rebuilt plan still carries the install")
		}
	}

	// A record that cannot be written is reported together with the install error.
	h = newHarness(t)
	h.options.Layout.DataRoot = filepath.Join(h.options.Layout.DataRoot, "blocked")
	if err := os.MkdirAll(filepath.Dir(h.options.Layout.DataRoot), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.options.Layout.DataRoot, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h.options.InstallDocker = func(context.Context, dockerinstall.Release, bool) (dockerinstall.Record, error) {
		return dockerinstall.Record{Packages: map[string]string{"docker-ce": "1"}}, errors.New("daemon did not answer")
	}
	_, err = h.options.installDockerIfPlanned(ctx, dockerPlan(h, "docker-install"))
	if err == nil || !strings.Contains(err.Error(), "record the Docker installation") || !strings.Contains(err.Error(), "daemon did not answer") {
		t.Errorf("unrecorded install: %v", err)
	}
}
