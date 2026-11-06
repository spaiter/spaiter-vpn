package apply

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
)

type fakeSystemd struct{ calls []string }

func (f *fakeSystemd) Reload(context.Context) error { f.calls = append(f.calls, "reload"); return nil }
func (f *fakeSystemd) Start(_ context.Context, unit string) error {
	f.calls = append(f.calls, "start:"+unit)
	return nil
}
func (f *fakeSystemd) Restart(_ context.Context, unit string) error {
	f.calls = append(f.calls, "restart:"+unit)
	return nil
}
func (f *fakeSystemd) Stop(_ context.Context, unit string) error {
	f.calls = append(f.calls, "stop:"+unit)
	return nil
}

func controlHarness(t *testing.T) (*harness, *fakeSystemd) {
	t.Helper()
	h := newHarness(t)
	h.layout.ControlUnitPath = filepath.Join(filepath.Dir(h.layout.ConfigRoot), "systemd", deploy.ControlUnitName)
	h.options.Layout = h.layout
	h.options.Manager.AllowedTargets = h.layout.ManagedFiles()
	sd := &fakeSystemd{}
	h.options.Systemd = sd
	h.options.ProbeControl = func(context.Context) error { return nil }
	h.enableBot(t)
	h.options.Desired.Bootstrap.ManageControl = true
	h.observed = readyObservation(t, h.options.Desired)
	h.observeBotCredential()
	h.replan(t)
	return h, sd
}

func TestTheControlDaemonIsInstalledProvedAndGivenToTheBot(t *testing.T) {
	h, sd := controlHarness(t)
	if !strings.Contains(planIDs(h.options.Approved), "control-daemon") {
		t.Fatalf("plan does not install the daemon: %s", planIDs(h.options.Approved))
	}
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sd.calls, ","); got != "reload,start:"+deploy.ControlUnitName {
		t.Fatalf("systemd calls = %s", got)
	}
	unit := string(mustRead(t, h.layout.ControlUnitPath))
	if !strings.Contains(unit, "control serve -socket /run/spaiter-vpn/control.sock") {
		t.Fatalf("unit = %s", unit)
	}
	if info, err := os.Stat(h.layout.ControlAccessPath()); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("access file = %v, %v", info, err)
	}
	compose := string(mustRead(t, h.layout.ComposePath()))
	botConfig := string(mustRead(t, h.layout.BotConfigPath()))
	if !strings.Contains(compose, "/run/spaiter-vpn:/run/spaiter-vpn") || !strings.Contains(botConfig, "/run/spaiter-vpn/control.sock") {
		t.Fatal("the bot was not given the control socket")
	}

	// An operator's edit of the allow-list survives the next apply.
	if err := os.WriteFile(h.layout.ControlAccessPath(), []byte(`{"apiVersion":"spaiter-vpn/control/v1alpha1","observers":[],"operators":[1000],"socketGroup":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := h.options.Desired
	h.installed(t, previous)
	h.observeBotCredential()
	h.observed.ControlUnit = &discover.File{Status: discover.FileRegular}
	h.replan(t)
	sd.calls = nil
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatalf("convergence with the daemon installed: %v", err)
	}
	if got := strings.Join(sd.calls, ","); got != "reload,start:"+deploy.ControlUnitName {
		t.Fatalf("convergence systemd calls = %s", got)
	}
	if !strings.Contains(string(mustRead(t, h.layout.ControlAccessPath())), "1000") {
		t.Fatal("the operator's allow-list was replaced")
	}

	// Turning it off stops it while its unit still exists, then removes it.
	desired := previous
	desired.Bootstrap.ManageControl = false
	h.options.Desired = desired
	h.installed(t, previous)
	h.observeBotCredential()
	h.replan(t)
	sd.calls = nil
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatalf("retiring the daemon: %v", err)
	}
	if got := strings.Join(sd.calls, ","); got != "stop:"+deploy.ControlUnitName+",reload" {
		t.Fatalf("retire systemd calls = %s", got)
	}
	if _, err := os.Stat(h.layout.ControlUnitPath); !os.IsNotExist(err) {
		t.Fatalf("the retired unit file is still there: %v", err)
	}
	if strings.Contains(string(mustRead(t, h.layout.ComposePath())), "/run/spaiter-vpn") {
		t.Fatal("the bot still mounts the retired daemon's socket")
	}
}

func TestADaemonThatDoesNotAnswerRollsTheInstallBack(t *testing.T) {
	h, sd := controlHarness(t)
	h.options.ProbeControl = func(context.Context) error { return errors.New("no answer") }
	if _, err := Run(context.Background(), h.options); err == nil || !strings.Contains(err.Error(), "no answer") {
		t.Fatalf("err = %v", err)
	}
	if got := strings.Join(sd.calls, ","); !strings.HasSuffix(got, "stop:"+deploy.ControlUnitName+",reload") {
		t.Fatalf("systemd calls = %s", got)
	}
	if _, err := os.Stat(h.layout.ControlUnitPath); !os.IsNotExist(err) {
		t.Fatal("the failed install left its unit file")
	}
}

func planIDs(p plan.Plan) string {
	var ids []string
	for _, action := range p.Actions {
		ids = append(ids, action.ID)
	}
	return strings.Join(ids, ",")
}

func TestTheWebUIRunsAsItsOwnAccountBehindTheDaemon(t *testing.T) {
	h, sd := controlHarness(t)
	webUID := uint32(os.Getuid())
	h.options.ProbeWeb = func(context.Context) error { return nil }
	h.options.Desired.Bootstrap.ManageWeb = true
	h.observed = readyObservation(t, h.options.Desired)
	h.observeBotCredential()
	h.replan(t)
	if !strings.Contains(planIDs(h.options.Approved), "web-ui") {
		t.Fatalf("plan = %s", planIDs(h.options.Approved))
	}
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sd.calls, ","); got != "reload,start:"+deploy.ControlUnitName+",start:"+deploy.WebUnitName {
		t.Fatalf("systemd calls = %s", got)
	}
	unit := string(mustRead(t, h.layout.WebUnitPath()))
	if !strings.Contains(unit, "User=spaiter-vpn-web") || !strings.Contains(unit, "-listen 127.0.0.1:10880") || strings.Contains(unit, "-secure-cookie") {
		t.Fatalf("web unit = %s", unit)
	}
	if info, err := os.Stat(h.layout.WebKeyPath()); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("web key = %v, %v", info, err)
	}
	key := mustRead(t, h.layout.WebKeyPath())
	var managed struct{ Operators []uint32 }
	if err := json.Unmarshal(mustRead(t, h.layout.ControlManagedAccessPath()), &managed); err != nil || !slices.Contains(managed.Operators, webUID) {
		t.Fatalf("managed allow-list = %s, %v", mustRead(t, h.layout.ControlManagedAccessPath()), err)
	}
	compose := string(mustRead(t, h.layout.ComposePath()))
	if !strings.Contains(compose, h.layout.WebKeyPath()+":/etc/spaiter-vpn/web.key:ro") || !strings.Contains(compose, "group_add:") {
		t.Fatalf("the bot cannot mint web links:\n%s", compose)
	}

	// A convergence keeps the key: replacing it would sign everyone out.
	previous := h.options.Desired
	h.installed(t, previous)
	h.observeBotCredential()
	h.replan(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if string(mustRead(t, h.layout.WebKeyPath())) != string(key) {
		t.Fatal("a convergence replaced the web key")
	}

	desired := previous
	desired.Bootstrap.ManageWeb = false
	h.options.Desired = desired
	h.installed(t, previous)
	h.observeBotCredential()
	h.replan(t)
	sd.calls = nil
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sd.calls, ","); !strings.HasPrefix(got, "stop:"+deploy.WebUnitName) {
		t.Fatalf("retire calls = %s", got)
	}
	for _, path := range []string{h.layout.WebUnitPath(), h.layout.WebKeyPath()} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s survived turning the web UI off", path)
		}
	}
}

func ddnsHarness(t *testing.T) (*harness, *fakeSystemd) {
	t.Helper()
	h, sd := controlHarness(t)
	h.options.Desired.Bot.PublicHost = "home.example.net"
	h.options.Desired.Bot.DynamicIP = true
	h.options.Desired.DDNS = &state.DDNS{Provider: "cloudflare", Token: "ddns-token", IPv6: true}
	if err := os.WriteFile(filepath.Join(h.layout.CredentialDir(), "ddns-token"), []byte("cf-fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.options.ProbeDDNS = func(context.Context) error { return nil }
	h.observed = readyObservation(t, h.options.Desired)
	h.observeBotCredential()
	h.observed.Credentials["ddns-token"] = discover.File{Status: discover.FileRegular, Mode: 0o600, UID: 0, Size: int64(len("cf-fixture"))}
	h.replan(t)
	return h, sd
}

func TestDynamicDNSRunsAsItsOwnUnit(t *testing.T) {
	h, sd := ddnsHarness(t)
	if !strings.Contains(planIDs(h.options.Approved), "ddns") {
		t.Fatalf("plan = %s", planIDs(h.options.Approved))
	}
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sd.calls, ","); !strings.Contains(got, "start:"+deploy.DDNSUnitName) {
		t.Fatalf("systemd calls = %s", got)
	}
	unit := string(mustRead(t, h.layout.DDNSUnitPath()))
	for _, want := range []string{
		"CapabilityBoundingSet=\n",
		"InaccessiblePaths=-" + h.layout.ConfigRoot + " -" + h.layout.DataRoot,
		"LoadCredential=ddns-token:" + filepath.Join(h.layout.CredentialDir(), "ddns-token"),
		"ddns run -provider cloudflare -host home.example.net -ipv6",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit lacks %q:\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "cf-fixture") {
		t.Fatal("the token is in the unit file")
	}

	// A new token restarts the updater; an unchanged one leaves it running.
	installed := h.options.Desired
	h.installed(t, installed)
	h.observeBotCredential()
	h.observed.Credentials["ddns-token"] = discover.File{Status: discover.FileRegular, Mode: 0o600, UID: 0, Size: int64(len("cf-fixture"))}
	h.replan(t)
	sd.calls = nil
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sd.calls, ","); strings.Contains(got, "restart:"+deploy.DDNSUnitName) {
		t.Fatalf("an unchanged token restarted the updater: %s", got)
	}
	tokenPath := filepath.Join(h.layout.CredentialDir(), "ddns-token")
	if err := os.WriteFile(tokenPath+".new", []byte("cf-fixture-2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tokenPath+".new", tokenPath); err != nil {
		t.Fatal(err)
	}
	h.installed(t, installed)
	h.observeBotCredential()
	h.observed.Credentials["ddns-token"] = discover.File{Status: discover.FileRegular, Mode: 0o600, UID: 0, Size: int64(len("cf-fixture-2"))}
	h.replan(t)
	sd.calls = nil
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sd.calls, ","); !strings.Contains(got, "restart:"+deploy.DDNSUnitName) {
		t.Fatalf("a new token did not restart the updater: %s", got)
	}

	// Turning it off removes the unit and stops it first.
	previous := h.options.Desired
	desired := previous
	desired.DDNS = nil
	h.options.Desired = desired
	h.installed(t, previous)
	h.observeBotCredential()
	h.replan(t)
	sd.calls = nil
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sd.calls, ","); !strings.Contains(got, "stop:"+deploy.DDNSUnitName) {
		t.Fatalf("retire calls = %s", got)
	}
	if _, err := os.Stat(h.layout.DDNSUnitPath()); !os.IsNotExist(err) {
		t.Fatal("the unit survived turning dynamic DNS off")
	}
}

// A token the provider rejects fails the apply and leaves nothing behind.
func TestARejectedDynamicDNSTokenRollsTheInstallBack(t *testing.T) {
	h, _ := ddnsHarness(t)
	h.options.ProbeDDNS = func(context.Context) error { return errors.New("dynamic DNS: Cloudflare rejected the token") }
	if _, err := Run(context.Background(), h.options); err == nil || !strings.Contains(err.Error(), "rejected the token") {
		t.Fatalf("apply = %v", err)
	}
	if _, err := os.Stat(h.layout.DDNSUnitPath()); !os.IsNotExist(err) {
		t.Fatal("a failed install left the unit behind")
	}
}
