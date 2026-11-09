package plan

import (
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func actionByID(p Plan, id string) *Action {
	for i := range p.Actions {
		if p.Actions[i].ID == id {
			return &p.Actions[i]
		}
	}
	return nil
}

func mustBuild(t *testing.T, desired state.State, observed discover.Observed) Plan {
	t.Helper()
	p, err := Build(desired, observed)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBuildRefusesWhatItCannotPlanFrom(t *testing.T) {
	desired := state.Default([]string{"owner"})
	observed := readyObservation(t, desired)
	observed.APIVersion = "something/else"
	if _, err := Build(desired, observed); err == nil || !strings.Contains(err.Error(), "apiVersion") {
		t.Errorf("a foreign observation version: %v", err)
	}
	bad := desired
	bad.Deployment.Image = ""
	if _, err := Build(bad, readyObservation(t, desired)); err == nil {
		t.Error("an invalid desired state was planned")
	}
}

func TestUnsupportedPlatformBlocksAndRootIsSaid(t *testing.T) {
	desired := state.Default([]string{"owner"})
	observed := readyObservation(t, desired)
	observed.Platform.ID = "arch"
	p := mustBuild(t, desired, observed)
	if !p.Blocked || actionByID(p, "platform") == nil || actionByID(p, "platform").Disposition != Blocked {
		t.Errorf("an unsupported platform did not block: %+v", p.Actions)
	}
	observed = readyObservation(t, desired)
	observed.Privileges.EUID = 1000
	if a := actionByID(mustBuild(t, desired, observed), "root"); a == nil || !strings.Contains(a.Summary, "1000") {
		t.Errorf("non-root: %+v", a)
	}
	observed.Privileges.EUID = 0
	if a := actionByID(mustBuild(t, desired, observed), "root"); a == nil || strings.Contains(a.Summary, "re-run") {
		t.Errorf("root: %+v", a)
	}
}

func TestExistingStateModes(t *testing.T) {
	desired := state.Default([]string{"owner"})

	// Intent absent but a deployment is on the host: refuse to adopt it.
	observed := readyObservation(t, desired)
	observed.Runtime.Config = regularFile()
	p := mustBuild(t, desired, observed)
	if p.Mode != ModeConflict || !p.Blocked || actionByID(p, "existing-runtime") == nil {
		t.Errorf("untracked deployment: %s %+v", p.Mode, p.Actions)
	}
	if actionByID(p, "preflight") != nil {
		t.Error("a conflicting plan went on to plan the apply")
	}

	// Invalid stored intent.
	observed = readyObservation(t, desired)
	observed.ExistingDesired = discover.ExistingDesired{Status: discover.FileInvalid, Error: "bad json"}
	p = mustBuild(t, desired, observed)
	if p.Mode != ModeConflict || actionByID(p, "desired-state").Reason != "bad json" {
		t.Errorf("invalid: %s %+v", p.Mode, p.Actions)
	}

	// A regular file whose parsed state is missing.
	observed = readyObservation(t, desired)
	observed.ExistingDesired = discover.ExistingDesired{Status: discover.FileRegular}
	if p = mustBuild(t, desired, observed); p.Mode != ModeConflict || !strings.Contains(actionByID(p, "desired-state").Summary, "not decoded") {
		t.Errorf("undecoded: %s %+v", p.Mode, p.Actions)
	}

	// A digest that does not match the state it claims to describe.
	observed = readyObservation(t, desired)
	setExisting(t, &observed, desired)
	observed.ExistingDesired.Digest = "0000"
	if p = mustBuild(t, desired, observed); p.Mode != ModeConflict || !strings.Contains(actionByID(p, "desired-state").Summary, "inconsistent") {
		t.Errorf("digest: %s %+v", p.Mode, p.Actions)
	}

	// Something the planner does not know.
	observed = readyObservation(t, desired)
	observed.ExistingDesired = discover.ExistingDesired{Status: "weird"}
	if p = mustBuild(t, desired, observed); p.Mode != ModeConflict || !strings.Contains(actionByID(p, "desired-state").Summary, "unknown") {
		t.Errorf("unknown status: %s %+v", p.Mode, p.Actions)
	}

	// Same intent, deployment present: reconcile, and keep desired.json as is.
	observed = readyObservation(t, desired)
	setExisting(t, &observed, desired)
	setRuntimeComplete(&observed)
	p = mustBuild(t, desired, observed)
	if p.Mode != ModeReconcile || p.Blocked {
		t.Fatalf("reconcile: %s %+v", p.Mode, p.Actions)
	}
	if a := actionByID(p, "desired-state"); a == nil || a.Disposition != Verify || a.Mutates {
		t.Errorf("an unchanged intent must not be rewritten: %+v", a)
	}
	if actionByID(p, "management-sync") == nil || actionByID(p, "compose-up") == nil || actionByID(p, "preserve-runtime") == nil {
		t.Errorf("reconcile lacks its steps: %+v", p.Actions)
	}

	// A half-present runtime is a conflict, with the pieces named.
	observed.Runtime.Secrets = absentFile()
	p = mustBuild(t, desired, observed)
	if p.Mode != ModeConflict || !strings.Contains(actionByID(p, "runtime-state").Reason, "secrets=absent") {
		t.Errorf("incomplete runtime: %s %+v", p.Mode, p.Actions)
	}
}

func TestRecreatePendingTurnsEachModeIntoItsRestartForm(t *testing.T) {
	previous := state.Default([]string{"owner"})
	same := previous
	observed := readyObservation(t, same)
	setExisting(t, &observed, previous)
	setRuntimeComplete(&observed)
	observed.Runtime.RecreatePending = true
	p := mustBuild(t, same, observed)
	if p.Mode != ModeRestartRecover || actionByID(p, "compose-recreate") == nil || actionByID(p, "compose-up") != nil {
		t.Errorf("reconcile+pending: %s %+v", p.Mode, p.Actions)
	}

	// A live-compatible change with a restart owed must restart: applying it
	// through the API would leave the crash boundary unresolved.
	changed := previous
	changed.Deployment.Ports = map[profile.Protocol]uint16{}
	for k, v := range previous.Deployment.Ports {
		changed.Deployment.Ports[k] = v
	}
	changed.Deployment.Ports[profile.AWG2]++
	observed = readyObservation(t, changed)
	setExisting(t, &observed, previous)
	setRuntimeComplete(&observed)
	observed.Runtime.RecreatePending = true
	if p = mustBuild(t, changed, observed); p.Mode != ModeRestartMigrate {
		t.Errorf("migrate+pending: %s", p.Mode)
	}
}

func TestCredentialAndCertificateObservations(t *testing.T) {
	desired := state.Default([]string{"owner"})
	observed := readyObservation(t, desired)
	observed.Credentials["good"] = regularFile()
	observed.Credentials["missing"] = absentFile()
	observed.Credentials["unsafe"] = discover.File{Status: discover.FileInvalid, Error: "mode 0644 exposes the credential"}
	observed.CertificateFiles["/etc/ssl/b.pem"] = regularFile()
	observed.CertificateFiles["/etc/ssl/a.pem"] = discover.File{Status: discover.FileInvalid, Error: "not a regular file"}
	p := mustBuild(t, desired, observed)

	if a := actionByID(p, "credential-good"); a == nil || a.Disposition != Verify {
		t.Errorf("good: %+v", a)
	}
	if a := actionByID(p, "credential-missing"); a == nil || a.Disposition != Blocked || !strings.Contains(a.Summary, "missing") {
		t.Errorf("missing: %+v", a)
	}
	if a := actionByID(p, "credential-unsafe"); a == nil || a.Disposition != Blocked || !strings.Contains(a.Reason, "exposes") {
		t.Errorf("unsafe: %+v", a)
	}
	// Certificate actions are numbered in path order, so a plan is stable.
	if a := actionByID(p, "certificate-file-1"); a == nil || a.Disposition != Blocked || !strings.Contains(a.Summary, "/etc/ssl/a.pem") {
		t.Errorf("cert 1: %+v", a)
	}
	if a := actionByID(p, "certificate-file-2"); a == nil || a.Disposition != Verify || !strings.Contains(a.Summary, "/etc/ssl/b.pem") {
		t.Errorf("cert 2: %+v", a)
	}
	if !p.Blocked {
		t.Error("a missing credential did not block the plan")
	}
}

func TestDockerStates(t *testing.T) {
	desired := state.Default([]string{"owner"})
	desired.Bootstrap.InstallDocker = false

	for _, tc := range []struct {
		name   string
		docker discover.Docker
		id     string
		want   Disposition
	}{
		{"no cli", discover.Docker{}, "docker", Blocked},
		{"daemon down", discover.Docker{CLIAvailable: true, Error: "dial unix"}, "docker", Blocked},
		{"no compose", discover.Docker{CLIAvailable: true, DaemonReachable: true}, "docker-compose", Blocked},
		{"direct", discover.Docker{CLIAvailable: true, DaemonReachable: true, ComposeAvailable: true, ServerVersion: "27"}, "docker", Verify},
		{"sudo", discover.Docker{CLIAvailable: true, DaemonReachable: true, ComposeAvailable: true, ViaSudo: true, ServerVersion: "27"}, "docker", Verify},
	} {
		observed := readyObservation(t, desired)
		observed.Docker = tc.docker
		a := actionByID(mustBuild(t, desired, observed), tc.id)
		if a == nil || a.Disposition != tc.want {
			t.Errorf("%s: %+v", tc.name, a)
		}
		if tc.name == "sudo" && !strings.Contains(a.Summary, "sudo") {
			t.Errorf("sudo access is not said: %q", a.Summary)
		}
	}
}

func TestDockerInstallIsPlannedOnlyWhenSafe(t *testing.T) {
	desired := state.Default([]string{"owner"})
	desired.Bootstrap.InstallDocker = true
	build := func(mutate func(*discover.Observed)) Plan {
		observed := readyObservation(t, desired)
		observed.Docker = discover.Docker{Install: &discover.DockerInstall{Conflicts: []string{}, ForeignSources: []string{}}}
		mutate(&observed)
		return mustBuild(t, desired, observed)
	}

	p := build(func(*discover.Observed) {})
	a := actionByID(p, "docker-install")
	if a == nil || a.Disposition != Apply || !a.Mutates || !strings.Contains(a.Summary, "docker-ce=") || !strings.Contains(a.Summary, "docker-compose-plugin=") {
		t.Fatalf("install: %+v", a)
	}

	// Compose only: just the plugin, and only the compose conflicts matter.
	p = build(func(o *discover.Observed) {
		o.Docker = discover.Docker{CLIAvailable: true, DaemonReachable: true, Install: &discover.DockerInstall{Conflicts: []string{"podman-docker"}, ForeignSources: []string{}}}
	})
	a = actionByID(p, "docker-compose-install")
	if a == nil || a.Disposition != Apply || strings.Contains(a.Summary, "docker-ce=") || !strings.Contains(a.Summary, "docker-compose-plugin=") {
		t.Fatalf("compose only: %+v", a)
	}
	p = build(func(o *discover.Observed) {
		o.Docker = discover.Docker{CLIAvailable: true, DaemonReachable: true, Install: &discover.DockerInstall{Conflicts: []string{"docker-compose"}, ForeignSources: []string{}}}
	})
	if a = actionByID(p, "docker-compose-install"); a == nil || a.Disposition != Blocked || !strings.Contains(a.Reason, "docker-compose") {
		t.Fatalf("compose conflict: %+v", a)
	}

	for name, tc := range map[string]struct {
		mutate func(*discover.Observed)
		want   string
	}{
		"unsupported release": {func(o *discover.Observed) { o.Platform.ID, o.Platform.VersionID = "ubuntu", "20.04" }, "no pinned Docker packages"},
		"not observed":        {func(o *discover.Observed) { o.Docker.Install = nil }, "rerun discovery"},
		"unreadable":          {func(o *discover.Observed) { o.Docker.Install.Error = "permission denied" }, "permission denied"},
		"foreign repository":  {func(o *discover.Observed) { o.Docker.Install.ForeignSources = []string{"/etc/apt/x.list"} }, "/etc/apt/x.list"},
		"conflicts":           {func(o *discover.Observed) { o.Docker.Install.Conflicts = []string{"docker.io"} }, "docker.io"},
	} {
		p := build(tc.mutate)
		a := actionByID(p, "docker-install")
		if name == "unsupported release" {
			// An unsupported platform is blocked earlier as well.
			if a == nil || a.Disposition != Blocked || !strings.Contains(a.Reason, tc.want) {
				t.Errorf("%s: %+v", name, a)
			}
			continue
		}
		if a == nil || a.Disposition != Blocked || !strings.Contains(a.Reason, tc.want) || !p.Blocked {
			t.Errorf("%s: %+v", name, a)
		}
	}
}

func TestXDPAutoNeedsAResolvableInterface(t *testing.T) {
	desired := state.Default([]string{"owner"})
	desired.Deployment.XDPInterfaces = []string{"auto"}
	observed := readyObservation(t, desired)
	if a := actionByID(mustBuild(t, desired, observed), "xdp-interface"); a == nil || a.Disposition != Verify || !strings.Contains(a.Summary, "eth0") {
		t.Errorf("resolved: %+v", a)
	}
	observed.Network = discover.Network{Error: "no route"}
	if a := actionByID(mustBuild(t, desired, observed), "xdp-interface"); a == nil || a.Disposition != Blocked || a.Reason != "no route" {
		t.Errorf("unresolved: %+v", a)
	}
	desired.Deployment.XDPInterfaces = []string{"eth1"}
	if actionByID(mustBuild(t, desired, readyObservation(t, desired)), "xdp-interface") != nil {
		t.Error("an explicit interface was 'resolved'")
	}
}

func TestLogrotateAndFirewallDecisions(t *testing.T) {
	desired := state.Default([]string{"owner"})
	observed := readyObservation(t, desired)
	observed.Logrotate = discover.File{Status: discover.FileInvalid, Error: "symlink"}
	if a := actionByID(mustBuild(t, desired, observed), "logrotate"); a == nil || a.Disposition != Blocked {
		t.Errorf("unsafe logrotate target: %+v", a)
	}
	observed.Logrotate = absentFile()
	if a := actionByID(mustBuild(t, desired, observed), "logrotate"); a == nil || a.Disposition != Apply {
		t.Errorf("logrotate: %+v", a)
	}
	desired.Bootstrap.ManageLogrotate = false
	if actionByID(mustBuild(t, desired, observed), "logrotate") != nil {
		t.Error("logrotate planned although not managed")
	}

	desired = state.Default([]string{"owner"})
	for name, mutate := range map[string]func(*discover.Firewall){
		"none":     func(f *discover.Firewall) { f.Kind = "none" },
		"inactive": func(f *discover.Firewall) { f.Active = false },
	} {
		observed = readyObservation(t, desired)
		mutate(&observed.Firewall)
		if a := actionByID(mustBuild(t, desired, observed), "firewall"); a == nil || a.Disposition != Verify || a.Mutates || !strings.Contains(a.Summary, "no host-firewall change") {
			t.Errorf("%s: %+v", name, a)
		}
	}
	// A firewall this tool cannot write to needs a person, and blocks the apply.
	for name, mutate := range map[string]func(*discover.Firewall){
		"firewalld":  func(f *discover.Firewall) { f.Kind = "firewalld" },
		"unreadable": func(f *discover.Firewall) { f.Readable = false },
	} {
		observed = readyObservation(t, desired)
		mutate(&observed.Firewall)
		p := mustBuild(t, desired, observed)
		if a := actionByID(p, "firewall"); a == nil || a.Disposition != Manual || !p.Blocked {
			t.Errorf("%s: %+v blocked=%v", name, a, p.Blocked)
		}
	}
	observed = readyObservation(t, desired)
	if a := actionByID(mustBuild(t, desired, observed), "firewall"); a == nil || a.Disposition != Verify || !strings.Contains(a.Summary, "keep existing") {
		t.Errorf("all allowed: %+v", a)
	}
	desired.Bootstrap.ManageFirewall = false
	if actionByID(mustBuild(t, desired, observed), "firewall") != nil {
		t.Error("firewall planned although not managed")
	}
}

func TestOptionalServicesAreEachPlannedOnlyWhenAsked(t *testing.T) {
	desired := state.Default([]string{"owner"})
	observed := readyObservation(t, desired)
	base := mustBuild(t, desired, observed)
	for _, id := range []string{"control-daemon", "web-ui", "ddns", "bot-user", "bot-claim"} {
		if actionByID(base, id) != nil {
			t.Errorf("%s planned by default", id)
		}
	}

	desired.Bootstrap.ManageControl = true
	observed = readyObservation(t, desired)
	unit := regularFile()
	observed.ControlUnit = &unit
	if a := actionByID(mustBuild(t, desired, observed), "control-daemon"); a == nil || a.Disposition != Apply || strings.Contains(a.Summary, "mounted into the bot") {
		t.Errorf("control: %+v", a)
	}
	bad := discover.File{Status: discover.FileInvalid, Error: "is a directory"}
	observed.ControlUnit = &bad
	if a := actionByID(mustBuild(t, desired, observed), "control-daemon"); a == nil || a.Disposition != Blocked || a.Reason != "is a directory" {
		t.Errorf("unsafe unit: %+v", a)
	}

	desired.Bootstrap.ManageWeb = true
	desired.Web = &state.Web{Listen: "127.0.0.1:8088"}
	observed = readyObservation(t, desired)
	observed.ControlUnit = &unit
	p, err := Build(desired, observed)
	if err != nil {
		t.Fatal(err)
	}
	if a := actionByID(p, "web-ui"); a == nil || a.Disposition != Apply || !strings.Contains(a.Summary, "127.0.0.1:8088") {
		t.Errorf("web: %+v", a)
	}
}

func TestBotPlanning(t *testing.T) {
	desired := state.Default([]string{"owner"})
	desired.Bot.Enabled = true
	desired.Bot.PublicHost = "vpn.example.com"
	desired.Bot.TelegramToken = "tg-token"
	desired.Bot.DedicatedUser = true
	desired.Bot.AdminIDs = []int64{}

	build := func(user *discover.SystemUser) Plan {
		observed := readyObservation(t, desired)
		observed.Credentials["tg-token"] = regularFile()
		observed.BotUser = user
		return mustBuild(t, desired, observed)
	}
	// Nobody owns a bot with no admin until a code issued on the host is claimed.
	if a := actionByID(build(&discover.SystemUser{Name: "b", Exists: true, UID: 5}), "bot-claim"); a == nil || a.Disposition != Manual {
		t.Errorf("bot-claim: %+v", a)
	}
	if a := actionByID(build(nil), "bot-user"); a == nil || a.Disposition != Blocked {
		t.Errorf("unobserved account: %+v", a)
	}
	if a := actionByID(build(&discover.SystemUser{Name: "b", Error: "lookup failed"}), "bot-user"); a == nil || a.Disposition != Blocked || a.Reason != "lookup failed" {
		t.Errorf("account error: %+v", a)
	}
	if a := actionByID(build(&discover.SystemUser{Name: "spaiter-vpn-bot"}), "bot-user"); a == nil || a.Disposition != Apply || !a.Mutates || !strings.Contains(a.Summary, "create") {
		t.Errorf("missing account: %+v", a)
	}
	if a := actionByID(build(&discover.SystemUser{Name: "spaiter-vpn-bot", Exists: true, UID: 998}), "bot-user"); a == nil || a.Disposition != Verify || !strings.Contains(a.Summary, "uid 998") {
		t.Errorf("existing account: %+v", a)
	}

	desired.Bot.AdminIDs = []int64{1}
	desired.Bot.DedicatedUser = false
	p := build(nil)
	if actionByID(p, "bot-claim") != nil || actionByID(p, "bot-user") != nil {
		t.Error("claim or account planned although an admin is configured and the user is root")
	}
}

func TestDDNSPlanning(t *testing.T) {
	desired := state.Default([]string{"owner"})
	desired.Bot.Enabled = true
	desired.Bot.AdminIDs = []int64{1}
	desired.Bot.PublicHost = "vpn.example.com"
	desired.Bot.TelegramToken = "tg-token"
	desired.Bootstrap.ManageControl = true
	desired.DDNS = &state.DDNS{Provider: "cloudflare", Token: "ddns-token", IPv6: true}
	observed := readyObservation(t, desired)
	observed.Credentials["tg-token"], observed.Credentials["ddns-token"] = regularFile(), regularFile()
	unit := regularFile()
	observed.ControlUnit = &unit
	p, err := Build(desired, observed)
	if err != nil {
		t.Skipf("this desired state is not valid on its own: %v", err)
	}
	a := actionByID(p, "ddns")
	if a == nil || a.Disposition != Apply || !strings.Contains(a.Summary, "A and AAAA") || !strings.Contains(a.Summary, "cloudflare") {
		t.Fatalf("ddns: %+v", a)
	}
	if a := actionByID(p, "control-daemon"); a == nil || !strings.Contains(a.Summary, "mounted into the bot") {
		t.Errorf("control with a bot: %+v", a)
	}
	desired.DDNS.IPv6 = false
	if a := actionByID(mustBuild(t, desired, observed), "ddns"); a == nil || !strings.Contains(a.Summary, " A records") {
		t.Errorf("ipv4 only: %+v", a)
	}
}

func TestMigrationClassification(t *testing.T) {
	for _, path := range []string{"/deployment/protocols", "/deployment/ports/awg-in", "/deployment/mtu/awg-in", "/deployment/realityHandshake"} {
		if !supportedMigration(path) || restartMigration(path) {
			t.Errorf("%s should be a live migration", path)
		}
	}
	for _, path := range []string{"/deployment/tier", "/deployment/xdpInterfaces", "/deployment/logLevel", "/deployment/domain", "/deployment/certificates"} {
		if supportedMigration(path) || !restartMigration(path) {
			t.Errorf("%s should need a restart", path)
		}
	}
	for _, path := range []string{"/deployment/subnets/awg-in", "/bootstrap/seedUsers", "/other"} {
		if supportedMigration(path) || restartMigration(path) {
			t.Errorf("%s is in neither the live nor the restart set", path)
		}
	}

	changes := []state.Change{{Path: "/deployment/image"}, {Path: "/deployment/subnets/x"}}
	if !hasSubnetMigrationChange(changes) || hasMigrationPolicyChange(changes) || hasSeedUserMigrationChange(changes) {
		t.Error("subnet classification")
	}
	policy := []state.Change{{Path: "/migrationPolicy"}}
	if !hasSubnetMigrationChange(policy) || !hasMigrationPolicyChange(policy) || !hasSeedUserMigrationChange(policy) {
		t.Error("policy classification")
	}
	seeds := []state.Change{{Path: "/bootstrap/seedUsers"}}
	if hasSubnetMigrationChange(seeds) || hasMigrationPolicyChange(seeds) || !hasSeedUserMigrationChange(seeds) {
		t.Error("seed users classification")
	}
	if hasSubnetMigrationChange(nil) || hasMigrationPolicyChange(nil) || hasSeedUserMigrationChange(nil) {
		t.Error("no changes")
	}
}

func TestUnsupportedMigrationsAreNamedAndBlock(t *testing.T) {
	previous := state.Default([]string{"owner"})
	desired := previous
	desired.Bootstrap.SeedUsers = []string{"owner", "second"}
	observed := readyObservation(t, desired)
	setExisting(t, &observed, previous)
	setRuntimeComplete(&observed)
	p := mustBuild(t, desired, observed)
	if p.Mode != ModeMigrationRequired || !p.Blocked {
		t.Fatalf("seed users without a policy: %s blocked=%v", p.Mode, p.Blocked)
	}
	if a := actionByID(p, "migration"); a == nil || !strings.Contains(a.Reason, "seedUsers") {
		t.Errorf("the blocking path is not named: %+v", a)
	}
	for _, a := range p.Actions {
		if a.Mutates {
			t.Errorf("a blocked migration plan contains a mutating action: %+v", a)
		}
	}
}

func TestValidateRejectsMalformedPlans(t *testing.T) {
	if err := (Plan{Actions: []Action{{ID: ""}}}).validate(); err == nil || !strings.Contains(err.Error(), "no id") {
		t.Errorf("empty id: %v", err)
	}
	if err := (Plan{Actions: []Action{{ID: "a"}, {ID: "a"}}}).validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate: %v", err)
	}
	// A blocked action under a plan that says it is not blocked would let apply proceed.
	if err := (Plan{Actions: []Action{{ID: "a", Disposition: Blocked}}}).validate(); err == nil {
		t.Error("a blocked action in an unblocked plan was accepted")
	}
	if err := (Plan{Blocked: true, Actions: []Action{{ID: "a", Disposition: Blocked}}}).validate(); err != nil {
		t.Errorf("consistent plan: %v", err)
	}
	var p Plan
	p.manualBlock("m", "s", "r")
	if !p.Blocked || p.Actions[0].Disposition != Manual {
		t.Errorf("manualBlock: %+v", p)
	}
}

func TestCredentialRotationIsPlannedAloneAndNeverBesideAReshape(t *testing.T) {
	previous := state.Default([]string{"owner"})
	rotation := &state.MigrationPolicy{RotateCredentials: &state.CredentialRotation{
		ID: "20261108T000000Z-abc", Users: []string{"owner"}, Strategy: state.CredentialRotationStrategyReissue,
	}}

	alone := previous
	alone.MigrationPolicy = rotation
	observed := readyObservation(t, alone)
	setExisting(t, &observed, previous)
	setRuntimeComplete(&observed)
	p := mustBuild(t, alone, observed)
	a := actionByID(p, "rotate-credentials")
	if p.Blocked || a == nil || !a.Mutates || !strings.Contains(a.Summary, "owner") || !strings.Contains(a.Reason, "stop working") {
		t.Fatalf("alone: blocked=%v mode=%s action=%+v", p.Blocked, p.Mode, a)
	}

	// One reason per generation: folded into a reshape, a failed apply would
	// not say which half to retry, and rollback would undo both.
	both := alone
	both.Deployment.Ports = map[profile.Protocol]uint16{}
	for k, v := range previous.Deployment.Ports {
		both.Deployment.Ports[k] = v
	}
	both.Deployment.Ports[profile.AWG2]++
	observed = readyObservation(t, both)
	setExisting(t, &observed, previous)
	setRuntimeComplete(&observed)
	p = mustBuild(t, both, observed)
	if !p.Blocked || p.Mode != ModeMigrationRequired || actionByID(p, "rotate-credentials") != nil {
		t.Fatalf("beside a reshape: blocked=%v mode=%s", p.Blocked, p.Mode)
	}
	if a := actionByID(p, "migration"); a == nil || !strings.Contains(a.Reason, "on its own") {
		t.Errorf("the reason is not given: %+v", a)
	}
	for _, act := range p.Actions {
		if act.Mutates {
			t.Errorf("a blocked plan carries a mutating action: %+v", act)
		}
	}
}
