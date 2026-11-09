package discover

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/firewall"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func testLayout(root string) Layout {
	return Layout{
		ConfigRoot: root + "/etc", DataRoot: root + "/var", LogrotatePath: root + "/logrotate",
		ControlUnitPath: root + "/systemd/spaiter-vpn-control.service",
	}
}

func TestLayoutPathsAreUnderTheirRootsAndManagedFilesCoverThem(t *testing.T) {
	l := testLayout("/r")
	under := func(path, root string) {
		t.Helper()
		if !strings.HasPrefix(path, root+"/") {
			t.Errorf("%s is not under %s", path, root)
		}
	}
	for _, p := range []string{l.ControlAccessPath(), l.ControlManagedAccessPath(), l.WebKeyPath(), l.DesiredPath(),
		l.CredentialDir(), l.DeploymentDir(), l.ConfigPath(), l.SecretsPath(), l.ComposePath(), l.EnvPath(),
		l.BotConfigPath(), l.BotManagementPath(), l.ReloadAgentPath()} {
		under(p, "/r/etc")
	}
	for _, p := range []string{l.CurrentReceiptPath(), l.CacheDir(), l.BotDataDir(), l.BootstrapStateDir(), l.PlatformRecordPath()} {
		under(p, "/r/var")
	}
	// The core's working directory, with its ACME state, must outlive a
	// rollback, so it is not among the managed (rolled back) files.
	managed := l.ManagedFiles()
	for _, p := range managed {
		if strings.HasPrefix(p, l.CacheDir()) || p == l.PlatformRecordPath() {
			t.Errorf("%s is rolled back with the deployment but must not be", p)
		}
	}
	for _, want := range []string{l.DesiredPath(), l.ConfigPath(), l.SecretsPath(), l.LogrotatePath, l.ControlUnitPath, l.WebUnitPath(), l.DDNSUnitPath(), l.WebKeyPath()} {
		if !slices.Contains(managed, want) {
			t.Errorf("ManagedFiles lacks %s", want)
		}
	}
	if l.WebUnitPath() != "/r/systemd/spaiter-vpn-web.service" || l.DDNSUnitPath() != "/r/systemd/spaiter-vpn-ddns.service" {
		t.Errorf("sibling units: %s %s", l.WebUnitPath(), l.DDNSUnitPath())
	}
	// Without a control unit path, none of the control-plane files are managed.
	l.ControlUnitPath = ""
	if l.WebUnitPath() != "" || l.DDNSUnitPath() != "" {
		t.Error("unit paths invented from nothing")
	}
	if got := l.ManagedFiles(); slices.Contains(got, "") || len(got) != 9 {
		t.Errorf("ManagedFiles = %v", got)
	}
}

func TestTransactionTargetsAreSortedUniqueAndSuperSetOfManaged(t *testing.T) {
	root := t.TempDir()
	l := testLayout(root)
	awg := filepath.Join(l.BotDataDir(), "awg", "42.json")
	vk := filepath.Join(l.BotDataDir(), "wdtt", "vk_hashes.json")
	subs := filepath.Join(l.BotDataDir(), "wdtt", "subs.json")
	for _, p := range []string{awg, vk, subs} {
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("{}"), 0o600)
	}
	targets, err := l.TransactionTargets()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.IsSorted(targets) || len(slices.Compact(slices.Clone(targets))) != len(targets) {
		t.Errorf("not sorted/unique: %v", targets)
	}
	for _, want := range append(l.ManagedFiles(), awg, subs) {
		if !slices.Contains(targets, want) {
			t.Errorf("missing %s", want)
		}
	}
	// The call pool is never part of a transaction: rolling it back would
	// resurrect dead links.
	if slices.Contains(targets, vk) {
		t.Error("vk_hashes.json entered the transaction")
	}
	// A receipt that cannot be read for a reason other than absence is an error.
	os.MkdirAll(l.CurrentReceiptPath(), 0o755)
	if _, err := l.TransactionTargets(); err == nil {
		t.Error("an unreadable receipt was ignored")
	}
}

func TestBotDelegationsFollowTheAccountNotTheIntent(t *testing.T) {
	l := testLayout("/r")
	if l.BotDelegations(SystemUser{}, "/relay") != nil {
		t.Error("delegations for an account that does not exist")
	}
	acct := SystemUser{Exists: true, UID: 990, GID: 991}
	got := l.BotDelegations(acct, "")
	if len(got) != 1 || got[0].Root != l.BotDataDir() || got[0].UID != 990 {
		t.Errorf("%+v", got)
	}
	got = l.BotDelegations(acct, "/relay")
	// The relay directory is root's, shared with the bot's group: a delegation
	// that gave it to the bot's uid would let the bot replace root's files.
	if len(got) != 2 || got[1].Root != "/relay" || got[1].UID != 0 || got[1].GID != 991 {
		t.Errorf("%+v", got)
	}
}

func TestInspectFileClassifiesWhatIsThere(t *testing.T) {
	dir := t.TempDir()
	if f := inspectFile(filepath.Join(dir, "absent")); f.Status != FileAbsent {
		t.Errorf("absent: %+v", f)
	}
	reg := filepath.Join(dir, "reg")
	os.WriteFile(reg, []byte("abc"), 0o640)
	os.Chmod(reg, 0o640)
	if f := inspectFile(reg); f.Status != FileRegular || f.Mode != 0o640 || f.Size != 3 || f.UID != uint32(os.Getuid()) {
		t.Errorf("regular: %+v", f)
	}
	if f := inspectFile(dir); f.Status != FileInvalid || f.Error == "" {
		t.Errorf("directory: %+v", f)
	}
	link := filepath.Join(dir, "link")
	os.Symlink(reg, link)
	// Lstat: a symlink is reported as what it is, never followed to a target.
	if f := inspectFile(link); f.Status != FileInvalid {
		t.Errorf("symlink: %+v", f)
	}
	// A path below a regular file cannot be inspected: reported, not absent.
	if f := inspectFile(filepath.Join(reg, "child")); f.Status != FileInvalid {
		t.Errorf("below a file: %+v", f)
	}
}

func TestCredentialsMustBeRootOwnedPrivateAndNonEmpty(t *testing.T) {
	dir := t.TempDir()
	if f := inspectCredential(dir, "missing"); f.Status != FileAbsent {
		t.Errorf("missing: %+v", f)
	}
	os.Mkdir(filepath.Join(dir, "adir"), 0o700)
	if f := inspectCredential(dir, "adir"); f.Status != FileInvalid {
		t.Errorf("a directory: %+v", f)
	}
	path := filepath.Join(dir, "token")
	os.WriteFile(path, []byte("secret"), 0o600)
	f := inspectCredential(dir, "token")
	if os.Getuid() == 0 {
		if f.Status != FileRegular {
			t.Errorf("root-owned 0600: %+v", f)
		}
		os.Chmod(path, 0o640)
		if f = inspectCredential(dir, "token"); f.Status != FileInvalid || !strings.Contains(f.Error, "exposes") {
			t.Errorf("0640: %+v", f)
		}
		os.WriteFile(path, nil, 0o600)
		os.Chmod(path, 0o600)
		if f = inspectCredential(dir, "token"); f.Status != FileInvalid || !strings.Contains(f.Error, "empty") {
			t.Errorf("empty: %+v", f)
		}
		return
	}
	// Unprivileged, the file is ours, not root's: a credential another user
	// could have written is not trusted.
	if f.Status != FileInvalid || !strings.Contains(f.Error, "want root") {
		t.Errorf("owned by %d: %+v", os.Getuid(), f)
	}
}

func TestInspectDesiredReadsTheStoredIntent(t *testing.T) {
	dir := t.TempDir()
	if e := inspectDesired(filepath.Join(dir, "none.json")); e.Status != FileAbsent || e.State != nil {
		t.Errorf("absent: %+v", e)
	}
	if e := inspectDesired(dir); e.Status != FileInvalid {
		t.Errorf("directory: %+v", e)
	}
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{not json"), 0o600)
	if e := inspectDesired(bad); e.Status != FileInvalid || e.Error == "" {
		t.Errorf("bad: %+v", e)
	}
	good := filepath.Join(dir, "good.json")
	desired := state.Default([]string{"owner"})
	data, _ := desired.MarshalIndent()
	os.WriteFile(good, data, 0o600)
	e := inspectDesired(good)
	want, _ := desired.Digest()
	if e.Status != FileRegular || e.State == nil || e.Digest != want {
		t.Errorf("good: %+v (digest want %s)", e, want)
	}
}

func TestCredentialRefsAreSortedAndOnlyWhatIsEnabled(t *testing.T) {
	desired := state.Default([]string{"owner"})
	if refs := CredentialRefs(desired); len(refs) != 0 {
		t.Errorf("a default deployment needs no credentials: %v", refs)
	}
	desired.Bot.Enabled = true
	desired.Bot.TelegramToken = "bot-token"
	desired.DDNS = &state.DDNS{Token: "ddns-token"}
	desired.Deployment.Certificates = &state.Certificates{ACMEDNS: &state.ACMEDNS{
		Cloudflare: &state.CloudflareDNS{APIToken: "cf-token"},
		Account:    &state.ACMEDNSAccount{Password: "acct-password"},
	}}
	got := CredentialRefs(desired)
	want := []state.SecretRef{"acct-password", "bot-token", "cf-token", "ddns-token"}
	if !slices.Equal(got, want) {
		t.Errorf("refs = %v, want %v", got, want)
	}
	// A bot that is configured but disabled needs no token on disk.
	desired.Bot.Enabled = false
	if refs := CredentialRefs(desired); slices.Contains(refs, "bot-token") {
		t.Errorf("a disabled bot's token is required: %v", refs)
	}

	files := state.Default([]string{"owner"})
	if certificatePaths(files) != nil {
		t.Error("no certificates, no paths")
	}
	files.Deployment.Certificates = &state.Certificates{Files: &state.CertificateFiles{CertificatePath: "/z/cert.pem", KeyPath: "/a/key.pem"}}
	if got := certificatePaths(files); !slices.Equal(got, []string{"/a/key.pem", "/z/cert.pem"}) {
		t.Errorf("paths = %v", got)
	}
}

func TestFirewallRulesAddTheSubscriptionPortOnlyWithTheBot(t *testing.T) {
	desired := state.Default([]string{"owner"})
	spec, err := desired.PreflightSpec(nil)
	if err != nil {
		t.Fatal(err)
	}
	base := FirewallRules(desired, spec)
	hasPort := func(rules []firewall.Rule, port uint16) bool {
		for _, r := range rules {
			if r.Port == port && r.Network == "tcp" {
				return true
			}
		}
		return false
	}
	if hasPort(base, deploy.DefaultBotSubPort) {
		t.Skip("the default subscription port is also a protocol port here")
	}
	desired.Bot.Enabled = true
	withBot := FirewallRules(desired, spec)
	if len(withBot) != len(base)+1 || !hasPort(withBot, deploy.DefaultBotSubPort) {
		t.Fatalf("the subscription port is missing: %v", withBot)
	}
	for i := 1; i < len(withBot); i++ {
		if withBot[i-1].Port > withBot[i].Port {
			t.Errorf("not sorted by port: %v", withBot)
		}
	}
	// A custom port wins over the default.
	desired.Bot.SubscriptionPort = 23456
	if custom := FirewallRules(desired, spec); !hasPort(custom, 23456) || hasPort(custom, deploy.DefaultBotSubPort) {
		t.Errorf("custom port: %v", custom)
	}
	// Opened already by a protocol: not listed twice.
	desired.Bot.SubscriptionPort = base[0].Port
	if base[0].Network == "tcp" {
		if dup := FirewallRules(desired, spec); len(dup) != len(base) {
			t.Errorf("a port already open was listed twice: %v", dup)
		}
	}
}

func TestNetworkAndFirewallProbes(t *testing.T) {
	if n := discoverNetwork(func() (string, error) { return "eth0", nil }); n.DefaultInterface != "eth0" || n.Error != "" {
		t.Errorf("%+v", n)
	}
	if n := discoverNetwork(func() (string, error) { return "", errors.New("no route") }); n.DefaultInterface != "" || n.Error != "no route" {
		t.Errorf("%+v", n)
	}

	// No firewall tool at all: nothing enforces, so everything is allowed, and
	// the requirement list is sorted for a stable observation digest.
	t.Setenv("PATH", t.TempDir())
	rules := []firewall.Rule{{Port: 20, Network: "udp"}, {Port: 10, Network: "tcp"}}
	f := probeFirewall(rules)
	if f.Kind != "none" || f.Active || !f.Readable {
		t.Errorf("%+v", f)
	}
	if !slices.Equal(f.Required, []string{"10/tcp", "20/udp"}) {
		t.Errorf("required = %v", f.Required)
	}
	if f.Rules["10/tcp"] != "allowed" || f.Rules["20/udp"] != "allowed" {
		t.Errorf("rules = %v", f.Rules)
	}
}

func TestLookupSystemUser(t *testing.T) {
	if u := LookupSystemUser("no-such-account-xyz"); u.Exists || u.Error != "" || u.Name != "no-such-account-xyz" {
		t.Errorf("an absent account is not an error: %+v", u)
	}
	// uid 0 is never an acceptable service account.
	if u := LookupSystemUser("root"); u.Exists || u.Error == "" {
		t.Errorf("root: %+v", u)
	}
}

func TestDockerInstallObservationNeverHasNilLists(t *testing.T) {
	runner := &fakeRunner{}
	opts := Options{Runner: runner, AptRoot: t.TempDir()}
	got := discoverDockerInstall(context.Background(), opts)
	// nil and empty lists marshal differently, which would change the
	// observation digest between two identical hosts.
	if got.Conflicts == nil || got.ForeignSources == nil {
		t.Errorf("%+v", got)
	}
}

func TestFillOptionsFillsOnlyWhatIsMissing(t *testing.T) {
	filled := fillOptions(Options{})
	d := DefaultOptions()
	if filled.Layout != d.Layout || filled.OSReleasePath != d.OSReleasePath || filled.SystemdPath != d.SystemdPath ||
		filled.GOOS != d.GOOS || filled.GOARCH != d.GOARCH || filled.EUID == nil || filled.Runner == nil ||
		filled.DefaultRoute == nil || filled.FirewallProbe == nil {
		t.Errorf("not filled: %+v", filled)
	}
	custom := Options{Layout: testLayout("/c"), OSReleasePath: "/x", GOOS: "plan9", EUID: func() int { return 7 }}
	got := fillOptions(custom)
	if got.Layout.ConfigRoot != "/c/etc" || got.OSReleasePath != "/x" || got.GOOS != "plan9" || got.EUID() != 7 {
		t.Errorf("an explicit option was overwritten: %+v", got)
	}
	_ = profile.AWG2
}

func TestSystemRunner(t *testing.T) {
	r := systemRunner{}
	if _, err := r.LookPath("definitely-not-a-binary-xyz"); err == nil {
		t.Error("found a binary that does not exist")
	}
	sh, err := r.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	out, err := r.Output(context.Background(), sh, "-c", "echo out; echo err >&2")
	if err != nil || !strings.Contains(string(out), "out") || !strings.Contains(string(out), "err") {
		t.Errorf("%q %v (both streams are wanted: install checks read stderr)", out, err)
	}
}
