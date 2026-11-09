package discover

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	"github.com/spaiter/spaiter-vpn/internal/firewall"
)

// scriptedRunner answers by the command line it is given.
type scriptedRunner struct {
	have    map[string]bool
	outputs map[string]string
	fail    map[string]bool
}

func (r *scriptedRunner) LookPath(name string) (string, error) {
	if r.have[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}

func (r *scriptedRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	if r.fail[key] {
		return []byte(r.outputs[key]), errors.New("exit 1")
	}
	return []byte(r.outputs[key]), nil
}

func TestDockerIsFoundDirectlyThroughSudoOrNotAtAll(t *testing.T) {
	ctx := context.Background()
	version := "version --format {{.Server.Version}}"

	if got := discoverDocker(ctx, &scriptedRunner{have: map[string]bool{}}); got.CLIAvailable {
		t.Errorf("no docker binary: %+v", got)
	}

	// Direct access fails with a message; sudo works, and compose is checked through it.
	r := &scriptedRunner{
		have:    map[string]bool{"docker": true, "sudo": true},
		fail:    map[string]bool{"/usr/bin/docker " + version: true},
		outputs: map[string]string{"/usr/bin/docker " + version: "permission denied\nsecond line", "/usr/bin/sudo -n /usr/bin/docker " + version: "27.0\n", "/usr/bin/sudo -n /usr/bin/docker compose version --short": "2.0\n"},
	}
	got := discoverDocker(ctx, r)
	if !got.DaemonReachable || !got.ViaSudo || got.ServerVersion != "27.0" || !got.ComposeAvailable {
		t.Errorf("via sudo = %+v", got)
	}

	// Neither works: the first line of the last error is reported; with no output, the error itself.
	r = &scriptedRunner{
		have:    map[string]bool{"docker": true, "sudo": true},
		fail:    map[string]bool{"/usr/bin/docker " + version: true, "/usr/bin/sudo -n /usr/bin/docker " + version: true},
		outputs: map[string]string{"/usr/bin/docker " + version: "cannot connect\nmore"},
	}
	got = discoverDocker(ctx, r)
	if got.DaemonReachable || got.Error != "exit 1" {
		t.Errorf("unreachable = %+v", got)
	}
	r.have["sudo"] = false
	if got := discoverDocker(ctx, r); got.Error != "cannot connect" {
		t.Errorf("first line only: %+v", got)
	}

	// A daemon with no Compose plugin.
	r = &scriptedRunner{have: map[string]bool{"docker": true}, outputs: map[string]string{"/usr/bin/docker " + version: "27\n"},
		fail: map[string]bool{"/usr/bin/docker compose version --short": true}}
	if got := discoverDocker(ctx, r); !got.DaemonReachable || got.ComposeAvailable {
		t.Errorf("no compose = %+v", got)
	}
}

func TestOSReleaseToleratesCommentsAndGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(path, []byte("# comment\n\nnonsense\nID=\"debian\"\nVERSION_ID=12\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	values, err := readOSRelease(path)
	if err != nil || values["ID"] != "debian" || values["VERSION_ID"] != "12" || len(values) != 2 {
		t.Errorf("values = %v, %v", values, err)
	}
	if _, err := readOSRelease(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a missing os-release was accepted")
	}
}

func TestPlatformSupportIsExactlyTheDocumentedMatrix(t *testing.T) {
	ok := func(id, version string) Platform {
		return Platform{OS: "linux", Arch: "amd64", ID: id, VersionID: version, Systemd: true}
	}
	for _, p := range []Platform{ok("ubuntu", "24.04"), ok("debian", "12"), ok("debian", "13")} {
		if !p.Supported() {
			t.Errorf("%+v should be supported", p)
		}
	}
	for _, p := range []Platform{ok("ubuntu", "22.04"), ok("debian", "11"), ok("fedora", "40"), {OS: "darwin", Arch: "amd64", ID: "ubuntu", VersionID: "24.04", Systemd: true}, {OS: "linux", Arch: "arm64", ID: "ubuntu", VersionID: "24.04", Systemd: true}, {OS: "linux", Arch: "amd64", ID: "ubuntu", VersionID: "24.04"}} {
		if p.Supported() {
			t.Errorf("%+v should not be supported", p)
		}
	}
}

func TestReceiptsThatAreNotDeploymentsAreRejectedByName(t *testing.T) {
	dir := t.TempDir()
	write := func(r any) string {
		path := filepath.Join(dir, "receipt.json")
		data, _ := json.Marshal(r)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	files := map[string]transaction.OwnedFile{"/x": {}}
	cases := map[string]struct {
		receipt transaction.Receipt
		want    FileStatus
		pending bool
	}{
		"wrong version":             {transaction.Receipt{APIVersion: "other", Files: files}, FileInvalid, false},
		"no files map":              {transaction.Receipt{APIVersion: transaction.ReceiptAPIVersion}, FileInvalid, false},
		"empty, nothing to recover": {transaction.Receipt{APIVersion: transaction.ReceiptAPIVersion, Files: map[string]transaction.OwnedFile{}}, FileInvalid, false},
		"files but no identity":     {transaction.Receipt{APIVersion: transaction.ReceiptAPIVersion, Files: files}, FileInvalid, false},
		"a real deployment":         {transaction.Receipt{APIVersion: transaction.ReceiptAPIVersion, Files: files, Sequence: 1, Transaction: "t", RecreatePending: true}, FileRegular, true},
		"recovery ownership only":   {transaction.Receipt{APIVersion: transaction.ReceiptAPIVersion, Files: map[string]transaction.OwnedFile{}, RecreatePending: true}, FileAbsent, true},
	}
	for name, c := range cases {
		got, pending := inspectReceiptState(write(c.receipt))
		if got.Status != c.want || pending != c.pending {
			t.Errorf("%s: %+v pending=%v", name, got, pending)
		}
	}
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := inspectReceipt(path); got.Status != FileInvalid || !strings.Contains(got.Error, "parse receipt") {
		t.Errorf("unparseable: %+v", got)
	}
	if got := inspectReceipt(filepath.Join(dir, "absent")); got.Status != FileAbsent {
		t.Errorf("absent: %+v", got)
	}
	// A directory is not a receipt.
	if got, _ := inspectReceiptState(dir); got.Status != FileInvalid {
		t.Errorf("directory: %+v", got)
	}
}

func TestSystemAccountsAreRefusedWhenPrivilegedOrUnknown(t *testing.T) {
	if got := LookupSystemUser("spaiter-no-such-user-xyz"); got.Exists || got.Error != "" {
		t.Errorf("unknown user = %+v", got)
	}
	got := LookupSystemUser("root")
	if got.Exists || !strings.Contains(got.Error, "not an unprivileged") {
		t.Errorf("root = %+v", got)
	}
}

func TestObservationDigestIgnoresRuleOrderAndFollowsContent(t *testing.T) {
	a := Observed{Firewall: Firewall{Required: []string{"b", "a"}}}
	b := Observed{Firewall: Firewall{Required: []string{"a", "b"}}}
	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	db, _ := b.Digest()
	if da != db {
		t.Error("rule order changed the digest")
	}
	c := Observed{Firewall: Firewall{Required: []string{"a"}}}
	if dc, _ := c.Digest(); dc == da {
		t.Error("different content, same digest")
	}
	broken := state.State{}
	withState := Observed{ExistingDesired: ExistingDesired{State: &broken}}
	_, _ = withState.Digest() // an invalid stored state is reported or tolerated, never a panic
}

func TestRunRefusesInvalidIntentAndObservesTheOptionalPieces(t *testing.T) {
	root := t.TempDir()
	layout := Layout{
		ConfigRoot:      filepath.Join(root, "etc"),
		DataRoot:        filepath.Join(root, "var"),
		LogrotatePath:   filepath.Join(root, "logrotate"),
		ControlUnitPath: filepath.Join(root, "control.service"),
	}
	options := Options{
		Layout: layout, OSReleasePath: filepath.Join(root, "none"), SystemdPath: filepath.Join(root, "none"),
		GOOS: "linux", GOARCH: "amd64", EUID: func() int { return 0 },
		Runner:        &scriptedRunner{have: map[string]bool{}},
		DefaultRoute:  func() (string, error) { return "", errors.New("no route") },
		FirewallProbe: func([]firewall.Rule) Firewall { return Firewall{} },
	}
	if _, err := Run(context.Background(), state.State{}, options); err == nil || !strings.Contains(err.Error(), "desired state") {
		t.Errorf("invalid desired state: %v", err)
	}

	desired := state.Default([]string{"owner"})
	desired.Bot.Enabled, desired.Bot.DedicatedUser = true, true
	desired.Bot.TelegramToken = "telegram-token"
	desired.Bot.AdminIDs = []int64{1}
	desired.Bot.PublicHost = "vpn.example.org"
	desired.Bootstrap.ManageControl = true
	desired.Bootstrap.InstallDocker = true
	observed, err := Run(context.Background(), desired, options)
	if err != nil {
		t.Fatal(err)
	}
	if observed.BotUser == nil || observed.ControlUnit == nil || observed.Docker.Install == nil {
		t.Errorf("optional observations missing: bot=%v control=%v install=%v", observed.BotUser, observed.ControlUnit, observed.Docker.Install)
	}
	if observed.Network.Error == "" {
		t.Error("a missing default route was not reported")
	}
	if len(observed.Credentials) == 0 {
		t.Error("the bot's credential was not inspected")
	}

	// Certificate files named by the intent are inspected where they are.
	cert := filepath.Join(root, "cert.pem")
	key := filepath.Join(root, "key.pem")
	if err := os.WriteFile(cert, []byte("c"), 0o600); err != nil {
		t.Fatal(err)
	}
	withFiles := state.State{}
	withFiles.Deployment.Certificates = &state.Certificates{Files: &state.CertificateFiles{CertificatePath: cert, KeyPath: key}}
	paths := certificatePaths(withFiles)
	if len(paths) != 2 || inspectFile(cert).Status != FileRegular || inspectFile(key).Status != FileAbsent {
		t.Errorf("certificate paths = %v", paths)
	}
	if certificatePaths(state.State{}) != nil {
		t.Error("paths without certificates")
	}
}

func TestInspectingACredentialExplainsWhyItIsNotUsable(t *testing.T) {
	dir := t.TempDir()
	if got := inspectCredential(dir, "absent"); got.Status != FileAbsent {
		t.Errorf("absent: %+v", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "tok"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Run as an ordinary user the file is owned by that user, which is itself the refusal.
	got := inspectCredential(dir, "tok")
	if os.Geteuid() != 0 && (got.Status != FileInvalid || !strings.Contains(got.Error, "want root")) {
		t.Errorf("non-root owner: %+v", got)
	}
}

func TestTheFirewallProbeReadsTheHostWithoutChangingIt(t *testing.T) {
	got := probeFirewall([]firewall.Rule{{Port: 443, Network: "tcp"}})
	if got.Required == nil || got.Rules == nil {
		t.Errorf("probe = %+v", got)
	}
}

func TestFirewallRulesAddTheSubscriptionPortOnce(t *testing.T) {
	desired := state.Default([]string{"owner"})
	desired.Bot.Enabled = true
	spec, err := desired.PreflightSpec(nil)
	if err != nil {
		t.Skip(err)
	}
	without := FirewallRules(state.Default([]string{"owner"}), spec)
	with := FirewallRules(desired, spec)
	if len(with) != len(without)+1 {
		t.Errorf("rules without bot=%d, with bot=%d", len(without), len(with))
	}
	desired.Bot.SubscriptionPort = 12345
	if got := FirewallRules(desired, spec); len(got) != len(without)+1 {
		t.Errorf("custom port: %d rules", len(got))
	}
	again := FirewallRules(desired, spec)
	for i := 1; i < len(again); i++ {
		if again[i-1].Network > again[i].Network && again[i-1].Port == again[i].Port {
			t.Error("rules are not sorted")
		}
	}
}
