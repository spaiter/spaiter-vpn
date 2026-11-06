package discover

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	"github.com/spaiter/spaiter-vpn/internal/firewall"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func TestBotTransactionTargetsRebuildWDTTPathsFromStoredIntent(t *testing.T) {
	root := t.TempDir()
	layout := Layout{
		ConfigRoot:    filepath.Join(root, "etc"),
		DataRoot:      filepath.Join(root, "var"),
		LogrotatePath: filepath.Join(root, "logrotate"),
	}
	desired := state.Default([]string{"owner"})
	desired.Bot.WDTTConfigDirectory = filepath.Join(root, "external-wdtt")
	data, err := desired.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.ConfigRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.DesiredPath(), data, 0o644); err != nil {
		t.Fatal(err)
	}

	marker := filepath.Join(layout.BotDataDir(), ".reload-wdtt")
	relay := filepath.Join(desired.Bot.WDTTConfigDirectory, "passwords.json")
	malicious := filepath.Join(root, "unrelated.json")
	receipt := transaction.Receipt{
		APIVersion: transaction.ReceiptAPIVersion,
		Files: map[string]transaction.OwnedFile{
			marker:    {Ownership: transaction.RuntimeMutable},
			relay:     {Ownership: transaction.RuntimeMutable},
			malicious: {Ownership: transaction.RuntimeMutable},
		},
	}
	receiptJSON, _ := json.Marshal(receipt)
	if err := os.MkdirAll(layout.BootstrapStateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.CurrentReceiptPath(), receiptJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	targets, err := layout.BotTransactionTargets()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{marker, relay} {
		if !slices.Contains(targets, path) {
			t.Fatalf("stored WDTT target %s was not reconstructed: %v", path, targets)
		}
	}
	if slices.Contains(targets, malicious) {
		t.Fatalf("an arbitrary receipt path entered the allowlist: %v", targets)
	}
}

type fakeRunner struct {
	calls []string
}

func (r *fakeRunner) LookPath(name string) (string, error) {
	if name == "docker" {
		return "/usr/bin/docker", nil
	}
	return "", errors.New("not found")
}

func (r *fakeRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+joinArgs(args))
	if len(args) > 0 && args[0] == "version" {
		return []byte("27.5.1\n"), nil
	}
	if len(args) > 1 && args[0] == "compose" && args[1] == "version" {
		return []byte("2.32.4\n"), nil
	}
	return nil, errors.New("unexpected command")
}

func TestRunIsReadOnlyAndDeterministic(t *testing.T) {
	root := t.TempDir()
	configRoot := filepath.Join(root, "etc", "spaiter-vpn")
	dataRoot := filepath.Join(root, "var", "lib", "spaiter-vpn")
	systemdPath := filepath.Join(root, "run", "systemd", "system")
	if err := os.MkdirAll(systemdPath, 0o755); err != nil {
		t.Fatal(err)
	}
	osRelease := filepath.Join(root, "os-release")
	if err := os.WriteFile(osRelease, []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	before := snapshotTree(t, root)
	runner := &fakeRunner{}
	options := Options{
		Layout: Layout{
			ConfigRoot:    configRoot,
			DataRoot:      dataRoot,
			LogrotatePath: filepath.Join(root, "etc", "logrotate.d", "spaiter-vpn"),
		},
		OSReleasePath: osRelease,
		SystemdPath:   systemdPath,
		GOOS:          "linux",
		GOARCH:        "amd64",
		EUID:          func() int { return 1000 },
		Runner:        runner,
		DefaultRoute:  func() (string, error) { return "ens3", nil },
		FirewallProbe: func(rules []firewall.Rule) Firewall {
			statuses := map[string]string{}
			required := make([]string, 0, len(rules))
			for _, rule := range rules {
				statuses[rule.String()] = "allowed"
				required = append(required, rule.String())
			}
			return Firewall{Kind: "ufw", Active: true, Readable: true, Required: required, Rules: statuses, Detail: "fixture"}
		},
	}

	desired := state.Default([]string{"owner"})
	first, err := Run(context.Background(), desired, options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Run(context.Background(), desired, options)
	if err != nil {
		t.Fatal(err)
	}
	after := snapshotTree(t, root)

	if !reflect.DeepEqual(before, after) {
		t.Fatalf("discovery mutated the filesystem:\nbefore: %#v\nafter:  %#v", before, after)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("identical discovery inputs produced different observations:\n%#v\n%#v", first, second)
	}
	if first.Platform.ID != "ubuntu" || first.Platform.VersionID != "24.04" || !first.Platform.Systemd {
		t.Fatalf("platform discovery = %#v", first.Platform)
	}
	if !first.Docker.DaemonReachable || !first.Docker.ComposeAvailable || first.Docker.ServerVersion != "27.5.1" {
		t.Fatalf("docker discovery = %#v", first.Docker)
	}
	if first.Network.DefaultInterface != "ens3" {
		t.Fatalf("network discovery = %#v", first.Network)
	}
	wantCalls := []string{
		"/usr/bin/docker version --format {{.Server.Version}}",
		"/usr/bin/docker compose version --short",
		"/usr/bin/docker version --format {{.Server.Version}}",
		"/usr/bin/docker compose version --short",
	}
	if !reflect.DeepEqual(runner.calls, wantCalls) {
		t.Fatalf("discovery command calls:\n got %#v\nwant %#v", runner.calls, wantCalls)
	}
}

func TestSupportedPlatformMatrixIsExplicit(t *testing.T) {
	tests := []struct {
		platform Platform
		want     bool
	}{
		{Platform{OS: "linux", Arch: "amd64", ID: "ubuntu", VersionID: "24.04", Systemd: true}, true},
		{Platform{OS: "linux", Arch: "amd64", ID: "debian", VersionID: "12", Systemd: true}, true},
		{Platform{OS: "linux", Arch: "amd64", ID: "debian", VersionID: "13", Systemd: true}, true},
		{Platform{OS: "linux", Arch: "amd64", ID: "ubuntu", VersionID: "22.04", Systemd: true}, false},
		{Platform{OS: "linux", Arch: "arm64", ID: "ubuntu", VersionID: "24.04", Systemd: true}, false},
		{Platform{OS: "linux", Arch: "amd64", ID: "ubuntu", VersionID: "24.04", Systemd: false}, false},
	}
	for _, test := range tests {
		if got := test.platform.Supported(); got != test.want {
			t.Errorf("Supported(%#v) = %t, want %t", test.platform, got, test.want)
		}
	}
}

func TestObservationCanonicalisesSetLikeDesiredState(t *testing.T) {
	leftState := state.Default([]string{"owner"})
	rightState := state.Default([]string{"owner"})
	leftState.Deployment.Protocols.Disabled = []profile.Protocol{profile.ShadowTLS, profile.Shadowsocks}
	rightState.Deployment.Protocols.Disabled = []profile.Protocol{profile.Shadowsocks, profile.ShadowTLS}
	leftDigest, err := leftState.Digest()
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := rightState.Digest()
	if err != nil {
		t.Fatal(err)
	}
	left := Observed{APIVersion: ObservationVersion, Firewall: Firewall{Required: []string{"2/tcp", "1/udp"}}, ExistingDesired: ExistingDesired{Status: FileRegular, Digest: leftDigest, State: &leftState}}
	right := Observed{APIVersion: ObservationVersion, Firewall: Firewall{Required: []string{"1/udp", "2/tcp"}}, ExistingDesired: ExistingDesired{Status: FileRegular, Digest: rightDigest, State: &rightState}}
	leftCanonical, err := left.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	rightCanonical, err := right.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leftCanonical, rightCanonical) {
		t.Fatalf("semantic set ordering changed observation:\n%s\n%s", leftCanonical, rightCanonical)
	}
}

func snapshotTree(t *testing.T, root string) []string {
	t.Helper()
	var entries []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		entries = append(entries, relative+" "+info.Mode().String())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(entries)
	return entries
}

func joinArgs(args []string) string {
	result := ""
	for i, arg := range args {
		if i > 0 {
			result += " "
		}
		result += arg
	}
	return result
}

// TestOwnershipOnlyReceiptIsNotADeployment. Recovery writes a receipt that
// claims no files after an interrupted first install, to record which firewall
// rules the killed apply had opened. Counting that as runtime state made the
// planner refuse the retry as "an untracked deployment", so a crash during the
// first install left the host needing a manual rm -rf to be installable again.
func TestOwnershipOnlyReceiptIsNotADeployment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "current.json")

	ownershipOnly := `{"apiVersion":"spaiter-vpn/receipt/v1alpha1","files":{},"firewall":["10863/udp"]}`
	if err := os.WriteFile(path, []byte(ownershipOnly), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := inspectReceipt(path).Status; got != FileAbsent {
		t.Fatalf("status = %q, want absent for a receipt that owns no files", got)
	}

	real := `{"apiVersion":"spaiter-vpn/receipt/v1alpha1","sequence":1,"transaction":"tx-1","files":{"/etc/spaiter-vpn/desired.json":{"digest":"x"}}}`
	if err := os.WriteFile(path, []byte(real), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := inspectReceipt(path).Status; got != FileRegular {
		t.Fatalf("status = %q, want regular for a receipt that owns files", got)
	}

	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := inspectReceipt(path).Status; got != FileInvalid {
		t.Fatalf("status = %q, want invalid for an unreadable receipt", got)
	}

	if err := os.WriteFile(path, []byte(`{"apiVersion":"spaiter-vpn/receipt/v1alpha1","files":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := inspectReceipt(path).Status; got != FileInvalid {
		t.Fatalf("status = %q, want invalid for an empty receipt with no ownership", got)
	}
}

func TestReceiptExposesPendingContainerRecreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "current.json")
	data := `{"apiVersion":"spaiter-vpn/receipt/v1alpha1","sequence":1,"transaction":"tx-1","files":{"/etc/example":{"digest":"x"}},"recreatePending":true}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	file, pending := inspectReceiptState(path)
	if file.Status != FileRegular || !pending {
		t.Fatalf("status=%q pending=%t, want regular/true", file.Status, pending)
	}
}
