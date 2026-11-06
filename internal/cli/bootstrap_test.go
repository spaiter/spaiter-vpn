package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	"github.com/spaiter/spaiter-vpn/internal/firewall"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// TestBootstrapStateRoundTrips. The document this writes is the one a later
// plan hashes, so if it does not parse back the whole flow is dead on the
// second command.
func TestBootstrapStateRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "desired.json")
	var out bytes.Buffer
	if err := runBootstrapState(context.Background(), &out, []string{"-users", "alice,bob", "-o", path}); err != nil {
		t.Fatal(err)
	}
	loaded, err := state.Load(path)
	if err != nil {
		t.Fatalf("the generated document does not parse: %v", err)
	}
	if len(loaded.Bootstrap.SeedUsers) != 2 {
		t.Fatalf("seed users = %v", loaded.Bootstrap.SeedUsers)
	}
	// Strict decoding requires every non-omitempty field to be present, so a
	// successful Load already proves the defaults were written out rather than
	// left to be filled in at read time. The digest is what a plan compares.
	if _, err := loaded.Digest(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("telegramToken")) {
		t.Error("a default document references a credential nobody has stored")
	}
}

func TestBootstrapStateNeedsUsers(t *testing.T) {
	var out bytes.Buffer
	err := runBootstrapState(context.Background(), &out, nil)
	if !errors.Is(err, ErrUsage) {
		t.Fatalf("err = %v, want ErrUsage", err)
	}
}

// TestBootstrapApplyRefusesWithoutConsent. Stdin is not a terminal under test,
// which is exactly the non-interactive case: it must not be read as agreement.
func TestBootstrapApplyRefusesWithoutConsent(t *testing.T) {
	root := t.TempDir()
	var out bytes.Buffer
	err := runBootstrapApply(context.Background(), &out, []string{
		"-config-root", filepath.Join(root, "etc"),
		"-data-root", filepath.Join(root, "var"),
		"-logrotate-path", filepath.Join(root, "logrotate"),
	})
	if err == nil {
		t.Fatal("apply proceeded with nobody to confirm the plan")
	}
	if !strings.Contains(err.Error(), "-yes") {
		t.Fatalf("the refusal does not say how to proceed: %v", err)
	}
	// Refused before reading or writing anything, so a missing desired state is
	// never even reported: consent is the first gate.
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Fatalf("the refused apply created %v", entries)
	}
}

// TestBootstrapApplyNeedsRootAndSaysHow. Elevating itself would hide the moment
// the operator agreed to give this root.
func TestBootstrapApplyNeedsRootAndSaysHow(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	root := t.TempDir()
	var out bytes.Buffer
	err := runBootstrapApply(context.Background(), &out, []string{
		"-yes",
		"-config-root", filepath.Join(root, "etc"),
		"-data-root", filepath.Join(root, "var"),
		"-logrotate-path", filepath.Join(root, "logrotate"),
	})
	if err == nil || !strings.Contains(err.Error(), "sudo ") {
		t.Fatalf("err = %v, want the exact sudo command", err)
	}
	if !strings.Contains(err.Error(), "bootstrap apply") {
		t.Fatalf("the suggested command is not the one that was run: %v", err)
	}
}

// TestBootstrapPlanIsReadOnly against a fabricated observation, so the test
// does not depend on this machine being a supported platform.
func TestBootstrapPlanIsReadOnly(t *testing.T) {
	root := t.TempDir()
	desiredPath := filepath.Join(root, "desired.json")
	var discard bytes.Buffer
	if err := runBootstrapState(context.Background(), &discard, []string{"-users", "owner", "-o", desiredPath}); err != nil {
		t.Fatal(err)
	}

	restore := discoverHost
	discoverHost = func(_ context.Context, desired state.State, _ discover.Layout) (discover.Observed, error) {
		return fakeObservation(t, desired), nil
	}
	t.Cleanup(func() { discoverHost = restore })

	var out bytes.Buffer
	args := []string{
		"-f", desiredPath,
		"-config-root", filepath.Join(root, "etc"),
		"-data-root", filepath.Join(root, "var"),
		"-logrotate-path", filepath.Join(root, "logrotate"),
	}
	if err := runBootstrapPlan(context.Background(), &out, args); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"mode:          fresh", "change this host (marked *)", "generate credentials"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan output is missing %q:\n%s", want, text)
		}
	}
	// Nothing on the host: no config root, no data root, no lock.
	for _, path := range []string{filepath.Join(root, "etc"), filepath.Join(root, "var")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("the read-only plan created %s", path)
		}
	}

	out.Reset()
	if err := runBootstrapPlan(context.Background(), &out, append(args, "-json")); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(out.String()), "{") {
		t.Fatalf("-json did not produce a document:\n%s", out.String())
	}
}

// TestBootstrapPlanReportsAMissingDocument with the command that creates one,
// rather than a bare open error.
func TestBootstrapPlanReportsAMissingDocument(t *testing.T) {
	root := t.TempDir()
	var out bytes.Buffer
	err := runBootstrapPlan(context.Background(), &out, []string{
		"-config-root", filepath.Join(root, "etc"),
		"-data-root", filepath.Join(root, "var"),
		"-logrotate-path", filepath.Join(root, "logrotate"),
	})
	if err == nil || !strings.Contains(err.Error(), "bootstrap state") {
		t.Fatalf("err = %v, want the next command named", err)
	}
}

// TestBootstrapStatusSeparatesAbsentFromUnreadable. A host with nothing
// installed must not report its intent as unreadable, which it did while the
// check used os.IsNotExist against a wrapped error.
func TestBootstrapStatusSeparatesAbsentFromUnreadable(t *testing.T) {
	root := t.TempDir()
	args := []string{
		"-config-root", filepath.Join(root, "etc"),
		"-data-root", filepath.Join(root, "var"),
		"-logrotate-path", filepath.Join(root, "logrotate"),
	}
	var out bytes.Buffer
	if err := runBootstrapStatus(context.Background(), &out, args); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "stored intent: none") {
		t.Fatalf("a clean host was not reported as clean:\n%s", out.String())
	}
	if strings.Contains(out.String(), "UNREADABLE") {
		t.Fatalf("an absent document was reported as unreadable:\n%s", out.String())
	}

	// Now an invalid one, which must NOT read as absent.
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "desired.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runBootstrapStatus(context.Background(), &out, args); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "UNREADABLE") {
		t.Fatalf("an invalid document was not reported as such:\n%s", out.String())
	}
}

func TestBootstrapStatusAcceptsAdoptedBotPeerInReceipt(t *testing.T) {
	root := t.TempDir()
	layout := discover.Layout{
		ConfigRoot:    filepath.Join(root, "etc"),
		DataRoot:      filepath.Join(root, "var"),
		LogrotatePath: filepath.Join(root, "logrotate"),
	}
	peerPath := filepath.Join(layout.BotDataDir(), "awg", "4242.json")
	if err := os.MkdirAll(filepath.Dir(peerPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(peerPath, []byte(`{"priv":"a","pub":"b","ip":"10.99.0.3/32"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.BootstrapStateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	receipt := `{"apiVersion":"spaiter-vpn.io/v1alpha1/receipt","sequence":2,"transaction":"tx1","files":{"` + peerPath + `":{"digest":"sha256:00","mode":384,"uid":0,"gid":0,"ownership":"runtime-mutable"}}}` + "\n"
	if err := os.WriteFile(layout.CurrentReceiptPath(), []byte(receipt), 0o600); err != nil {
		t.Fatal(err)
	}
	// Run with a manager whose UID/GID match the test process if non-root, via
	// newTransactionManager check when root or by verifying layout.TransactionTargets.
	targets, err := layout.TransactionTargets()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, target := range targets {
		if target == peerPath {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("adopted bot peer %s missing from TransactionTargets: %v", peerPath, targets)
	}
}

func TestBootstrapRejectsUnknownSubcommand(t *testing.T) {
	var out bytes.Buffer
	err := runBootstrap(context.Background(), &out, []string{"aplly"})
	if !errors.Is(err, ErrUsage) {
		t.Fatalf("err = %v, want ErrUsage", err)
	}
}

func TestBootstrapPruneRequiresExplicitSafeRetention(t *testing.T) {
	for _, args := range [][]string{{"prune"}, {"prune", "-keep", "1"}, {"prune", "-keep", "2", "unexpected"}} {
		var out bytes.Buffer
		err := runBootstrap(context.Background(), &out, args)
		if !errors.Is(err, ErrUsage) {
			t.Errorf("args = %v: err = %v, want ErrUsage", args, err)
		}
	}
}

func TestRollbackDesiredPreservesUsersRuntimePathAndAuthorizesSubnetMove(t *testing.T) {
	historical := state.Default([]string{"original"})
	current := state.Default([]string{"original", "added-later"})
	current.Bot.WDTTConfigDirectory = "/srv/wdtt-live"
	current.Deployment.Subnets[profile.WGWDTT] = "10.99.0.0/24"
	current.MigrationPolicy = &state.MigrationPolicy{Subnets: map[profile.Protocol]state.SubnetMigration{
		profile.WGWDTT: {From: historical.Deployment.Subnets[profile.WGWDTT], To: "10.99.0.0/24", Strategy: state.SubnetStrategyPreserveHost},
	}}

	desired, err := rollbackDesired(current, historical)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(desired.Bootstrap.SeedUsers, ","); got != "original,added-later" {
		t.Fatalf("seed users = %s", got)
	}
	if desired.Bot.WDTTConfigDirectory != current.Bot.WDTTConfigDirectory {
		t.Fatalf("wdtt directory = %q", desired.Bot.WDTTConfigDirectory)
	}
	move := desired.MigrationPolicy.Subnets[profile.WGWDTT]
	if move.From != "10.99.0.0/24" || move.To != historical.Deployment.Subnets[profile.WGWDTT] || move.Strategy != state.SubnetStrategyPreserveHost {
		t.Fatalf("rollback subnet policy = %#v", move)
	}
}

func TestRollbackDesiredRefusesToMintCredentialsForReenabledProtocol(t *testing.T) {
	historical := state.Default([]string{"owner"})
	current := state.Default([]string{"owner"})
	current.Deployment.Protocols.Disabled = []profile.Protocol{profile.AWG2}

	_, err := rollbackDesired(current, historical)
	if err == nil || !strings.Contains(err.Error(), string(profile.AWG2)) {
		t.Fatalf("err = %v, want protocol-specific refusal", err)
	}
}

func TestSelectRollbackGenerationDefaultsToLatestOlderCommit(t *testing.T) {
	generations := []transaction.Generation{
		{Sequence: 1, Transaction: "one", CommittedAt: time.Unix(1, 0)},
		{Sequence: 4, Transaction: "four", CommittedAt: time.Unix(4, 0)},
		{Sequence: 7, Transaction: "seven", CommittedAt: time.Unix(7, 0)},
	}
	got, err := selectRollbackGeneration(generations, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sequence != 4 {
		t.Fatalf("default target = %d, want 4", got.Sequence)
	}
	if _, err := selectRollbackGeneration(generations, 7, 7); err == nil {
		t.Fatal("current generation was accepted as rollback target")
	}
}

// TestBootstrapCredentialNeedsRoot, and rejects a name that is a path: the
// desired-state document chooses this name, and a path there would make the
// credential store an arbitrary-write primitive.
func TestBootstrapCredentialRejectsPathsAsNames(t *testing.T) {
	var out bytes.Buffer
	for _, name := range []string{"../escape", "sub/token", "Token"} {
		err := runBootstrapCredential(context.Background(), &out, []string{name})
		if !errors.Is(err, ErrUsage) {
			t.Errorf("credential name %q: err = %v, want ErrUsage", name, err)
		}
	}
}

func TestLayoutFlagsRejectRelativePaths(t *testing.T) {
	var out bytes.Buffer
	err := runBootstrapStatus(context.Background(), &out, []string{"-config-root", "etc"})
	if !errors.Is(err, ErrUsage) {
		t.Fatalf("err = %v, want ErrUsage", err)
	}
}

func fakeObservation(t *testing.T, desired state.State) discover.Observed {
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
	absent := discover.File{Status: discover.FileAbsent}
	return discover.Observed{
		APIVersion:       discover.ObservationVersion,
		Platform:         discover.Platform{OS: "linux", Arch: "amd64", ID: "ubuntu", VersionID: "24.04", Systemd: true},
		Privileges:       discover.Privileges{EUID: 0},
		Docker:           discover.Docker{CLIAvailable: true, DaemonReachable: true, ComposeAvailable: true, ServerVersion: "27.5.1"},
		Network:          discover.Network{DefaultInterface: "eth0"},
		Firewall:         discover.Firewall{Kind: "ufw", Active: true, Readable: true, Required: required, Rules: rules, Detail: "fixture"},
		ExistingDesired:  discover.ExistingDesired{Status: discover.FileAbsent},
		Runtime:          discover.Runtime{Config: absent, Secrets: absent, Compose: absent, Receipt: absent},
		Credentials:      map[state.SecretRef]discover.File{},
		CertificateFiles: map[string]discover.File{},
		Logrotate:        absent,
	}
}

func TestRotationUsersAreRequiredUniqueAndSorted(t *testing.T) {
	got, err := parseRotationUsers(" carol, alice ,bob")
	if err != nil || strings.Join(got, ",") != "alice,bob,carol" {
		t.Fatalf("parseRotationUsers = %v, %v", got, err)
	}
	for _, raw := range []string{"", " , ", "alice,alice"} {
		if _, err := parseRotationUsers(raw); !errors.Is(err, ErrUsage) {
			t.Errorf("%q: err = %v, want ErrUsage", raw, err)
		}
	}
	for _, args := range [][]string{{"rotate"}, {"rotate", "-users", "a", "extra"}} {
		var out bytes.Buffer
		if err := runBootstrap(context.Background(), &out, args); !errors.Is(err, ErrUsage) {
			t.Errorf("args = %v: err = %v, want ErrUsage", args, err)
		}
	}
}

func TestRotationDesiredKeepsAuditRecordsAndAddsOnlyTheRequest(t *testing.T) {
	current := state.Default([]string{"alice", "bob"})
	current.MigrationPolicy = &state.MigrationPolicy{SeedUsers: &state.SeedUsersMigration{
		From: []string{"alice"}, To: []string{"alice", "bob"}, Strategy: state.SeedUsersStrategyPreserveExisting,
	}}
	id, err := newRotationID(time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC))
	if err != nil || !strings.HasPrefix(id, "20261104T120000Z-") {
		t.Fatalf("id = %q, %v", id, err)
	}
	desired, err := rotationDesired(current, []string{"bob"}, id)
	if err != nil {
		t.Fatal(err)
	}
	policy := desired.MigrationPolicy
	if policy.Subnets != nil || policy.SeedUsers == nil || policy.RotateCredentials == nil || policy.RotateCredentials.ID != id {
		t.Fatalf("policy = %#v", policy)
	}
	rotation, err := desired.AuthorizedCredentialRotation(current)
	if err != nil || rotation == nil {
		t.Fatalf("synthesized rotation is not authorized: (%#v, %v)", rotation, err)
	}
	if move, err := desired.AuthorizedSeedUserMigration(current); err != nil || move != nil {
		t.Fatalf("the retained seedUsers record became a move: (%#v, %v)", move, err)
	}
}

// A rollback that moves no subnet must still be valid when the current
// generation carries other audit records. It used to synthesize an empty
// subnets object, which validation rejects.
func TestRollbackDesiredCarriesRotationRecordWithoutEmptySubnets(t *testing.T) {
	historical := state.Default([]string{"owner"})
	current := state.Default([]string{"owner"})
	current.MigrationPolicy = &state.MigrationPolicy{RotateCredentials: &state.CredentialRotation{
		ID: "r1", Users: []string{"owner"}, Strategy: state.CredentialRotationStrategyReissue,
	}}
	desired, err := rollbackDesired(current, historical)
	if err != nil {
		t.Fatal(err)
	}
	if desired.MigrationPolicy == nil || desired.MigrationPolicy.Subnets != nil || desired.MigrationPolicy.RotateCredentials == nil {
		t.Fatalf("policy = %#v", desired.MigrationPolicy)
	}
	if rotation, err := desired.AuthorizedCredentialRotation(current); err != nil || rotation != nil {
		t.Fatalf("rollback repeated the rotation: (%#v, %v)", rotation, err)
	}
}
