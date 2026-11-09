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

	"filippo.io/age"

	"github.com/spaiter/spaiter-vpn/internal/backup"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

const testPassphrase = "a long enough passphrase"

func layoutArgs(l discover.Layout) []string {
	return []string{"-config-root", l.ConfigRoot, "-data-root", l.DataRoot}
}

// archiveOf backs a deployed layout up to a file and returns the file and a
// passphrase file that opens it.
func archiveOf(t *testing.T) (archive, passFile string, source discover.Layout) {
	t.Helper()
	asRoot(t)
	source = deployedLayout(t)
	dir := t.TempDir()
	passFile = filepath.Join(dir, "pass")
	os.WriteFile(passFile, []byte(testPassphrase+"\n"), 0o600)
	archive = filepath.Join(dir, "vpn.age")
	args := append(layoutArgs(source), "-passphrase-file", passFile, "-o", archive)
	if err := runBackup(context.Background(), &bytes.Buffer{}, args); err != nil {
		t.Fatal(err)
	}
	return archive, passFile, source
}

func freshLayout(t *testing.T) discover.Layout {
	t.Helper()
	root := t.TempDir()
	return discover.Layout{
		ConfigRoot: filepath.Join(root, "etc"), DataRoot: filepath.Join(root, "var"),
		LogrotatePath: filepath.Join(root, "logrotate"), ControlUnitPath: filepath.Join(root, "control.service"),
	}
}

func stdinHolds(t *testing.T, text string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString(text)
	w.Close()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; r.Close() })
}

func TestBackupToAFileIsPrivateAndNeverOverwrites(t *testing.T) {
	archive, _, source := archiveOf(t)
	if m := mode(t, archive); m != 0o600 {
		t.Errorf("archive is %v", m)
	}
	info, _ := os.Stat(archive)
	if info.Size() == 0 {
		t.Fatal("empty archive")
	}
	identity, _ := age.GenerateX25519Identity()
	args := append(layoutArgs(source), "-recipient", identity.Recipient().String(), "-o", archive)
	if err := runBackup(context.Background(), &bytes.Buffer{}, args); err == nil {
		t.Error("an existing backup was overwritten")
	}
	if after, _ := os.Stat(archive); after.Size() != info.Size() {
		t.Error("the existing backup changed")
	}
}

func TestBackupRecipientsFileAndErrors(t *testing.T) {
	asRoot(t)
	source := deployedLayout(t)
	a, _ := age.GenerateX25519Identity()
	b, _ := age.GenerateX25519Identity()
	list := filepath.Join(t.TempDir(), "keys")
	os.WriteFile(list, []byte("# mine\n"+a.Recipient().String()+"\n\n"+b.Recipient().String()+"\n"), 0o600)

	var archive bytes.Buffer
	if err := runBackup(context.Background(), &archive, append(layoutArgs(source), "-recipients-file", list)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []*age.X25519Identity{a, b} {
		if _, err := readBackup(archive.Bytes(), id); err != nil {
			t.Errorf("a listed recipient cannot open it: %v", err)
		}
	}
	other, _ := age.GenerateX25519Identity()
	if _, err := readBackup(archive.Bytes(), other); err == nil {
		t.Error("a stranger opened the backup")
	}

	if err := runBackup(context.Background(), &bytes.Buffer{}, append(layoutArgs(source), "-recipient", "age1nope")); err == nil || !strings.Contains(err.Error(), "recipient") {
		t.Errorf("bad key: %v", err)
	}
	if err := runBackup(context.Background(), &bytes.Buffer{}, append(layoutArgs(source), "-recipients-file", filepath.Join(t.TempDir(), "none"))); err == nil {
		t.Error("a missing recipients file was fine")
	}
	empty := filepath.Join(t.TempDir(), "empty")
	os.WriteFile(empty, []byte("\n\n"), 0o600)
	if err := runBackup(context.Background(), &bytes.Buffer{}, append(layoutArgs(source), "-passphrase-file", empty)); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Errorf("empty passphrase file: %v", err)
	}
}

func TestBackupAsksTwiceAndRefusesTheTerminalAndNonRoot(t *testing.T) {
	asRoot(t)
	source := deployedLayout(t)
	answers := []string{"another long passphrase", "mismatching passphrase"}
	old := readPassphrase
	readPassphrase = func(string) (string, error) { a := answers[0]; answers = answers[1:]; return a, nil }
	t.Cleanup(func() { readPassphrase = old })
	if err := runBackup(context.Background(), &bytes.Buffer{}, layoutArgs(source)); err == nil || !strings.Contains(err.Error(), "differ") {
		t.Errorf("mismatch: %v", err)
	}
	readPassphrase = func(string) (string, error) { return "another long passphrase", nil }
	var archive bytes.Buffer
	if err := runBackup(context.Background(), &archive, layoutArgs(source)); err != nil {
		t.Fatal(err)
	}
	identity, _ := age.NewScryptIdentity("another long passphrase")
	if _, err := readBackup(archive.Bytes(), identity); err != nil {
		t.Errorf("the typed passphrase does not open it: %v", err)
	}

	// A binary archive is not thrown at a terminal.
	oldTTY := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdoutIsTerminal = oldTTY })
	if err := runBackup(context.Background(), os.Stdout, layoutArgs(source)); !errors.Is(err, ErrUsage) {
		t.Errorf("terminal stdout: %v", err)
	}

	runningAsRoot = func() bool { return false }
	if err := runBackup(context.Background(), &bytes.Buffer{}, layoutArgs(source)); err == nil || !strings.Contains(err.Error(), "needs root") {
		t.Errorf("non-root: %v", err)
	}
}

func TestRestoreRefusesBeforeTouchingAnything(t *testing.T) {
	archive, passFile, source := archiveOf(t)
	ctx := context.Background()
	target := freshLayout(t)
	base := append(layoutArgs(target), "-from", archive, "-passphrase-file", passFile)
	run := func(extra ...string) error {
		return runRestore(ctx, &bytes.Buffer{}, append(append([]string(nil), base...), extra...))
	}

	if err := runRestore(ctx, &bytes.Buffer{}, nil); !errors.Is(err, ErrUsage) {
		t.Errorf("no -from: %v", err)
	}
	if err := run("-public-host", "h.example", "-keep-address", "-yes"); !errors.Is(err, ErrUsage) {
		t.Errorf("contradiction: %v", err)
	}
	if err := run("-health-deadline", "1s", "-health-settle", "2s", "-yes"); !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), "-health-settle") {
		t.Errorf("settle >= deadline: %v", err)
	}
	if err := run(); err == nil || !strings.Contains(err.Error(), "pass -yes") {
		t.Errorf("nobody to confirm: %v", err)
	}
	runningAsRoot = func() bool { return false }
	if err := run("-yes"); err == nil || !strings.Contains(err.Error(), "needs root") {
		t.Errorf("non-root: %v", err)
	}
	runningAsRoot = func() bool { return true }

	wrong := filepath.Join(t.TempDir(), "wrong")
	os.WriteFile(wrong, []byte("not the passphrase at all\n"), 0o600)
	err := runRestore(ctx, &bytes.Buffer{}, append(layoutArgs(target), "-from", archive, "-passphrase-file", wrong, "-yes"))
	if err == nil {
		t.Error("a wrong passphrase opened the backup")
	}
	if err := runRestore(ctx, &bytes.Buffer{}, append(layoutArgs(target), "-from", filepath.Join(t.TempDir(), "none"), "-passphrase-file", passFile, "-yes")); err == nil {
		t.Error("a missing archive was fine")
	}

	// The server the backup came from already has a deployment.
	err = runRestore(ctx, &bytes.Buffer{}, append(layoutArgs(source), "-from", archive, "-passphrase-file", passFile, "-yes"))
	if err == nil || !strings.Contains(err.Error(), "already has a deployment") {
		t.Errorf("not fresh: %v", err)
	}
	if _, err := os.Stat(target.ConfigRoot); err == nil {
		t.Error("a refused restore created the config root")
	}
}

func TestRestoreDeclinedLeavesTheStateAndInstallsNothing(t *testing.T) {
	archive, passFile, _ := archiveOf(t)
	target := freshLayout(t)
	restore := discoverHost
	discoverHost = func(_ context.Context, desired state.State, _ discover.Layout) (discover.Observed, error) {
		return fakeObservation(t, desired), nil
	}
	t.Cleanup(func() { discoverHost = restore })
	atTerminal(t, "") // a prompt exists, so -yes is not demanded
	stdinHolds(t, "no\n")

	var out bytes.Buffer
	args := append(layoutArgs(target), "-from", archive, "-passphrase-file", passFile, "-keep-address")
	err := runRestore(context.Background(), &out, args)
	if os.Geteuid() != 0 {
		// The transaction manager hands its directory to root, which a test
		// account cannot do. What happened before that point still counts:
		// the state is placed first so that running the restore again resumes.
		if err == nil || !strings.Contains(err.Error(), "recover an interrupted transaction") {
			t.Fatalf("err = %v", err)
		}
		token, rerr := os.ReadFile(filepath.Join(target.CredentialDir(), "telegram-token"))
		if rerr != nil || string(token) != "123:abc" {
			t.Errorf("credential = %q, %v", token, rerr)
		}
		if _, serr := os.Stat(target.ConfigPath()); serr == nil {
			t.Error("the config was rendered before the plan")
		}
		return
	}
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for _, want := range []string{"Backup of", "Placed", "mode:          fresh", "No key is generated", "nothing was installed"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("lacks %q:\n%s", want, out.String())
		}
	}
	// The credentials came back; nothing was rendered or started.
	token, err := os.ReadFile(filepath.Join(target.CredentialDir(), "telegram-token"))
	if err != nil || string(token) != "123:abc" {
		t.Errorf("credential = %q, %v", token, err)
	}
	if _, err := os.Stat(target.ConfigPath()); err == nil {
		t.Error("the config was rendered before consent")
	}
	if _, err := os.Stat(target.DesiredPath()); err == nil {
		t.Error("the desired state was installed before consent")
	}
}

func TestBootstrapDestructiveCommandsGuardTheirArguments(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the root refusal is the point")
	}
	ctx := context.Background()
	layout := freshLayout(t)
	la := layoutArgs(layout)
	cases := []struct {
		name  string
		run   func(args []string) error
		args  []string
		want  string
		usage bool
	}{
		{"rollback stray", func(a []string) error { return runBootstrapRollback(ctx, &bytes.Buffer{}, a) }, append([]string{"x"}, la...), "flags only", true},
		{"rollback no confirmer", func(a []string) error { return runBootstrapRollback(ctx, &bytes.Buffer{}, a) }, la, "nobody to confirm", false},
		{"rollback root", func(a []string) error { return runBootstrapRollback(ctx, &bytes.Buffer{}, a) }, append([]string{"-yes"}, la...), "needs root", false},
		{"rollback settle", func(a []string) error { return runBootstrapRollback(ctx, &bytes.Buffer{}, a) }, append([]string{"-yes", "-health-settle", "9h"}, la...), "needs root", false},
		{"rotate stray", func(a []string) error { return runBootstrapRotate(ctx, &bytes.Buffer{}, a) }, append([]string{"-users", "a", "x"}, la...), "flags only", true},
		{"rotate no users", func(a []string) error { return runBootstrapRotate(ctx, &bytes.Buffer{}, a) }, la, "-users is required", true},
		{"rotate twice", func(a []string) error { return runBootstrapRotate(ctx, &bytes.Buffer{}, a) }, append([]string{"-users", "a,a"}, la...), "twice", true},
		{"rotate no confirmer", func(a []string) error { return runBootstrapRotate(ctx, &bytes.Buffer{}, a) }, append([]string{"-users", "a"}, la...), "nobody to confirm", false},
		{"rotate root", func(a []string) error { return runBootstrapRotate(ctx, &bytes.Buffer{}, a) }, append([]string{"-users", "a", "-yes"}, la...), "needs root", false},
		{"prune root", func(a []string) error { return runBootstrapPrune(ctx, &bytes.Buffer{}, a) }, append([]string{"-keep", "2"}, la...), "needs root", false},
		{"prune relative layout", func(a []string) error { return runBootstrapPrune(ctx, &bytes.Buffer{}, a) }, []string{"-keep", "2", "-config-root", "rel"}, "absolute", true},
	}
	for _, c := range cases {
		err := c.run(c.args)
		if err == nil || !strings.Contains(err.Error(), c.want) || errors.Is(err, ErrUsage) != c.usage {
			t.Errorf("%s: err = %v (usage %v)", c.name, err, errors.Is(err, ErrUsage))
		}
	}
}

func TestSynthesizeRollbackNeedsACommittedGeneration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the transaction manager hands its directory to root")
	}
	if _, _, err := synthesizeRollback(freshLayout(t), 0); err == nil || !strings.Contains(err.Error(), "no committed generation") {
		t.Errorf("err = %v", err)
	}
}

func TestNewRotationIDIsSortableAndUnique(t *testing.T) {
	now := mustTime(t, "2026-11-08T10:11:12Z")
	a, err := newRotationID(now)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newRotationID(now)
	if !strings.HasPrefix(a, "20261108T101112Z-") || a == b {
		t.Errorf("ids %q %q", a, b)
	}
	later, _ := newRotationID(now.Add(1e9))
	if later <= a[:17] {
		t.Errorf("not sortable: %q then %q", a, later)
	}
}

func readBackup(data []byte, identity age.Identity) (any, error) {
	return backup.Read(bytes.NewReader(data), identity)
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
