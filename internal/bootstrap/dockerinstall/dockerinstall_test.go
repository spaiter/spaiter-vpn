package dockerinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The embedded key is the trust root for every package this installs, so a
// change to it must be a deliberate edit of this digest too.
func TestEmbeddedKeyIsDockersReleaseKey(t *testing.T) {
	sum := sha256.Sum256(Keyring())
	if got := hex.EncodeToString(sum[:]); got != "1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570" {
		t.Fatalf("embedded Docker key digest = %s", got)
	}
	if !strings.HasPrefix(string(Keyring()), "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		t.Fatal("embedded key is not an armored public key")
	}
}

func TestEveryReleaseIsPinnedExactly(t *testing.T) {
	for _, want := range [][2]string{{"ubuntu", "24.04"}, {"debian", "12"}, {"debian", "13"}} {
		release, err := For(want[0], want[1])
		if err != nil {
			t.Fatal(err)
		}
		for _, pkg := range release.Packages(false) {
			name, version, ok := strings.Cut(pkg, "=")
			if !ok || version == "" || !strings.HasSuffix(version, "~"+release.Codename) {
				t.Errorf("%s %s: %s is not pinned to its codename", want[0], want[1], pkg)
			}
			_ = name
		}
		if !strings.Contains(string(release.Sources()), "Suites: "+release.Codename) ||
			!strings.Contains(string(release.Sources()), "Signed-By: "+KeyringPath) {
			t.Errorf("sources for %s do not restrict the repository to its key: %s", release.Codename, release.Sources())
		}
		if !strings.Contains(release.Versions.Engine, release.EngineVersion) || !strings.HasPrefix(release.Versions.Compose, release.ComposeVersion+"-") {
			t.Errorf("%s: reported versions do not match the packages", release.Codename)
		}
	}
	if _, err := For("ubuntu", "22.04"); err == nil {
		t.Fatal("an unsupported release was accepted")
	}
}

type exitOne struct{}

func (exitOne) Error() string { return "exit status 1" }
func (exitOne) ExitCode() int { return 1 }

type call struct {
	env  []string
	name string
	args []string
}

type fakeRunner struct {
	calls     []call
	installed string
	engine    string
	compose   string
	fail      map[string]error
}

func (f *fakeRunner) Run(_ context.Context, env []string, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{env, name, args})
	key := name
	if len(args) > 0 {
		key += " " + args[0]
	}
	if err := f.fail[key]; err != nil {
		return []byte("boom"), err
	}
	switch {
	case name == "dpkg-query":
		return []byte(f.installed + "dpkg-query: no packages found matching podman-docker\n"), exitOne{}
	case name == "docker" && args[0] == "version":
		return []byte(f.engine + "\n"), nil
	case name == "docker" && args[0] == "compose":
		return []byte("v" + f.compose + "\n"), nil
	}
	return nil, nil
}

func newInstaller(t *testing.T, runner *fakeRunner) Installer {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/apt/sources.list.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	return Installer{Runner: runner, Root: root, Now: func() time.Time { return time.Unix(0, 0) }}
}

func TestInstallConfiguresTheRepositoryAndProvesTheVersions(t *testing.T) {
	release, _ := For("ubuntu", "24.04")
	runner := &fakeRunner{engine: release.EngineVersion, compose: release.ComposeVersion}
	installer := newInstaller(t, runner)
	record, err := installer.Install(context.Background(), release, false)
	if err != nil {
		t.Fatal(err)
	}
	if record.Packages["docker-ce"] != release.Versions.Engine || record.Engine != release.EngineVersion || len(record.Files) != 2 {
		t.Fatalf("record = %#v", record)
	}
	key, err := os.ReadFile(filepath.Join(installer.Root, KeyringPath))
	if err != nil || string(key) != string(Keyring()) {
		t.Fatalf("keyring not written: %v", err)
	}
	var install *call
	for i := range runner.calls {
		if runner.calls[i].name == "apt-get" && runner.calls[i].args[0] == "install" {
			install = &runner.calls[i]
		}
	}
	if install == nil || !strings.Contains(strings.Join(install.args, " "), "docker-ce="+release.Versions.Engine) ||
		!strings.Contains(strings.Join(install.env, " "), "DEBIAN_FRONTEND=noninteractive") {
		t.Fatalf("install call = %#v", install)
	}

	// A second attempt over its own files is accepted.
	if _, err := installer.Install(context.Background(), release, false); err != nil {
		t.Fatalf("re-running over our own files: %v", err)
	}
}

func TestInstallRefusesConflictsForeignSourcesAndForeignFiles(t *testing.T) {
	release, _ := For("debian", "12")
	runner := &fakeRunner{installed: "docker.io installed\nrunc not-installed\n", engine: release.EngineVersion, compose: release.ComposeVersion}
	installer := newInstaller(t, runner)
	if _, err := installer.Install(context.Background(), release, false); err == nil || !strings.Contains(err.Error(), "docker.io") {
		t.Fatalf("conflict err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(installer.Root, KeyringPath)); !os.IsNotExist(err) {
		t.Fatal("a refused install wrote the keyring")
	}

	runner.installed = ""
	foreign := filepath.Join(installer.Root, "etc/apt/sources.list.d/docker.list")
	if err := os.WriteFile(foreign, []byte("deb https://download.docker.com/linux/debian bookworm stable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Install(context.Background(), release, false); err == nil || !strings.Contains(err.Error(), "/etc/apt/sources.list.d/docker.list") {
		t.Fatalf("foreign source err = %v", err)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Dir(filepath.Join(installer.Root, KeyringPath)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installer.Root, KeyringPath), []byte("someone else's key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Install(context.Background(), release, false); err == nil || !strings.Contains(err.Error(), "not ours to replace") {
		t.Fatalf("foreign file err = %v", err)
	}
}

func TestComposeOnlyInstallLeavesTheEngineAlone(t *testing.T) {
	release, _ := For("debian", "13")
	runner := &fakeRunner{installed: "docker.io installed\n", compose: release.ComposeVersion}
	installer := newInstaller(t, runner)
	record, err := installer.Install(context.Background(), release, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Packages) != 1 || record.Packages["docker-compose-plugin"] != release.Versions.Compose || record.Engine != "" {
		t.Fatalf("record = %#v", record)
	}
	for _, c := range runner.calls {
		if c.name == "systemctl" || (c.name == "docker" && c.args[0] == "version") {
			t.Fatalf("compose-only install touched the engine: %#v", c)
		}
	}
}

func TestInstallRejectsAVersionItDidNotAskFor(t *testing.T) {
	release, _ := For("ubuntu", "24.04")
	runner := &fakeRunner{engine: "27.0.0", compose: release.ComposeVersion}
	if _, err := newInstaller(t, runner).Install(context.Background(), release, false); err == nil || !strings.Contains(err.Error(), "27.0.0") {
		t.Fatalf("err = %v", err)
	}
}

func TestRecordMergesAcrossInstalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "platform.json")
	if err := WriteRecord(path, Record{Packages: map[string]string{"docker-ce": "1"}, Engine: "29"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteRecord(path, Record{Packages: map[string]string{"docker-compose-plugin": "2"}, Compose: "5"}); err != nil {
		t.Fatal(err)
	}
	record, err := ReadRecord(path)
	if err != nil || record == nil || record.Packages["docker-ce"] != "1" || record.Packages["docker-compose-plugin"] != "2" || record.Engine != "29" {
		t.Fatalf("record = %#v, %v", record, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("record mode = %v, %v", info, err)
	}
	if missing, err := ReadRecord(filepath.Join(t.TempDir(), "absent.json")); err != nil || missing != nil {
		t.Fatalf("absent record = %#v, %v", missing, err)
	}
}
