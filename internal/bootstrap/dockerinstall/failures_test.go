package dockerinstall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEachInstallStepFailsWithItsOwnNameAndTheCommandOutput(t *testing.T) {
	release, _ := For("ubuntu", "24.04")
	cases := map[string]string{
		"apt-get update":   "apt-get update",
		"apt-get install":  "apt-get install",
		"systemctl enable": "start docker.service",
		"dpkg-query -W":    "query installed packages",
	}
	for key, want := range cases {
		runner := &fakeRunner{engine: release.EngineVersion, compose: release.ComposeVersion, fail: map[string]error{key: errors.New("denied")}}
		_, err := newInstaller(t, runner).Install(context.Background(), release, false)
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "boom") {
			t.Errorf("%s failing: err = %v, want %q and the command output", key, err, want)
		}
	}
}

func TestAComposeThatReportsTheWrongVersionOrFailsIsRefused(t *testing.T) {
	release, _ := For("ubuntu", "24.04")
	runner := &fakeRunner{engine: release.EngineVersion, compose: "1.0.0"}
	if _, err := newInstaller(t, runner).Install(context.Background(), release, false); err == nil || !strings.Contains(err.Error(), "compose reports 1.0.0") {
		t.Errorf("wrong compose version: %v", err)
	}
	runner = &fakeRunner{engine: release.EngineVersion, compose: release.ComposeVersion, fail: map[string]error{"docker compose": errors.New("no plugin")}}
	if _, err := newInstaller(t, runner).Install(context.Background(), release, false); err == nil || !strings.Contains(err.Error(), "docker compose version") {
		t.Errorf("failing compose: %v", err)
	}
}

func TestAComposeOnlyInstallRefusesADistributionComposePackage(t *testing.T) {
	release, _ := For("ubuntu", "24.04")
	runner := &fakeRunner{installed: "docker-compose-v2 installed\n", compose: release.ComposeVersion}
	if _, err := newInstaller(t, runner).Install(context.Background(), release, true); err == nil || !strings.Contains(err.Error(), "docker-compose-v2") {
		t.Errorf("err = %v", err)
	}
}

func TestWaitEngineRetriesThenReportsAndHonoursCancellation(t *testing.T) {
	runner := &flakyEngine{failures: 1}
	installer := Installer{Runner: runner}
	version, err := installer.waitEngine(context.Background())
	if err != nil || version != "29.0.0" || runner.calls != 2 {
		t.Fatalf("version=%q err=%v calls=%d, want one retry then success", version, err, runner.calls)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := (Installer{Runner: &flakyEngine{failures: 100}}).waitEngine(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("cancelled wait: %v", err)
	}
}

type flakyEngine struct{ failures, calls int }

func (f *flakyEngine) Run(context.Context, []string, string, ...string) ([]byte, error) {
	f.calls++
	if f.calls <= f.failures {
		return []byte("Cannot connect to the Docker daemon"), errors.New("exit status 1")
	}
	return []byte("29.0.0\n"), nil
}

func TestExecRunnerPassesTheExtraEnvironmentAndReturnsCombinedOutput(t *testing.T) {
	out, err := ExecRunner{}.Run(context.Background(), []string{"SPAITER_TEST=hello"}, "sh", "-c", `echo "$SPAITER_TEST"; echo err >&2; exit 3`)
	if err == nil {
		t.Fatal("exit status 3 was not an error")
	}
	if !strings.Contains(string(out), "hello") || !strings.Contains(string(out), "err") {
		t.Errorf("output = %q", out)
	}
	if (Installer{}).runner() == nil {
		t.Error("no default runner")
	}
	if _, ok := (Installer{}).runner().(ExecRunner); !ok {
		t.Error("the default runner is not the real one")
	}
}

func TestTailKeepsTheLastSixLines(t *testing.T) {
	var lines []string
	for i := 1; i <= 10; i++ {
		lines = append(lines, "line"+string(rune('0'+i%10)))
	}
	got := tail([]byte(strings.Join(lines, "\n") + "\n\n"))
	if n := len(strings.Split(got, "\n")); n != 6 || !strings.HasSuffix(got, "line0") {
		t.Errorf("tail = %q (%d lines)", got, n)
	}
	if got := tail([]byte("one\n")); got != "one" {
		t.Errorf("short tail = %q", got)
	}
}

func TestWriteOwnedRefusesWhatItCannotInspectOrCreate(t *testing.T) {
	root := t.TempDir()
	installer := Installer{Root: root}
	// A parent that is a regular file: neither readable as a directory nor creatable.
	if err := os.WriteFile(filepath.Join(root, "etc"), []byte("file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := installer.writeOwned("/etc/x/key", []byte("k")); err == nil {
		t.Error("a path under a regular file was written")
	}
	// Identical content is accepted without rewriting.
	other := Installer{Root: t.TempDir()}
	if err := other.writeOwned("/etc/k", []byte("same")); err != nil {
		t.Fatal(err)
	}
	info1, _ := os.Stat(other.path("/etc/k"))
	time.Sleep(10 * time.Millisecond)
	if err := other.writeOwned("/etc/k", []byte("same")); err != nil {
		t.Fatal(err)
	}
	if info2, _ := os.Stat(other.path("/etc/k")); !info2.ModTime().Equal(info1.ModTime()) {
		t.Error("identical content was rewritten")
	}
	if info, _ := os.Stat(other.path("/etc/k")); info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v", info.Mode().Perm())
	}
}
