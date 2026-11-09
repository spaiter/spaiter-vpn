package compose

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDocker installs a `docker` that is the only thing on PATH. It uses shell
// builtins only, so nothing real can be reached from it.
func fakeDocker(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return dir
}

func TestDetectPrefersADockerThatAnswersAVersionQuery(t *testing.T) {
	fakeDocker(t, `case "$1" in version) echo 27.0; exit 0;; esac; exit 0`)
	r, err := Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.DisplayName() != "docker" {
		t.Errorf("DisplayName = %q", r.DisplayName())
	}
	if len(r.command) != 1 {
		t.Errorf("command = %v, want the direct docker", r.command)
	}
}

func TestDetectRefusesADaemonThatDeniesTheQuery(t *testing.T) {
	fakeDocker(t, `exit 1`)
	if _, err := Detect(context.Background()); err == nil || !strings.Contains(err.Error(), "no usable docker") {
		t.Errorf("err = %v", err)
	}
}

func TestDetectWithNoDockerAtAll(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := Detect(context.Background()); err == nil {
		t.Error("detected a docker in an empty PATH")
	}
}

func TestDisplayNameOfAnEmptyRunner(t *testing.T) {
	if got := (&ExecRunner{}).DisplayName(); got != "docker" {
		t.Errorf("%q", got)
	}
	if got := (&ExecRunner{command: []string{"sudo", "-n", "docker"}}).DisplayName(); got != "sudo" {
		t.Errorf("%q", got)
	}
}

func TestWithEnvironmentCopiesAndNeverTouchesTheOriginal(t *testing.T) {
	base := &ExecRunner{command: []string{"docker"}, env: []string{"A=1"}}
	if base.WithEnvironment(nil) != base {
		t.Error("no values should return the same runner")
	}
	next := base.WithEnvironment(map[string]string{"TOKEN": "t", "B": "2"})
	if next == base {
		t.Fatal("a new runner was expected")
	}
	if len(base.env) != 1 {
		t.Errorf("the original runner was modified: %v", base.env)
	}
	// Sorted, so the child's environment does not depend on map order.
	if got := strings.Join(next.env, ","); got != "A=1,B=2,TOKEN=t" {
		t.Errorf("env = %s", got)
	}
	next.command[0] = "changed"
	if base.command[0] != "docker" {
		t.Error("the command slice is shared between runners")
	}
}

func TestEnvironmentReachesTheChildButNotItsArguments(t *testing.T) {
	fakeDocker(t, `echo "args=$*"; echo "token=$BOT_TOKEN"`)
	r := (&ExecRunner{command: []string{"docker"}}).WithEnvironment(map[string]string{"BOT_TOKEN": "s3cret-value"})
	var out, errOut bytes.Buffer
	if err := r.Up(context.Background(), "/p/compose.yml", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "token=s3cret-value") {
		t.Errorf("the child did not get the variable: %q", out.String())
	}
	argsLine := strings.SplitN(out.String(), "\n", 2)[0]
	if strings.Contains(argsLine, "s3cret-value") {
		t.Errorf("the secret is in argv, where any local user can read it: %q", argsLine)
	}
}

func TestStopServiceNamesTheServiceAndRefusesAnEmptyOne(t *testing.T) {
	fakeDocker(t, `echo "$*"`)
	r := &ExecRunner{command: []string{"docker"}}
	var out bytes.Buffer
	if err := r.StopService(context.Background(), "/p/c.yml", "vpn-bot", &out, &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "compose -f /p/c.yml stop vpn-bot" {
		t.Errorf("argv = %q", got)
	}
	out.Reset()
	if err := r.StopService(context.Background(), "/p/c.yml", "", &out, &out); err == nil {
		t.Error("an empty service name ran `compose stop` on the whole project")
	}
	if out.Len() != 0 {
		t.Errorf("docker was invoked: %q", out.String())
	}
}

func TestServicesReadsBothComposeShapesAndReportsFailures(t *testing.T) {
	fakeDocker(t, `case "$*" in
*ps*) echo '{"Service":"sing-box","State":"running","Health":"healthy"}'; echo '{"Service":"bot","State":"restarting","ExitCode":1}';;
esac`)
	r := &ExecRunner{command: []string{"docker"}}
	states, err := r.Services(context.Background(), "/p/c.yml")
	if err != nil || len(states) != 2 {
		t.Fatalf("%v %v", states, err)
	}
	if !states[0].Running() || states[1].Running() {
		t.Errorf("running = %v / %v (a restarting container is not running)", states[0].Running(), states[1].Running())
	}

	fakeDocker(t, `echo "boom: no such project" >&2; exit 1`)
	_, err = r.Services(context.Background(), "/p/c.yml")
	if err == nil || !strings.Contains(err.Error(), "boom: no such project") {
		t.Errorf("a failing ps must carry docker's own words: %v", err)
	}
}

func TestLogsPassesTheLineCountAndBothStreams(t *testing.T) {
	fakeDocker(t, `echo "argv=$*"; echo "warn" >&2`)
	r := &ExecRunner{command: []string{"docker"}}
	got, err := r.Logs(context.Background(), "/p/c.yml", "sing-box", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "logs --no-color --tail 40 sing-box") || !strings.Contains(got, "warn") {
		t.Errorf("logs = %q", got)
	}
	fakeDocker(t, `echo "no such service" >&2; exit 2`)
	if _, err := r.Logs(context.Background(), "/p/c.yml", "x", 1); err == nil || !strings.Contains(err.Error(), "no such service") {
		t.Errorf("err = %v", err)
	}
}

func TestRunnersSatisfyTheInterface(t *testing.T) {
	var _ Runner = (*ExecRunner)(nil)
}

// TestUpAndRecreateAlwaysRemoveOrphans: the project is generated, so a
// container the current file does not define is left over from an earlier
// generation. Without the flag, disabling the bot leaves it running forever.
func TestUpAndRecreateAlwaysRemoveOrphans(t *testing.T) {
	fakeDocker(t, `echo "$*"`)
	r := &ExecRunner{command: []string{"docker"}}
	for name, call := range map[string]func(context.Context, string, io.Writer, io.Writer) error{"up": r.Up, "recreate": r.Recreate} {
		var out bytes.Buffer
		if err := call(context.Background(), "/p/c.yml", &out, &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "--remove-orphans") {
			t.Errorf("%s: %q", name, out.String())
		}
	}
	var out bytes.Buffer
	r.Down(context.Background(), "/p/c.yml", &out, &out)
	if strings.Contains(out.String(), "--force-recreate") || strings.Contains(out.String(), "--remove-orphans") {
		t.Errorf("down gained flags: %q", out.String())
	}
}
