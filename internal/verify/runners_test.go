package verify

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// script writes an executable /bin/sh script and returns its path.
func script(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestBinaryRunnerReportsACoreThatExitsWithItsOutput(t *testing.T) {
	bin := script(t, "core", `echo "FATAL refused: $1 $2 $3"; echo more >&2; exit 1`)
	process, err := BinaryRunner(bin)(context.Background(), "/tmp/client.json")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the core to exit", process.Exited)
	logs := process.Logs()
	if !strings.Contains(logs, "FATAL refused: run -c /tmp/client.json") || !strings.Contains(logs, "more") {
		t.Errorf("logs = %q, want both streams and the run arguments", logs)
	}
	process.Stop() // stopping an already-dead core must not hang or panic
}

func TestBinaryRunnerStopsALongRunningCore(t *testing.T) {
	bin := script(t, "core", `echo up; exec sleep 60`)
	process, err := BinaryRunner(bin)(context.Background(), "x")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the core to print", func() bool { return strings.Contains(process.Logs(), "up") })
	if process.Exited() {
		t.Fatal("a running core reported as exited")
	}
	process.Stop()
	if !process.Exited() {
		t.Error("the core is still running after Stop")
	}
}

func TestBinaryRunnerRefusesAMissingBinary(t *testing.T) {
	if _, err := BinaryRunner(filepath.Join(t.TempDir(), "nope"))(context.Background(), "x"); err == nil {
		t.Fatal("a missing binary started")
	}
}

// fakeDocker puts a `docker` on PATH that records its arguments and answers
// the few subcommands the runner uses.
func fakeDocker(t *testing.T, run string) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	body := `echo "$@" >>` + log + "\n" + `case "$1" in
run) ` + run + `;;
inspect) echo false;;
logs) echo "core said hello";;
rm) exit 0;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return log
}

func TestDockerRunnerStartsInspectsReadsAndRemovesTheContainer(t *testing.T) {
	log := fakeDocker(t, `echo abc123`)
	process, err := DockerRunner("repo/core:1")(context.Background(), "/etc/c.json")
	if err != nil {
		t.Fatal(err)
	}
	if !process.Exited() {
		t.Error("inspect said the container is not running, but Exited is false")
	}
	if got := process.Logs(); !strings.Contains(got, "core said hello") {
		t.Errorf("Logs = %q", got)
	}
	process.Stop()

	calls, _ := os.ReadFile(log)
	text := string(calls)
	for _, want := range []string{
		"run -d --name spaiter-vpn-verify-", "--network host", "/etc/c.json:/etc/sing-box/client.json:ro",
		"repo/core:1 run -c /etc/sing-box/client.json", "inspect -f {{.State.Running}} spaiter-vpn-verify-",
		"logs spaiter-vpn-verify-", "rm -f spaiter-vpn-verify-",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("docker calls missing %q:\n%s", want, text)
		}
	}
}

func TestDockerRunnerReportsAStartThatDockerRefuses(t *testing.T) {
	fakeDocker(t, `echo "no such image" >&2; exit 125`)
	_, err := DockerRunner("repo/core:1")(context.Background(), "/etc/c.json")
	if err == nil || !strings.Contains(err.Error(), "start the client core") || !strings.Contains(err.Error(), "no such image") {
		t.Errorf("err = %v", err)
	}
}

func TestExitedIsFalseWhenDockerCannotAnswer(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if (dockerProcess{name: "x"}).Exited() {
		t.Error("an unanswerable inspect was read as 'exited'")
	}
}

func TestAShortCoreLogIsKeptWhole(t *testing.T) {
	log := "a\nb\nc\n"
	if got := headTail(log); got != log {
		t.Errorf("headTail = %q", got)
	}
}
