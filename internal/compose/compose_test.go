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

func TestExecRunnerUsesTypedComposeCommands(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "argv.log")
	commandPath := filepath.Join(dir, "docker-fake")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$COMPOSE_TEST_LOG\"\nprintf 'stdout:%s\\n' \"$*\"\nprintf 'stderr:%s\\n' \"$*\" >&2\n"
	if err := os.WriteFile(commandPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COMPOSE_TEST_LOG", logPath)
	runner := &ExecRunner{command: []string{commandPath, "--prefix"}}
	var stdout, stderr bytes.Buffer
	project := "/etc/sing-box/docker-compose.yml"
	for name, call := range map[string]func(context.Context, string, io.Writer, io.Writer) error{
		"pull":     runner.Pull,
		"up":       runner.Up,
		"recreate": runner.Recreate,
		"down":     runner.Down,
	} {
		if err := call(context.Background(), project, &stdout, &stderr); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"--prefix compose -f /etc/sing-box/docker-compose.yml pull",
		"--prefix compose -f /etc/sing-box/docker-compose.yml up -d",
		"--prefix compose -f /etc/sing-box/docker-compose.yml up -d --force-recreate --remove-orphans",
		"--prefix compose -f /etc/sing-box/docker-compose.yml down",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("missing invocation %q in:\n%s", want, data)
		}
	}
	if stdout.Len() == 0 || stderr.Len() == 0 {
		t.Fatal("runner did not connect command output streams")
	}
}

func TestExecRunnerRejectsAnEmptyCommand(t *testing.T) {
	err := (&ExecRunner{}).Up(context.Background(), "project.yml", io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "command is empty") {
		t.Fatalf("error = %v", err)
	}
}
