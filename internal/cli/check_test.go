package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/deploy"
)

func TestRunUpKeepsItsCLIContractThroughComposeRunner(t *testing.T) {
	dir := t.TempDir()
	composePath := filepath.Join(dir, deploy.ComposeFileName)
	if err := os.WriteFile(composePath, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "docker.log")
	dockerPath := filepath.Join(binDir, "docker")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$DOCKER_TEST_LOG\"\n"
	if err := os.WriteFile(dockerPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("DOCKER_TEST_LOG", logPath)

	var out bytes.Buffer
	if err := runUp(context.Background(), &out, []string{"-dir", dir}); err != nil {
		t.Fatalf("runUp: %v", err)
	}
	invocations, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"version --format {{.Server.Version}}",
		"compose -f " + composePath + " up -d",
	} {
		if !strings.Contains(string(invocations), want) {
			t.Errorf("missing docker invocation %q in:\n%s", want, invocations)
		}
	}
	for _, want := range []string{
		"running docker compose -f " + composePath + " up -d",
		"Next: spaiter-vpn selftest",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing CLI output %q in:\n%s", want, out.String())
		}
	}
}

func TestRunUpStillRefusesAMissingProjectBeforeDockerDetection(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", t.TempDir())
	var out bytes.Buffer
	err := runUp(context.Background(), &out, []string{"-dir", dir})
	if err == nil || !strings.Contains(err.Error(), "run `spaiter-vpn init") {
		t.Fatalf("error = %v", err)
	}
}
