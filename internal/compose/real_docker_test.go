package compose

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRealDockerLifecycle drives a real Docker daemon. It only runs when
// SPAITER_REAL_DOCKER=1, which the throwaway-VM runner sets; on a developer
// machine it is skipped. It pulls busybox, so the guest needs registry access.
func TestRealDockerLifecycle(t *testing.T) {
	if os.Getenv("SPAITER_REAL_DOCKER") != "1" {
		t.Skip("set SPAITER_REAL_DOCKER=1 (done by run-unit-tests-in-vm.sh) to use a real Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	runner, err := Detect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if runner.DisplayName() == "" {
		t.Error("empty display name")
	}

	dir := t.TempDir()
	project := filepath.Join(dir, "docker-compose.yml")
	name := fmt.Sprintf("svpn-real-%d", os.Getpid())
	body := `name: ` + name + `
services:
  web:
    image: busybox:1.36
    command: ["sh", "-c", "echo hello-from-web; echo $GREETING; sleep 600"]
    environment:
      GREETING: ${GREETING}
  once:
    image: busybox:1.36
    command: ["sh", "-c", "echo done-once; exit 3"]
`
	if err := os.WriteFile(project, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	runner = runner.WithEnvironment(map[string]string{"GREETING": "hi-there"})
	t.Cleanup(func() {
		_ = runner.Down(context.Background(), project, &bytes.Buffer{}, &bytes.Buffer{})
	})

	var out, errb bytes.Buffer
	if err := runner.Pull(ctx, project, &out, &errb); err != nil {
		t.Skipf("cannot pull images (no registry access?): %v: %s", err, errb.String())
	}
	if err := runner.Up(ctx, project, &out, &errb); err != nil {
		t.Fatalf("up: %v: %s", err, errb.String())
	}

	var states []ServiceState
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		states, err = runner.Services(ctx, project)
		if err != nil {
			t.Fatal(err)
		}
		if len(states) == 2 && states[0].State != "created" && states[1].State != "created" {
			once := stateOf(states, "once")
			if strings.EqualFold(once.State, "exited") {
				break
			}
		}
		time.Sleep(time.Second)
	}
	web, once := stateOf(states, "web"), stateOf(states, "once")
	if !web.Running() {
		t.Errorf("web = %+v, want running", web)
	}
	if once.Running() || once.ExitCode != 3 {
		t.Errorf("once = %+v, want exited with code 3", once)
	}

	logs, err := runner.Logs(ctx, project, "web", 20)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs, "hello-from-web") || !strings.Contains(logs, "hi-there") {
		t.Errorf("logs = %q, want the greeting passed through WithEnvironment", logs)
	}
	if _, err := runner.Logs(ctx, project, "nope", 5); err == nil {
		t.Error("logs of an unknown service succeeded")
	}

	if err := runner.StopService(ctx, project, "web", &out, &errb); err != nil {
		t.Fatalf("stop: %v: %s", err, errb.String())
	}
	states, _ = runner.Services(ctx, project)
	if stateOf(states, "web").Running() {
		t.Error("web still running after StopService")
	}

	if err := runner.Recreate(ctx, project, &out, &errb); err != nil {
		t.Fatalf("recreate: %v: %s", err, errb.String())
	}
	states, _ = runner.Services(ctx, project)
	if !stateOf(states, "web").Running() {
		t.Errorf("web not running after Recreate: %+v", states)
	}

	if err := runner.Down(ctx, project, &out, &errb); err != nil {
		t.Fatalf("down: %v: %s", err, errb.String())
	}
	states, err = runner.Services(ctx, project)
	if err != nil || len(states) != 0 {
		t.Errorf("after down: %v %+v", err, states)
	}
}

func stateOf(states []ServiceState, service string) ServiceState {
	for _, s := range states {
		if s.Service == service {
			return s
		}
	}
	return ServiceState{}
}
