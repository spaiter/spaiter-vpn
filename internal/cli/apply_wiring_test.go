package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

// onlyPathScripts puts the scripts alone on PATH; they use shell builtins only.
func onlyPathScripts(t *testing.T, scripts map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	return dir
}

func wiringLayout(t *testing.T) discover.Layout {
	root := t.TempDir()
	return discover.Layout{ConfigRoot: root + "/etc", DataRoot: root + "/var", LogrotatePath: root + "/logrotate"}
}

func TestLazyComposeFindsDockerOnFirstUseAndRemembersAFailure(t *testing.T) {
	ctx := context.Background()
	var out bytes.Buffer

	// A host with no Docker yet: every operation reports it, and the lookup is
	// not retried per call.
	onlyPathScripts(t, nil)
	l := &lazyCompose{}
	for name, err := range map[string]error{
		"pull":     l.Pull(ctx, "p.yml", &out, &out),
		"up":       l.Up(ctx, "p.yml", &out, &out),
		"recreate": l.Recreate(ctx, "p.yml", &out, &out),
		"stop":     l.StopService(ctx, "p.yml", "bot", &out, &out),
		"down":     l.Down(ctx, "p.yml", &out, &out),
	} {
		if err == nil || !strings.Contains(err.Error(), "no usable docker") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := l.Services(ctx, "p.yml"); err == nil {
		t.Error("services without docker")
	}
	if _, err := l.Logs(ctx, "p.yml", "x", 5); err == nil {
		t.Error("logs without docker")
	}

	// Docker appears after the lazy runner was built (what the apply that
	// installs it relies on): a fresh one finds it and passes the environment.
	onlyPathScripts(t, map[string]string{"docker": `case "$1" in version) exit 0;; esac; echo "args=$*"; echo "token=$BOT_TOKEN"`})
	l = &lazyCompose{env: map[string]string{"BOT_TOKEN": "s3cret"}}
	out.Reset()
	if err := l.Up(ctx, "/p/c.yml", &out, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "compose -f /p/c.yml up -d") || !strings.Contains(out.String(), "token=s3cret") {
		t.Errorf("up: %q", out.String())
	}
	argLine := strings.SplitN(out.String(), "\n", 2)[0]
	if strings.Contains(argLine, "s3cret") {
		t.Errorf("the token is in argv: %q", argLine)
	}
	if l.DisplayName() != "docker" {
		t.Error("DisplayName")
	}
	if got, err := l.Logs(ctx, "/p/c.yml", "sing-box", 3); err != nil || !strings.Contains(got, "logs --no-color --tail 3 sing-box") {
		t.Errorf("logs: %q %v", got, err)
	}
	// Detected once: the runner is reused.
	first := l.run
	l.Pull(ctx, "/p/c.yml", &out, &out)
	if l.run != first {
		t.Error("docker was detected again")
	}
}

func TestLazyCheckWaitsForTheValidatorAndSaysWhatItUsed(t *testing.T) {
	ctx := context.Background()
	var out bytes.Buffer

	onlyPathScripts(t, nil)
	check := lazyCheck("", "registry.example/core:1", &out)
	err := check(ctx, []byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "even after installing Docker") {
		t.Fatalf("err = %v", err)
	}
	// The failure is the answer for this run; it is not looked up again.
	if err2 := check(ctx, []byte("{}")); err2 == nil || err2.Error() != err.Error() {
		t.Errorf("second call: %v", err2)
	}

	ok := fakeSingBox(t, "exit 0")
	out.Reset()
	check = lazyCheck(ok, "", &out)
	if err := check(ctx, []byte(`{"log":{}}`)); err != nil {
		t.Fatalf("a passing config: %v", err)
	}
	if !strings.Contains(out.String(), "validating generated configuration with "+ok) {
		t.Errorf("announcement: %q", out.String())
	}
	bad := fakeSingBox(t, `echo "FATAL bad" >&2; exit 1`)
	if err := lazyCheck(bad, "", &out)(ctx, []byte("{}")); err == nil || !strings.Contains(err.Error(), "bad") {
		t.Errorf("a failing config: %v", err)
	}
}

func TestApplyOptionsWiresTheRealHostAndRefusesToRunBlind(t *testing.T) {
	ctx := context.Background()
	layout := wiringLayout(t)
	desired := state.Default([]string{"owner"})
	desired.Bootstrap.InstallDocker = false
	var out bytes.Buffer

	// Neither Docker nor a local binary: validation is not optional.
	onlyPathScripts(t, nil)
	_, err := applyOptions(ctx, layout, desired, plan.Plan{}, &out, false, "")
	if err == nil || !strings.Contains(err.Error(), "Validation is not optional") || !strings.Contains(err.Error(), "-sing-box") {
		t.Fatalf("no validator: %v", err)
	}

	// Docker present: the image validates, and the runner is real Docker.
	onlyPathScripts(t, map[string]string{"docker": "exit 0"})
	options, err := applyOptions(ctx, layout, desired, plan.Plan{}, &out, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if options.Layout != layout || options.Compose == nil || options.CheckConfig == nil || !options.Strict ||
		options.Manager == nil || options.Preflight == nil || options.SelfTest == nil || options.Discover == nil || options.Out == nil {
		t.Errorf("incomplete options: %+v", options)
	}
	if !strings.Contains(out.String(), "validating generated configuration with") {
		t.Errorf("the validator is not announced:\n%s", out.String())
	}

	// A local binary replaces the image.
	sb := fakeSingBox(t, "exit 0")
	onlyPathScripts(t, map[string]string{"docker": "exit 0"})
	out.Reset()
	if _, err := applyOptions(ctx, layout, desired, plan.Plan{}, &out, false, sb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), sb) {
		t.Errorf("binary not used: %q", out.String())
	}

	// An apply that installs Docker is wired on a host that has none: nothing is
	// detected up front, or the very apply that installs it would be refused.
	onlyPathScripts(t, nil)
	installing := plan.Plan{Actions: []plan.Action{{ID: "docker-install", Disposition: plan.Apply}}}
	options, err = applyOptions(ctx, layout, desired, installing, &out, false, "")
	if err != nil {
		t.Fatalf("wiring an installing apply: %v", err)
	}
	if _, lazy := options.Compose.(*lazyCompose); !lazy {
		t.Errorf("compose = %T, want the lazy runner", options.Compose)
	}
}

func TestApplyOptionsNeedsTheBotTokenWhenTheBotIsEnabled(t *testing.T) {
	onlyPathScripts(t, map[string]string{"docker": "exit 0"})
	layout := wiringLayout(t)
	desired := state.Default([]string{"owner"})
	desired.Bot.Enabled = true
	desired.Bot.PublicHost = "vpn.example.com"
	desired.Bot.TelegramToken = "telegram-token"
	desired.Bot.AdminIDs = []int64{1}
	// The token is read through the credential store, which refuses a file that
	// is missing or not root's: the apply stops here rather than starting a
	// bot that has no token.
	_, err := applyOptions(context.Background(), layout, desired, plan.Plan{}, &bytes.Buffer{}, false, "")
	if err == nil || !strings.Contains(err.Error(), "telegram-token") {
		t.Fatalf("err = %v", err)
	}
}
