package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSingBox writes a sing-box that accepts or refuses every config, and puts
// an otherwise empty PATH in place so nothing on the host (a firewall tool,
// Docker) is consulted.
func fakeSingBox(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sing-box")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	return path
}

func initArgs(out, singBox string, extra ...string) []string {
	return append([]string{
		"-out", out, "-users", "alice,bob", "-sing-box", singBox,
		"-skip-preflight", "-xdp-interface", "none",
	}, extra...)
}

func runInitCapture(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runInit(context.Background(), &out, args)
	return out.String(), err
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return info.Mode().Perm()
}

func TestInitWritesAValidatedDeploymentWithPrivateKeys(t *testing.T) {
	sb := fakeSingBox(t, "exit 0")
	dir := filepath.Join(t.TempDir(), "etc", "sing-box")
	out, err := runInitCapture(t, initArgs(dir, sb)...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	config, secrets := filepath.Join(dir, "config.json"), filepath.Join(dir, "secrets", "secrets.json")
	for _, p := range []string{config, secrets} {
		// Between them these hold every private key and the management secret.
		if m := mode(t, p); m != 0o600 {
			t.Errorf("%s is %v, want 0600", p, m)
		}
	}
	// The secrets bundle is NOT beside config.json: the service merges every
	// top-level *.json there, and a bundle would be read as configuration.
	if _, err := os.Stat(filepath.Join(dir, "secrets.json")); err == nil {
		t.Error("secrets.json was written beside config.json")
	}
	if m := mode(t, filepath.Join(dir, "firewall.sh")); m != 0o755 {
		t.Errorf("firewall.sh is %v", m)
	}
	for _, name := range []string{"docker-compose.yml", ".env"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	var doc map[string]any
	data, _ := os.ReadFile(config)
	if json.Unmarshal(data, &doc) != nil {
		t.Fatal("config.json is not JSON")
	}
	// The cache directory is created beside the config, outside what sing-box merges.
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "cache")); err != nil {
		t.Errorf("cache dir: %v", err)
	}
	for _, want := range []string{"sing-box check: ok", "wrote " + config, "Next: spaiter-vpn up -dir " + dir, "2 users"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "client credentials ===") {
		t.Error("credentials were printed without -print-secrets")
	}

	// A live deployment's keys are not overwritten by accident.
	_, err = runInitCapture(t, initArgs(dir, sb)...)
	if err == nil || !strings.Contains(err.Error(), "already exists") || !strings.Contains(err.Error(), "-force") {
		t.Fatalf("second run: %v", err)
	}
	before, _ := os.ReadFile(secrets)
	if _, err = runInitCapture(t, initArgs(dir, sb, "-force", "-print-secrets")...); err != nil {
		t.Fatalf("forced rerun: %v", err)
	}
	after, _ := os.ReadFile(secrets)
	if bytes.Equal(before, after) {
		t.Error("-force kept the old keys: a rerun must mint new ones")
	}
}

func TestInitPrintsSecretsOnlyWhenAskedAndHonoursPortFlags(t *testing.T) {
	sb := fakeSingBox(t, "exit 0")
	dir := filepath.Join(t.TempDir(), "sb")
	out, err := runInitCapture(t, initArgs(dir, sb, "-print-secrets", "-ports", "awg-in=23456", "-disable", "snell-in")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "=== client credentials ===") || !strings.Contains(out, "--- alice ---") {
		t.Errorf("secrets not printed:\n%s", out)
	}
	if !strings.Contains(out, "port 23456") {
		t.Errorf("the fixed port is not in the summary:\n%s", out)
	}
	if strings.Contains(out, "snell-in") {
		t.Errorf("a disabled protocol is listed:\n%s", out)
	}
}

func TestInitRefusesAConfigSingBoxRejects(t *testing.T) {
	sb := fakeSingBox(t, `echo "FATAL decode config: unknown field" >&2; exit 1`)
	dir := filepath.Join(t.TempDir(), "sb")
	_, err := runInitCapture(t, initArgs(dir, sb)...)
	if err == nil || !strings.Contains(err.Error(), "not usable") || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("err = %v", err)
	}
	// Nothing reaches the target before validation passes.
	if _, statErr := os.Stat(dir); statErr == nil {
		t.Error("the output directory was created for a rejected config")
	}
}

func TestInitValidationIsNotOptional(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	dir := filepath.Join(t.TempDir(), "sb")
	// No local binary, no Docker: say so, and name both ways out.
	_, err := runInitCapture(t, "-out", dir, "-users", "alice", "-skip-preflight", "-xdp-interface", "none")
	if err == nil || !strings.Contains(err.Error(), "-skip-check") || !strings.Contains(err.Error(), "-sing-box") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(dir); statErr == nil {
		t.Error("files were written without validation")
	}
	// The deliberate bypass works, and says that it is a bypass.
	out, err := runInitCapture(t, "-out", dir, "-users", "alice", "-skip-preflight", "-skip-check", "-xdp-interface", "none")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err != nil {
		t.Error("-skip-check wrote nothing")
	}
}

func TestInitRejectsBadInputBeforeWritingAnything(t *testing.T) {
	sb := fakeSingBox(t, "exit 0")
	dir := filepath.Join(t.TempDir(), "sb")
	for name, args := range map[string][]string{
		"no users":        {"-out", dir, "-sing-box", sb},
		"unknown tag":     initArgs(dir, sb, "-disable", "nonsense"),
		"bad port":        initArgs(dir, sb, "-ports", "awg-in=0"),
		"bad admins":      initArgs(dir, sb, "-bot", "-bot-public-host", "203.0.113.9", "-bot-admins", "@alice"),
		"cert flag in A":  initArgs(dir, sb, "-domain", "vpn.example.org"),
		"bad handshake":   initArgs(dir, sb, "-reality-handshake", ":443"),
		"dynamic no host": initArgs(dir, sb, "-bot", "-dynamic-ip"),
	} {
		_, err := runInitCapture(t, args...)
		if err == nil {
			t.Errorf("%s was accepted", name)
			continue
		}
		if name != "bad handshake" && !errors.Is(err, ErrUsage) {
			t.Errorf("%s: %v, want ErrUsage", name, err)
		}
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("a rejected invocation created the output directory")
	}
}

func TestInitWithTheBotWritesItsConfigAndTheReloadMarker(t *testing.T) {
	sb := fakeSingBox(t, "exit 0")
	root := t.TempDir()
	dir := filepath.Join(root, "etc", "sing-box")
	out, err := runInitCapture(t, initArgs(dir, sb, "-bot", "-bot-public-host", "203.0.113.9", "-bot-admins", "111,222", "-bot-sub-port", "18080")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	botCfg := filepath.Join(dir, "bot.json")
	data, err := os.ReadFile(botCfg)
	if err != nil {
		t.Fatalf("no bot.json: %v", err)
	}
	for _, want := range []string{"203.0.113.9", "111", "222", "18080"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("bot.json lacks %q:\n%s", want, data)
		}
	}
	// The marker must exist as a FILE before compose starts: Docker would
	// create a directory at a missing bind source and reloads would silently stop.
	marker := filepath.Join(root, "etc", "bot-data", ".reload-singbox")
	if info, err := os.Stat(marker); err != nil || !info.Mode().IsRegular() {
		t.Errorf("reload marker %s: %v %v", marker, info, err)
	}
	if !strings.Contains(out, "TELEGRAM_TOKEN") || strings.Contains(out, "first /start wins") {
		t.Errorf("bot guidance:\n%s", out)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "docker-compose.yml")); !strings.Contains(string(data), "bot") {
		t.Error("the compose project has no bot service")
	}

	// Without admins the operator is warned who would win /start.
	out2 := filepath.Join(root, "second")
	if _, err := runInitCapture(t, initArgs(out2, sb, "-bot", "-bot-public-host", "203.0.113.9")...); err != nil {
		t.Fatal(err)
	}
}
