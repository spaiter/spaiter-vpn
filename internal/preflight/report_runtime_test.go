package preflight

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/firewall"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// onlyPath puts the given scripts alone on PATH. They use shell builtins only,
// so nothing real can be reached.
func onlyPath(t *testing.T, scripts map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
}

func find(checks []Check, name string) *Check {
	for i := range checks {
		if checks[i].Name == name {
			return &checks[i]
		}
	}
	return nil
}

func TestReportCountsErrAndRenders(t *testing.T) {
	r := &Report{}
	r.add(Check{Name: "a", Severity: Pass, Detail: "fine"},
		Check{Name: "bb", Severity: Warn, Detail: "meh", Remedy: "do x"},
		Check{Name: "", Severity: Fail, Detail: "a nameless check is dropped"},
		Check{Name: "c", Severity: Unknown, Detail: "?"},
		Check{Name: "d", Severity: Pass, Detail: "ok", Remedy: "never shown for a pass"})
	if len(r.Checks) != 4 || r.Count(Pass) != 2 || r.Count(Warn) != 1 || r.Count(Unknown) != 1 || r.Failed() {
		t.Fatalf("%+v", r)
	}
	if err := r.Err(false); err != nil {
		t.Errorf("warnings stopped a non-strict run: %v", err)
	}
	// Strict makes the unproven count: warnings and unknowns both.
	if err := r.Err(true); err == nil || !strings.Contains(err.Error(), "1 warnings, 1 unknown") {
		t.Errorf("strict: %v", err)
	}
	clean := &Report{Checks: []Check{{Name: "a", Severity: Pass}}}
	if clean.Err(true) != nil {
		t.Error("a clean report failed under -strict")
	}

	var out bytes.Buffer
	r.Write(&out)
	text := out.String()
	for _, want := range []string{"PASS  a ", "WARN  bb", "→ do x", "?     c", "2 passed, 1 warnings, 1 unknown, 0 failed"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "never shown") {
		t.Errorf("a passing check printed its remedy:\n%s", text)
	}

	r.add(Check{Name: "boom", Severity: Fail, Detail: "x", Remedy: "y"})
	if err := r.Err(false); err == nil || !strings.Contains(err.Error(), "1 of 5") {
		t.Errorf("failure: %v", err)
	}
	for s, want := range map[Severity]string{Pass: "PASS", Warn: "WARN", Unknown: "?   ", Fail: "FAIL", Severity(9): "????"} {
		if s.String() != want {
			t.Errorf("Severity(%d) = %q", s, s.String())
		}
	}
}

func TestPrivilegesCheckFollowsTheUID(t *testing.T) {
	c := checkPrivileges()
	if os.Geteuid() == 0 {
		if c.Severity != Pass {
			t.Errorf("root: %+v", c)
		}
		return
	}
	if c.Severity != Warn || !strings.Contains(c.Detail, "uid") || c.Remedy == "" {
		t.Errorf("non-root: %+v", c)
	}
}

func TestDirectoryChecks(t *testing.T) {
	dir := t.TempDir()
	if got := checkDirectories(Options{}); len(got) != 0 {
		t.Errorf("no directories, no checks: %+v", got)
	}
	file := filepath.Join(dir, "afile")
	os.WriteFile(file, []byte("x"), 0o600)
	got := checkDirectories(Options{ConfigDir: filepath.Join(file, "sub")})
	if c := find(got, "config directory"); c == nil || c.Severity != Fail || c.Remedy == "" {
		t.Errorf("a directory below a file: %+v", got)
	}
	got = checkDirectories(Options{ConfigDir: dir, CacheDir: filepath.Join(dir, "cache", "deeper")})
	for _, c := range got {
		// Writable, so the verdict is about space; it must say how much.
		if c.Severity == Fail && !strings.Contains(c.Detail, "free") {
			t.Errorf("%+v", c)
		}
		if c.Severity == Pass && c.Name != "config directory" && c.Name != "cache directory" {
			t.Errorf("unexpected name %q", c.Name)
		}
	}
	if len(got) != 2 {
		t.Errorf("both directories must be reported: %+v", got)
	}
}

func fakeUFW(status string) string {
	return "echo '" + status + "'"
}

func TestFirewallCheckReadsUFWAndExplainsWhatItCannotKnow(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	rules := len(firewall.Rules(spec))
	if rules == 0 {
		t.Fatal("no rules for the default spec")
	}

	// Active, nothing allowed: the ports are blocked.
	onlyPath(t, map[string]string{"ufw": fakeUFW("Status: active")})
	got := checkFirewall(spec, false)
	if len(got) != 1 || got[0].Severity != Fail || !strings.Contains(got[0].Detail, "does not allow") {
		t.Fatalf("blocked: %+v", got)
	}
	// The caller is about to open them itself, and the backend is one it can write to.
	got = checkFirewall(spec, true)
	if got[0].Severity != Pass || !strings.Contains(got[0].Detail, "this apply opens them") {
		t.Fatalf("will be added: %+v", got)
	}

	// Inactive ufw enforces nothing.
	onlyPath(t, map[string]string{"ufw": fakeUFW("Status: inactive")})
	got = checkFirewall(spec, false)
	if got[0].Severity != Pass || !strings.Contains(got[0].Detail, "permitted by ufw") {
		t.Fatalf("inactive: %+v", got)
	}
	// The pass still carries the caveat about reachability from outside.
	if !strings.Contains(got[0].Detail, "reachability") || got[0].Remedy == "" {
		t.Errorf("a clean firewall check must not imply reachability: %+v", got[0])
	}

	// No firewall at all.
	onlyPath(t, nil)
	got = checkFirewall(spec, false)
	if got[0].Severity != Pass || !strings.Contains(got[0].Detail, "no host firewall found") {
		t.Fatalf("none: %+v", got)
	}

	// A raw iptables cannot be read reliably: Unknown, never a guessed Pass.
	onlyPath(t, map[string]string{"iptables": "exit 0"})
	got = checkFirewall(spec, true)
	if got[0].Severity != Unknown || !strings.Contains(got[0].Detail, "cannot be read reliably") {
		t.Fatalf("iptables: %+v", got)
	}

	// Nothing exposed to the internet is itself worth a warning.
	empty := profile.Defaults([]string{"alice"})
	empty.Enabled = map[profile.Protocol]bool{profile.Shadowsocks: true}
	if got := checkFirewall(empty, false); got[0].Severity != Warn || !strings.Contains(got[0].Detail, "no internet-facing") {
		t.Fatalf("no exposed ports: %+v", got)
	}
}

func TestXDPChecks(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	spec.XDPInterfaces = nil
	if got := checkXDP(spec); len(got) != 1 || got[0].Severity != Warn || !strings.Contains(got[0].Remedy, "reconnects") {
		t.Errorf("disabled: %+v", got)
	}

	// An interface that does not exist is a failure: a program attached nowhere
	// loads cleanly and sees no traffic.
	got := checkXDPInterfaces([]string{"no-such-if0"})
	if c := find(got, "xdp interface no-such-if0"); c == nil || c.Severity != Fail {
		t.Errorf("missing interface: %+v", got)
	}
	// Loopback is up but never carries the default route.
	got = checkXDPInterfaces([]string{"lo"})
	if c := find(got, "xdp interface lo"); c == nil || (c.Severity != Warn && c.Severity != Pass) {
		t.Errorf("lo: %+v", got)
	}

	spec.XDPInterfaces = []string{"no-such-if0"}
	all := checkXDP(spec)
	for _, name := range []string{"xdp kernel", "xdp bpf support", "xdp btf", "bpffs", "xdp interface no-such-if0"} {
		if find(all, name) == nil {
			t.Errorf("no %q check in %+v", name, all)
		}
	}
	for _, c := range all {
		if (c.Severity == Warn || c.Severity == Fail || c.Severity == Unknown) && c.Remedy == "" {
			t.Errorf("%q is not a pass but gives no way forward", c.Name)
		}
	}
}

func TestRuntimeChecks(t *testing.T) {
	ctx := context.Background()

	// A local binary replaces the image.
	onlyPath(t, map[string]string{"my-sing-box": "exit 0"})
	got := checkRuntime(ctx, Options{SingBoxBinary: "my-sing-box"})
	if len(got) != 1 || got[0].Severity != Pass || got[0].Name != "sing-box binary" {
		t.Errorf("binary: %+v", got)
	}
	got = checkRuntime(ctx, Options{SingBoxBinary: "absent-binary"})
	if len(got) != 1 || got[0].Severity != Fail || got[0].Remedy == "" {
		t.Errorf("missing binary: %+v", got)
	}

	// Nothing to run sing-box with.
	onlyPath(t, nil)
	got = checkRuntime(ctx, Options{})
	if len(got) != 1 || got[0].Name != "container runtime" || got[0].Severity != Fail {
		t.Errorf("no runtime: %+v", got)
	}

	// Docker with the plugin and the image.
	onlyPath(t, map[string]string{"docker": `exit 0`})
	got = checkRuntime(ctx, Options{Image: "registry.example/core:1"})
	if c := find(got, "container runtime"); c == nil || c.Severity != Pass {
		t.Fatalf("runtime: %+v", got)
	}
	if c := find(got, "docker compose"); c == nil || c.Severity != Pass {
		t.Errorf("compose: %+v", got)
	}
	if c := find(got, "sing-box image"); c == nil || c.Severity != Pass || !strings.Contains(c.Detail, "registry.example/core:1") {
		t.Errorf("image: %+v", got)
	}

	// Without the compose plugin, and without the image.
	onlyPath(t, map[string]string{"docker": `case "$*" in *compose*|*inspect*) exit 1;; esac; exit 0`})
	got = checkRuntime(ctx, Options{Image: "registry.example/core:1"})
	if c := find(got, "docker compose"); c == nil || c.Severity != Fail || !strings.Contains(c.Remedy, "docker-compose-plugin") {
		t.Errorf("no compose: %+v", got)
	}
	c := find(got, "sing-box image")
	if c == nil || c.Severity != Warn {
		t.Fatalf("no image: %+v", got)
	}
	// A registry host means the pull may need credentials, and the remedy says so.
	if !strings.Contains(c.Remedy, "docker login registry.example") {
		t.Errorf("remedy = %q", c.Remedy)
	}
	got = checkRuntime(ctx, Options{Image: "library-image"})
	if c := find(got, "sing-box image"); c == nil || strings.Contains(c.Remedy, "docker login") {
		t.Errorf("a registry-less image must not suggest a login: %+v", c)
	}
}

func TestSelftestPrerequisiteIsPassOrFailWithAReason(t *testing.T) {
	c := checkSelftestPrerequisites()
	if c.Name != "wireguard module" {
		t.Fatalf("%+v", c)
	}
	if c.Severity == Fail && c.Remedy == "" {
		t.Errorf("a failure with no way forward: %+v", c)
	}
	if c.Severity != Pass && c.Severity != Fail {
		t.Errorf("severity = %v", c.Severity)
	}
}

func TestACMEDataDirectoryCheck(t *testing.T) {
	dir := t.TempDir()
	mk := func(path string) profile.Spec {
		s := profile.Defaults([]string{"alice"})
		s.Certs.DataDirectory = path
		return s
	}
	if c := checkACMEDataDirectory(mk(dir)); c.Severity != Pass {
		t.Errorf("existing dir: %+v", c)
	}
	file := filepath.Join(dir, "f")
	os.WriteFile(file, []byte("x"), 0o600)
	if c := checkACMEDataDirectory(mk(file)); c.Severity != Fail {
		t.Errorf("a file: %+v", c)
	}
	c := checkACMEDataDirectory(mk(filepath.Join(dir, "absent")))
	if c.Severity != Warn || !strings.Contains(c.Remedy, "persistent volume") {
		t.Errorf("absent: %+v (the remedy is the point: creating it is not the same as it surviving)", c)
	}
	if c := checkACMEDataDirectory(mk(filepath.Join(file, "child"))); c.Severity != Unknown {
		t.Errorf("unstatable: %+v", c)
	}
}

func TestRunAssemblesTheChecksForTheDeployment(t *testing.T) {
	onlyPath(t, nil)
	dir := t.TempDir()
	spec := profile.Defaults([]string{"alice"})
	spec.XDPInterfaces = nil
	opts := Options{Spec: spec, ConfigDir: dir, CacheDir: dir, SingBoxBinary: "absent-binary", LogrotateWillBeInstalled: true}
	report := Run(context.Background(), opts)
	for _, name := range []string{"privileges", "config directory", "firewall", "xdp blocker", "sing-box binary"} {
		if find(report.Checks, name) == nil {
			t.Errorf("Run produced no %q check", name)
		}
	}
	if find(report.Checks, "wireguard module") != nil {
		t.Error("the self-test's check ran without ForSelftest")
	}
	if !report.Failed() {
		t.Error("a missing sing-box binary must fail the run")
	}
	opts.ForSelftest = true
	if find(Run(context.Background(), opts).Checks, "wireguard module") == nil {
		t.Error("ForSelftest added no wireguard check")
	}
}

func TestFreeSpaceThresholds(t *testing.T) {
	dir := t.TempDir()
	old := freeBytes
	defer func() { freeBytes = old }()
	for _, tc := range []struct {
		free uint64
		want Severity
	}{
		{MinimumFreeBytes - 1, Fail},
		{MinimumFreeBytes, Warn},
		{ComfortableFreeBytes - 1, Warn},
		{ComfortableFreeBytes, Pass},
	} {
		freeBytes = func(string) (uint64, error) { return tc.free, nil }
		got := checkDirectories(Options{ConfigDir: dir})
		if len(got) != 1 || got[0].Severity != tc.want {
			t.Errorf("%d bytes free: %+v, want %v", tc.free, got, tc.want)
		}
		if tc.want != Pass && got[0].Remedy == "" {
			t.Errorf("%d bytes free: a finding with no remedy", tc.free)
		}
	}
	// A directory whose free space cannot be read is unproven, not failed.
	freeBytes = func(string) (uint64, error) { return 0, os.ErrInvalid }
	if got := checkDirectories(Options{ConfigDir: dir}); got[0].Severity != Unknown {
		t.Errorf("unreadable free space: %+v", got)
	}
}
