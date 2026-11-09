package preflight

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/firewall"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// TestIPv6BindingCatchesBindv6only is the test this check exists for.
//
// With net.ipv6.bindv6only=1 the server starts, logs nothing unusual, and is
// unreachable for every IPv4 client, because a `::` socket then refuses
// mapped IPv4. There is no second symptom to notice later, which is why the
// check has to be proven to fire rather than observed to pass on a host where
// the sysctl happens to be 0.
func TestIPv6BindingCatchesBindv6only(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})

	cases := []struct {
		name     string
		values   map[string]string
		severity Severity
		mentions string
	}{
		{
			name:     "dual-stack works",
			values:   map[string]string{"net.ipv6.conf.all.disable_ipv6": "0", "net.ipv6.bindv6only": "0"},
			severity: Pass,
		},
		{
			name:     "bindv6only makes the server IPv6-only",
			values:   map[string]string{"net.ipv6.conf.all.disable_ipv6": "0", "net.ipv6.bindv6only": "1"},
			severity: Fail,
			mentions: "bindv6only",
		},
		{
			name:     "ipv6 disabled makes the bind fail",
			values:   map[string]string{"net.ipv6.conf.all.disable_ipv6": "1"},
			severity: Fail,
			mentions: "disable_ipv6",
		},
		{
			name:     "ipv6 compiled out",
			values:   map[string]string{},
			severity: Fail,
			mentions: "compiled out",
		},
		{
			name:     "bindv6only unreadable is unknown, not fine",
			values:   map[string]string{"net.ipv6.conf.all.disable_ipv6": "0"},
			severity: Unknown,
			mentions: "bindv6only",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restore := fakeSysctl(t, tc.values)
			defer restore()

			checks := checkIPv6Binding(spec)
			if len(checks) != 1 {
				t.Fatalf("got %d checks, want 1", len(checks))
			}
			got := checks[0]
			if got.Severity != tc.severity {
				t.Errorf("severity is %s, want %s (detail: %s)", got.Severity, tc.severity, got.Detail)
			}
			if tc.mentions != "" && !strings.Contains(got.Detail+got.Remedy, tc.mentions) {
				t.Errorf("neither detail nor remedy mentions %q:\n  detail: %s\n  remedy: %s", tc.mentions, got.Detail, got.Remedy)
			}
			if got.Severity != Pass && got.Remedy == "" {
				t.Error("a non-passing check with no remedy is just an obstacle")
			}
		})
	}
}

func TestIPv6BindingIsSkippedForAnIPv4Listener(t *testing.T) {
	// The whole dual-stack question only arises because the inbounds bind the
	// IPv6 wildcard. On an IPv4 listen address the sysctls are irrelevant, and
	// reporting them would be noise — so the check must not even read them.
	restore := fakeSysctl(t, map[string]string{"net.ipv6.bindv6only": "1"})
	defer restore()

	spec := profile.Defaults([]string{"alice"})
	spec.PublicListen = netip.MustParseAddr("0.0.0.0")

	checks := checkIPv6Binding(spec)
	if len(checks) != 1 || checks[0].Severity != Pass {
		t.Fatalf("an IPv4 listener should pass regardless of bindv6only, got %+v", checks)
	}
}

func TestXDPDisabledIsAWarningWithTheConsequenceSpelledOut(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	spec.XDPInterfaces = nil

	checks := checkXDP(spec)
	if len(checks) != 1 {
		t.Fatalf("got %d checks, want 1", len(checks))
	}
	if checks[0].Severity != Warn {
		t.Errorf("severity is %s, want WARN: a missing blocker is a degraded deployment, not a broken one", checks[0].Severity)
	}
	// The point of the remedy is that the operator understands what they lose:
	// detection still fires, but the offender is never banned.
	if !strings.Contains(checks[0].Remedy, "ban") {
		t.Errorf("the remedy does not say what is lost: %q", checks[0].Remedy)
	}
}

func TestReportErrSeparatesFailuresFromWarnings(t *testing.T) {
	warnOnly := &Report{Checks: []Check{
		{Name: "a", Severity: Pass},
		{Name: "b", Severity: Warn, Remedy: "x"},
	}}
	if err := warnOnly.Err(false); err != nil {
		t.Errorf("warnings alone must not stop the operation: %v", err)
	}
	if err := warnOnly.Err(true); err == nil {
		t.Error("-strict must turn warnings into a failure")
	}

	unknownOnly := &Report{Checks: []Check{{Name: "a", Severity: Unknown, Remedy: "x"}}}
	if err := unknownOnly.Err(false); err != nil {
		t.Errorf("an unknown alone must not stop the operation: %v", err)
	}
	if err := unknownOnly.Err(true); err == nil {
		t.Error("-strict must treat \"cannot tell\" as not clean")
	}

	failed := &Report{Checks: []Check{{Name: "a", Severity: Fail, Remedy: "x"}}}
	if err := failed.Err(false); err == nil {
		t.Error("a failure must stop the operation even without -strict")
	}
}

func TestPortCheckCountsBothNetworks(t *testing.T) {
	// shadowsocks binds TCP and UDP, everything else one of the two. The count
	// in the report is listeners, not protocols, and conflating the two would
	// hide a UDP conflict behind a free TCP port of the same number.
	spec := profile.Defaults([]string{"alice"})
	expected := 0
	for _, p := range spec.EnabledProtocols() {
		expected += len(p.Networks())
	}
	if expected != 13 {
		t.Fatalf("the twelve Tier A protocols should bind 13 listeners, got %d", expected)
	}

	checks := checkPorts(spec, false)
	if len(checks) != 1 {
		t.Fatalf("got %d checks, want 1", len(checks))
	}
	// On a host where the default ports happen to be free this reports the
	// listener count; where they are not, it names the conflicts. Either way
	// the check must mention the ports it looked at rather than be silent.
	if checks[0].Detail == "" {
		t.Error("the port check produced no detail")
	}
}

func TestSeverityStringsAreDistinct(t *testing.T) {
	seen := map[string]Severity{}
	for _, s := range []Severity{Pass, Warn, Unknown, Fail} {
		text := s.String()
		if other, dup := seen[text]; dup {
			t.Errorf("severities %d and %d both render as %q", other, s, text)
		}
		seen[text] = s
	}
	if got := Severity(99).String(); got != "????" {
		t.Errorf("an unknown severity renders as %q; it must be obviously wrong rather than plausible", got)
	}
}

// fakeSysctl replaces the sysctl reader with a fixed table. A name absent from
// the table reads as an error, which is how a kernel without IPv6 behaves.
func fakeSysctl(t *testing.T, values map[string]string) func() {
	t.Helper()
	original := sysctl
	sysctl = func(name string) (string, error) {
		value, ok := values[name]
		if !ok {
			return "", fmt.Errorf("no such sysctl: %s", name)
		}
		return value, nil
	}
	return func() { sysctl = original }
}

// TestManagementPortConflictIsAFailure. The clash API is not a protocol port,
// so checkPorts never looked at it, and a conflict there is the exact failure
// mode this package exists for: the core refuses the bind and exits, so every
// protocol port reads as free while the deployment is not there at all.
func TestManagementPortConflictIsAFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	taken := listener.Addr().(*net.TCPAddr).Port

	spec := profile.Defaults([]string{"alice"})
	spec.ClashAPIListen = fmt.Sprintf("127.0.0.1:%d", taken)
	check := checkManagementPort(spec, false)
	if check.Severity != Fail {
		t.Fatalf("severity = %s, want Fail: %s", check.Severity, check.Detail)
	}
	if !strings.Contains(check.Remedy, "started and then vanished") {
		t.Errorf("the remedy does not say what the operator would see: %q", check.Remedy)
	}

	// A bare ":port" is valid in the config and means every interface; reading
	// it as unparseable would skip the check on a configuration the core
	// accepts.
	spec.ClashAPIListen = fmt.Sprintf(":%d", taken)
	if check := checkManagementPort(spec, false); check.Severity != Fail {
		t.Fatalf("a wildcard listener was not checked: %s / %s", check.Severity, check.Detail)
	}

	spec.ClashAPIListen = "127.0.0.1:9"
	if check := checkManagementPort(spec, false); check.Severity == Fail {
		t.Fatalf("a free port was reported as taken: %s", check.Detail)
	}
}

// TestLogRotationCheckDoesNotBlockTheApplyThatInstallsIt. Found by the
// acceptance run: preflight runs before any host file is written, so at debug
// level it correctly reported that nothing rotates the log — and failed the
// apply whose next step installs the rotation. The check's question is whether
// the log will be reclaimed, not whether the file is already on disk.
func TestLogRotationCheckDoesNotBlockTheApplyThatInstallsIt(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	spec.LogLevel = "debug"
	dir := t.TempDir()
	// Hermetic: a host may have no readable /etc/logrotate.d at all.
	old := logrotateCovers
	logrotateCovers = func(string) (bool, bool) { return false, true }
	defer func() { logrotateCovers = old }()

	blocked := checkLogRotation(Options{Spec: spec, ConfigDir: dir})
	if len(blocked) != 1 {
		t.Fatalf("got %d checks, want 1", len(blocked))
	}
	// Still a failure for a caller that is NOT going to install it: at debug
	// level an unrotated append-only log is a countdown to a full disk.
	if blocked[0].Severity != Fail {
		t.Fatalf("severity = %s, want Fail when nothing will rotate the log", blocked[0].Severity)
	}

	promised := checkLogRotation(Options{Spec: spec, ConfigDir: dir, LogrotateWillBeInstalled: true})
	if promised[0].Severity != Pass {
		t.Fatalf("severity = %s, want Pass when the apply installs the rotation: %s", promised[0].Severity, promised[0].Detail)
	}
	if !strings.Contains(promised[0].Detail, "installs the rotation") {
		t.Errorf("the pass does not say why it passed: %q", promised[0].Detail)
	}
}

// TestOwnListenersAreNotConflictsWhileConverging. Without this a converging
// apply can never pass its own preflight: the port check sees every port bound
// by the deployment it is about to update and calls them conflicts.
func TestOwnListenersAreNotConflictsWhileConverging(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	taken := uint16(listener.Addr().(*net.TCPAddr).Port)

	spec := profile.Defaults([]string{"alice"})
	// Point one protocol at the bound port so the check has a real conflict.
	for _, p := range spec.EnabledProtocols() {
		if len(p.Networks()) > 0 && p.Networks()[0] == "tcp" {
			spec.Ports[p] = taken
			break
		}
	}
	spec.ClashAPIListen = fmt.Sprintf("127.0.0.1:%d", taken)

	fresh := checkPorts(spec, false)
	if fresh[0].Severity != Fail {
		t.Fatalf("a fresh install must still refuse a taken port: %s / %s", fresh[0].Severity, fresh[0].Detail)
	}
	if checkManagementPort(spec, false).Severity != Fail {
		t.Fatal("a fresh install must still refuse a taken management port")
	}

	converging := checkPorts(spec, true)
	if converging[0].Severity != Pass {
		t.Fatalf("severity = %s, want Pass while converging: %s", converging[0].Severity, converging[0].Detail)
	}
	if !strings.Contains(converging[0].Detail, "bound by this deployment") {
		t.Errorf("the pass does not say why it passed: %q", converging[0].Detail)
	}
	if checkManagementPort(spec, true).Severity != Pass {
		t.Error("the management port bound by the running core was treated as a conflict")
	}

	// And the inverse: nothing bound while converging is not a clean result,
	// it means the deployment is not serving. Port 1 stands in for "certainly
	// free": binding it needs root, so nothing on a test host is listening
	// there — unlike the generated defaults, which are bound on the very host
	// this suite usually runs on.
	idle := profile.Defaults([]string{"alice"})
	for _, p := range idle.EnabledProtocols() {
		idle.Ports[p] = 1
	}
	if check := checkPorts(idle, true)[0]; check.Severity != Warn {
		t.Fatalf("severity = %s, want Warn when a running deployment binds nothing: %s", check.Severity, check.Detail)
	}
}

// TestFirewallCheckDoesNotBlockTheApplyThatOpensThePorts. The same defect as
// the rotation check, found the same way and only once a host with its firewall
// actually switched on ran the suite: preflight reports the deployment's ports
// as blocked, correctly, and fails the apply whose next step opens them.
func TestFirewallCheckDoesNotBlockTheApplyThatOpensThePorts(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	// The real backend on the test host decides what this can assert, so the
	// test is written against both outcomes rather than assuming either.
	backend := firewall.Detect()
	blocked := checkFirewall(spec, false)
	promised := checkFirewall(spec, true)

	if backend.Kind != firewall.UFW || !backend.Active {
		if promised[0].Severity != blocked[0].Severity {
			t.Fatalf("the promise changed the verdict on a backend the caller cannot write to: %s -> %s",
				blocked[0].Severity, promised[0].Severity)
		}
		t.Skipf("no active UFW on this host (%s, active=%t); the downgrade is only valid for one it can write to",
			backend.Kind, backend.Active)
	}
	if blocked[0].Severity == Fail && promised[0].Severity != Pass {
		t.Fatalf("a blocked port still failed although the apply opens it: %s / %s", promised[0].Severity, promised[0].Detail)
	}
	if promised[0].Severity == Pass && blocked[0].Severity == Fail &&
		!strings.Contains(promised[0].Detail, "this apply opens them") {
		t.Errorf("the pass does not say why it passed: %q", promised[0].Detail)
	}
}

func TestLogRotationCheckSaysUnknownWhenTheHostCannotBeRead(t *testing.T) {
	old := logrotateCovers
	defer func() { logrotateCovers = old }()
	logrotateCovers = func(string) (bool, bool) { return false, false }
	checks := checkLogRotation(Options{Spec: profile.Defaults([]string{"alice"}), ConfigDir: t.TempDir()})
	if len(checks) != 1 || checks[0].Severity != Unknown {
		t.Fatalf("an unreadable logrotate.d must be Unknown, not a verdict: %+v", checks)
	}
	logrotateCovers = func(string) (bool, bool) { return true, true }
	if checks = checkLogRotation(Options{Spec: profile.Defaults([]string{"alice"}), ConfigDir: t.TempDir()}); checks[0].Severity != Pass {
		t.Fatalf("a covered log: %+v", checks)
	}
	if checkLogRotation(Options{}) != nil {
		t.Error("no config dir, nothing to check")
	}
}
