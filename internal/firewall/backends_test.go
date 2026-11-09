package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// fakeBin makes the named programs the only ones on PATH. Each is a /bin/sh
// script, so it must use shell builtins only: PATH holds nothing else.
func fakeBin(t *testing.T, scripts map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	return dir
}

func readLog(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func TestParseRuleAcceptsOnlyCanonicalPortSlashProtocol(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Rule
		ok   bool
	}{
		{"10861/tcp", Rule{Port: 10861, Network: "tcp"}, true},
		{"53/udp", Rule{Port: 53, Network: "udp"}, true},
		{"65535/tcp", Rule{Port: 65535, Network: "tcp"}, true},
		{"", Rule{}, false},
		{"10861", Rule{}, false},
		{"10861/sctp", Rule{}, false},
		{"10861/TCP", Rule{}, false},
		{"0/tcp", Rule{}, false},
		{"65536/tcp", Rule{}, false},
		{"-1/tcp", Rule{}, false},
		{"http/tcp", Rule{}, false},
		{"6000:6007/tcp", Rule{}, false},
		{"/tcp", Rule{}, false},
	} {
		got, err := ParseRule(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("ParseRule(%q): err=%v, want ok=%v", tc.in, err, tc.ok)
			continue
		}
		if tc.ok && got != tc.want {
			t.Errorf("ParseRule(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
	// The receipt stores String(); retiring a rule later parses it back.
	r := Rule{Port: 4443, Network: "udp", Comment: "ignored"}
	back, err := ParseRule(r.String())
	if err != nil || back.Port != r.Port || back.Network != r.Network || back.Comment != "" {
		t.Fatalf("round trip = %+v, %v (the comment is deliberately not recovered)", back, err)
	}
}

func TestMissingKeepsOrderAndTreatsAnythingButAllowedAsMissing(t *testing.T) {
	rules := []Rule{{Port: 1, Network: "tcp"}, {Port: 2, Network: "tcp"}, {Port: 3, Network: "udp"}, {Port: 4, Network: "udp"}}
	statuses := map[string]Status{"1/tcp": Allowed, "2/tcp": Blocked, "3/udp": Unknown, "4/udp": Blocked}
	got := Missing(rules, statuses)
	if len(got) != 3 || got[0].Port != 2 || got[1].Port != 3 || got[2].Port != 4 {
		t.Fatalf("Missing = %v, want ports 2, 3, 4 in input order", got)
	}
	if got := Missing(rules, allStatuses(rules, Allowed)); len(got) != 0 {
		t.Fatalf("nothing is missing when everything is allowed: %v", got)
	}
	if got := Missing(nil, nil); got != nil {
		t.Fatalf("no rules, nothing missing: %v", got)
	}
}

func tierBHTTPSpec() profile.Spec {
	spec := profile.Defaults([]string{"alice"})
	spec.Tier = profile.TierB
	spec.XDPInterfaces = []string{"eth0"}
	spec.Domain = "vpn.example.net"
	spec.Certs.Source = profile.CertSourceACMEHTTP
	spec.Certs.Email = "ops@example.net"
	return spec
}

func TestChallengeRuleExistsOnlyForHTTP01OnTierB(t *testing.T) {
	spec := tierBHTTPSpec()
	rule, ok := ChallengeRule(spec)
	if !ok || rule.Port != 80 || rule.Network != "tcp" || !strings.Contains(rule.Comment, "http-01") {
		t.Fatalf("HTTP-01 on Tier B: %+v ok=%v, want 80/tcp", rule, ok)
	}

	spec.Certs.AlternativeHTTPPort = 8080
	if rule, _ := ChallengeRule(spec); rule.Port != 8080 {
		t.Fatalf("the alternative HTTP port was ignored: %+v", rule)
	}

	// DNS-01 needs nothing reachable, and a files source brings its own renewal.
	for _, source := range []profile.CertSource{profile.CertSourceACMEDNS, profile.CertSourceFiles} {
		other := tierBHTTPSpec()
		other.Certs.Source = source
		if rule, ok := ChallengeRule(other); ok {
			t.Errorf("source %q opened a challenge port: %+v", source, rule)
		}
	}

	// Tier A serves no certificate, whatever the source field holds.
	tierA := profile.Defaults([]string{"alice"})
	tierA.Certs.Source = profile.CertSourceACMEHTTP
	if rule, ok := ChallengeRule(tierA); ok {
		t.Errorf("Tier A opened a challenge port: %+v", rule)
	}
}

func TestRulesPutTheChallengePortInSortedPosition(t *testing.T) {
	spec := tierBHTTPSpec()
	rules := Rules(spec)
	found := false
	for i, r := range rules {
		if r.Port == 80 && r.Network == "tcp" {
			found = true
		}
		if i > 0 {
			prev := rules[i-1]
			if prev.Port > r.Port || (prev.Port == r.Port && prev.Network > r.Network) {
				t.Fatalf("rules are not sorted by port then network: %v before %v", prev, r)
			}
		}
	}
	if !found {
		t.Fatalf("the HTTP-01 port is missing from %v: without it the CA challenge times out", rules)
	}
}

// ufwStatus is `ufw status` as it prints: v6 duplicates, a rule with no
// protocol, a range, an application profile, a DENY row and an interface rule.
const ufwStatus = `Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
10861/tcp                  ALLOW       Anywhere
10861/tcp (v6)             ALLOW       Anywhere (v6)
5353                       ALLOW       Anywhere
6000:6007/tcp              ALLOW       Anywhere
OpenSSH                    ALLOW       Anywhere
10870/tcp                  DENY        Anywhere
Anywhere on lo             ALLOW       Anywhere
`

func TestCheckReadsAnActiveUFW(t *testing.T) {
	fakeBin(t, map[string]string{"ufw": "[ \"$1\" = status ] || exit 3\nprintf '%s\\n' \"" + strings.ReplaceAll(strings.ReplaceAll(ufwStatus, `\`, `\\`), `"`, `\"`) + "\""})
	rules := []Rule{
		{Port: 10861, Network: "tcp"}, // listed, with a v6 twin
		{Port: 10861, Network: "udp"}, // only tcp was allowed
		{Port: 5353, Network: "udp"},  // bare port covers both protocols
		{Port: 5353, Network: "tcp"},
		{Port: 6001, Network: "tcp"},  // inside a range: ranges are left alone, so not provable
		{Port: 10870, Network: "tcp"}, // DENY row must not count
		{Port: 22, Network: "tcp"},
	}
	statuses, err := Backend{Kind: UFW, Active: true}.Check(rules)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Status{
		"10861/tcp": Allowed, "10861/udp": Blocked, "5353/udp": Allowed, "5353/tcp": Allowed,
		"6001/tcp": Blocked, "10870/tcp": Blocked, "22/tcp": Allowed,
	}
	for rule, status := range want {
		if statuses[rule] != status {
			t.Errorf("%s = %d, want %d", rule, statuses[rule], status)
		}
	}
}

func TestCheckSaysWhyAnActiveUFWCannotBeRead(t *testing.T) {
	fakeBin(t, map[string]string{"ufw": "echo 'ERROR: You need to be root to run this script' >&2\nexit 1"})
	if _, err := (Backend{Kind: UFW, Active: true}).Check([]Rule{{Port: 1, Network: "tcp"}}); err == nil || !strings.Contains(err.Error(), "needs root") {
		t.Fatalf("an unreadable ufw must be an error that says so, not a map of Blocked: %v", err)
	}

	fakeBin(t, nil) // ufw vanished between Detect and Check
	if _, err := (Backend{Kind: UFW, Active: true}).Check([]Rule{{Port: 1, Network: "tcp"}}); err == nil {
		t.Fatal("a missing ufw binary must be an error")
	}
}

func TestCheckWithNoFirewallAllowsEverything(t *testing.T) {
	rules := []Rule{{Port: 1, Network: "tcp"}, {Port: 2, Network: "udp"}}
	statuses, err := Backend{Kind: None}.Check(rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if statuses[r.String()] != Allowed {
			t.Errorf("%s = %d without any host firewall", r, statuses[r.String()])
		}
	}
}

func TestDetect(t *testing.T) {
	const ufwActive = "echo 'Status: active'\necho ''\necho 'To   Action'"
	cases := []struct {
		name    string
		scripts map[string]string
		kind    Kind
		active  bool
		detail  string
	}{
		{"ufw active", map[string]string{"ufw": ufwActive}, UFW, true, "ufw reports Status: active"},
		{"ufw inactive", map[string]string{"ufw": "echo 'Status: inactive'"}, UFW, false, "Status: inactive"},
		{"ufw unreadable", map[string]string{"ufw": "exit 1"}, UFW, false, "could not be read"},
		{"ufw wins over everything else", map[string]string{"ufw": "echo 'Status: inactive'", "firewall-cmd": "echo running", "nft": "echo table", "iptables": ""}, UFW, false, "Status: inactive"},
		{"firewalld running", map[string]string{"firewall-cmd": "echo running"}, Firewalld, true, "firewall-cmd --state: running"},
		{"firewalld not running", map[string]string{"firewall-cmd": "echo 'not running'\nexit 252"}, Firewalld, false, "not running"},
		{"nft with rules", map[string]string{"nft": "echo 'table inet filter {}'"}, NFTables, true, "non-empty"},
		{"nft empty", map[string]string{"nft": "echo ''"}, NFTables, false, "empty ruleset"},
		{"nft unreadable", map[string]string{"nft": "exit 1"}, NFTables, false, "empty ruleset"},
		{"iptables only", map[string]string{"iptables": ""}, IPTables, true, "iptables is present"},
		{"nothing", nil, None, false, "no ufw, firewalld, nft or iptables"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeBin(t, tc.scripts)
			got := Detect()
			if got.Kind != tc.kind || got.Active != tc.active || !strings.Contains(got.Detail, tc.detail) {
				t.Fatalf("Detect() = %+v, want kind=%s active=%v detail containing %q", got, tc.kind, tc.active, tc.detail)
			}
		})
	}
}

func TestUFWApplierRunsOnlyAllowAndDeleteAllow(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "calls")
	fakeBin(t, map[string]string{"ufw": "echo \"$@\" >> " + logPath})
	a, err := NewUFWApplier()
	if err != nil {
		t.Fatal(err)
	}
	if a.Name() != "ufw" {
		t.Fatalf("Name() = %q", a.Name())
	}

	ctx := t.Context()
	if err := a.Add(ctx, Rule{Port: 10861, Network: "tcp", Comment: "spaiter-vpn vless"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Add(ctx, Rule{Port: 53, Network: "udp"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Remove(ctx, Rule{Port: 10861, Network: "tcp", Comment: "not needed to delete"}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"allow 10861/tcp comment spaiter-vpn vless",
		"allow 53/udp",
		"delete allow 10861/tcp",
	}
	got := readLog(t, logPath)
	if len(got) != len(want) {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("call %d = %q, want %q", i, got[i], want[i])
		}
	}
	// The surface cannot express a policy change or a flush.
	for _, line := range got {
		for _, forbidden := range []string{"default", "reset", "enable", "disable", "--force"} {
			if strings.Contains(line, forbidden) {
				t.Errorf("%q contains %q", line, forbidden)
			}
		}
	}
}

func TestUFWApplierReportsTheFailureWithUFWsOwnWords(t *testing.T) {
	fakeBin(t, map[string]string{"ufw": "echo 'ERROR: Bad port' >&2\nexit 1"})
	a, err := NewUFWApplier()
	if err != nil {
		t.Fatal(err)
	}
	err = a.Add(t.Context(), Rule{Port: 1, Network: "tcp"})
	if err == nil || !strings.Contains(err.Error(), "ufw allow 1/tcp") || !strings.Contains(err.Error(), "ERROR: Bad port") {
		t.Fatalf("the error must name the command and carry ufw's message: %v", err)
	}
}

func TestNewUFWApplierWithoutUFW(t *testing.T) {
	fakeBin(t, nil)
	if _, err := NewUFWApplier(); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("got %v", err)
	}
}

func TestPrivilegedCallsGoThroughNonInteractiveSudo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root calls ufw directly")
	}
	logPath := filepath.Join(t.TempDir(), "calls")
	fakeBin(t, map[string]string{
		"sudo": "echo \"sudo $@\" >> " + logPath + "\n[ \"$1\" = -n ] && shift\nexec \"$@\"",
		"ufw":  "echo \"ufw $@\" >> " + logPath,
	})
	if sudoIfNeeded("/usr/sbin/ufw") != "sudo" {
		t.Fatal("a non-root caller with sudo available must go through sudo")
	}
	args := ufwArgs("/usr/sbin/ufw", "status")
	if strings.Join(args, " ") != "-n /usr/sbin/ufw status" {
		t.Fatalf("ufwArgs = %v: -n keeps sudo from hanging on a password prompt", args)
	}

	a, err := NewUFWApplier()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Add(t.Context(), Rule{Port: 7, Network: "tcp"}); err != nil {
		t.Fatal(err)
	}
	got := readLog(t, logPath)
	if len(got) == 0 || !strings.HasPrefix(got[0], "sudo -n ") || !strings.HasSuffix(got[0], "ufw allow 7/tcp") {
		t.Fatalf("calls = %q, want the ufw call wrapped in sudo -n", got)
	}
}

func TestNoSudoMeansDirectCalls(t *testing.T) {
	fakeBin(t, nil)
	if sudoIfNeeded("/usr/sbin/ufw") != "/usr/sbin/ufw" {
		t.Fatal("without sudo the program is called as itself")
	}
	if args := ufwArgs("/usr/sbin/ufw", "status"); len(args) != 1 || args[0] != "status" {
		t.Fatalf("ufwArgs = %v", args)
	}
}

func TestFirstLine(t *testing.T) {
	for in, want := range map[string]string{
		"Status: active\nmore": "Status: active",
		"  padded  \nx":        "padded",
		"single":               "single",
		"":                     "",
		"\nafter blank":        "",
	} {
		if got := firstLine(in); got != want {
			t.Errorf("firstLine(%q) = %q, want %q", in, got, want)
		}
	}
}

// An inactive ufw lists no rules, so reading them would call every port blocked.
// The fake ufw here allows nothing: the answer must come from Active alone, not
// from whatever the machine running the test happens to have open.
func TestInactiveUFWIsNotInterrogated(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "calls")
	fakeBin(t, map[string]string{"ufw": "echo called >> " + logPath + "\necho 'Status: inactive'"})
	rules := []Rule{{Port: 10861, Network: "tcp"}, {Port: 10865, Network: "udp"}}
	statuses, err := Backend{Kind: UFW, Active: false}.Check(rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if statuses[r.String()] != Allowed {
			t.Errorf("%s = %d, want Allowed from an inactive ufw", r, statuses[r.String()])
		}
	}
	if calls := readLog(t, logPath); len(calls) != 0 {
		t.Fatalf("an inactive ufw was asked for its rules: %v", calls)
	}
}
