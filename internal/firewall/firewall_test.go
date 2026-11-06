package firewall

import (
	"strconv"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// TestRulesOpenOnlyWhatShouldBeOpen is the test that matters here, because the
// output of this package becomes `ufw allow` lines. A missing rule is an
// inconvenience; a surplus one is a hole that nobody will notice, since the
// deployment works fine with an extra port open.
func TestRulesOpenOnlyWhatShouldBeOpen(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	rules := Rules(spec)

	opened := map[uint16]string{}
	for _, r := range rules {
		opened[r.Port] = r.Network
	}

	// Loopback-only listeners. Exposed, the first speaks shadowsocks to
	// anyone who asks and the second speaks vless in clear text.
	for _, p := range []profile.Protocol{profile.Shadowsocks, profile.VLESSWSCDN} {
		if _, found := opened[spec.Ports[p]]; found {
			t.Errorf("%s binds loopback but its port %d would be opened", p, spec.Ports[p])
		}
	}

	// Wildcard-bound but still internal: these receive plain WireGuard from
	// their own fronts on the same host, so the public door is the front's
	// port. Confirmed against the hand-built deployment, where ufw allows
	// neither.
	for _, p := range []profile.Protocol{profile.WGMasque, profile.WGWDTT} {
		if _, found := opened[spec.Ports[p]]; found {
			t.Errorf("%s sits behind a front but its port %d would be opened", p, spec.Ports[p])
		}
	}

	// And everything genuinely public must be there, with the right transport.
	wantPublic := map[profile.Protocol]string{
		profile.VLESSXHTTP:   "tcp",
		profile.VLESSReality: "tcp",
		profile.ShadowTLS:    "tcp",
		profile.Snell:        "tcp",
		profile.Mieru:        "tcp",
		profile.MTProto:      "tcp",
		profile.AWG2:         "udp",
		profile.AWG3:         "udp",
	}
	for p, network := range wantPublic {
		got, found := opened[spec.Ports[p]]
		if !found {
			t.Errorf("%s is internet-facing but port %d is not opened", p, spec.Ports[p])
			continue
		}
		if got != network {
			t.Errorf("%s: opened as %s, want %s", p, got, network)
		}
	}
	if len(rules) != len(wantPublic) {
		t.Errorf("%d rules for %d public protocols: %v", len(rules), len(wantPublic), rules)
	}
}

func TestRulesFollowPortOverrides(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	for p := range spec.Ports {
		spec.Ports[p] += 11000
	}
	for _, r := range Rules(spec) {
		if r.Port < 11000 {
			t.Errorf("rule %s ignores the port override", r)
		}
	}
}

func TestRulesFollowDisabledProtocols(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	spec.Enabled = map[profile.Protocol]bool{
		profile.VLESSReality: true,
		profile.AWG2:         true,
	}
	rules := Rules(spec)
	if len(rules) != 2 {
		t.Fatalf("got %d rules for two enabled protocols: %v", len(rules), rules)
	}
}

func TestScriptNeverTouchesPolicyOrRemovesRules(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	rules := Rules(spec)
	// Nothing allowed yet, so the script has the most to say.
	statuses := allStatuses(rules, Blocked)

	for _, backend := range []Backend{
		{UFW, true, ""}, {Firewalld, true, ""}, {NFTables, true, ""}, {None, false, ""},
	} {
		script := Script(backend, rules, statuses)
		// A tool that adjusts policy on a host it does not understand
		// eventually cuts someone's SSH.
		for _, forbidden := range []string{
			"default deny", "default-deny", "--set-default", "ufw enable", "ufw reset",
			"ufw delete", "--remove-port", "-D INPUT", "flush",
		} {
			if strings.Contains(strings.ToLower(script), forbidden) {
				t.Errorf("%s script contains %q", backend.Kind, forbidden)
			}
		}
		if !strings.HasPrefix(script, "#!/bin/sh") {
			t.Errorf("%s script has no shebang", backend.Kind)
		}
		if !strings.Contains(script, "set -eu") {
			t.Errorf("%s script does not set -eu", backend.Kind)
		}
		// Every rule it does emit must be one of ours, named by port.
		for _, r := range rules {
			if !strings.Contains(script, strconv.Itoa(int(r.Port))) {
				t.Errorf("%s script is missing port %d", backend.Kind, r.Port)
			}
		}
	}
}

func TestScriptSaysNothingToDoWhenAlreadyOpen(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	rules := Rules(spec)
	script := Script(Backend{UFW, true, ""}, rules, allStatuses(rules, Allowed))
	if strings.Contains(script, "ufw allow") {
		t.Error("script emits rules although every port is already allowed")
	}
	if !strings.Contains(script, "Nothing to do") {
		t.Errorf("script does not say it has nothing to do:\n%s", script)
	}
}

// TestUFWStatusParsing feeds the real output format, including the lines that
// a careless parser would mishandle: IPv6 duplicates, interface rules, ranges
// and application profiles.
func TestUFWStatusParsing(t *testing.T) {
	cases := map[string]struct {
		spec  string
		want  uint16
		proto string
		ok    bool
	}{
		"port and proto":   {"10861/tcp", 10861, "tcp", true},
		"bare port":        {"10861", 10861, "", true},
		"ipv6 duplicate":   {"10861/tcp", 10861, "tcp", true},
		"interface rule":   {"Anywhere", 0, "", false},
		"app profile":      {"OpenSSH", 0, "", false},
		"range":            {"6000:6007/tcp", 0, "", false},
		"zero port":        {"0/tcp", 0, "", false},
		"unknown protocol": {"10861/sctp", 0, "", false},
	}
	for name, tc := range cases {
		port, proto, ok := parsePortSpec(tc.spec)
		if ok != tc.ok {
			t.Errorf("%s: parsePortSpec(%q) ok=%v, want %v", name, tc.spec, ok, tc.ok)
			continue
		}
		if ok && (port != tc.want || proto != tc.proto) {
			t.Errorf("%s: got %d/%q, want %d/%q", name, port, proto, tc.want, tc.proto)
		}
	}
}

func TestInactiveFirewallBlocksNothing(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	rules := Rules(spec)
	// An installed-but-inactive ufw enforces nothing. Reporting its empty
	// rule list as "blocked" would send the operator to fix the wrong thing.
	statuses, err := Backend{UFW, false, ""}.Check(rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if statuses[r.String()] != Allowed {
			t.Errorf("%s reported as not allowed by an inactive firewall", r)
		}
	}
}

func TestUnreadableBackendsReportUnknownNotBlocked(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	rules := Rules(spec)
	// "I cannot read these rules" and "these rules say no" lead to different
	// actions, and claiming the second sends people to add rules they have.
	for _, kind := range []Kind{Firewalld, NFTables, IPTables} {
		statuses, err := Backend{kind, true, ""}.Check(rules)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rules {
			if statuses[r.String()] != Unknown {
				t.Errorf("%s reported %s as %d, want Unknown", kind, r, statuses[r.String()])
			}
		}
	}
}
