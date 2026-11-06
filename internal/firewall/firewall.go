// Package firewall works out which of a deployment's ports a host firewall
// has to let through, whether it currently does, and what to run if it does
// not.
//
// It deliberately does not reconfigure anything by itself. Firewall changes are
// the classic way to lock yourself out of a machine you are halfway through
// setting up, so this emits a script the operator can read first. Nothing here
// ever touches a default policy either — only `allow` rules for specific ports
// are produced, because a tool that adjusts policy on a host it does not
// understand is a tool that eventually cuts someone's SSH.
package firewall

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// Rule is one port a deployment needs reachable.
type Rule struct {
	Port    uint16
	Network string // "tcp" or "udp"
	Comment string
}

func (r Rule) String() string { return fmt.Sprintf("%d/%s", r.Port, r.Network) }

// ChallengeRule is the ACME HTTP-01 port, when that is how certificates are
// obtained.
//
// Only for the HTTP-01 source. DNS-01 needs nothing reachable — that is its
// whole advantage — and the files source has somebody else's renewal process
// with its own, separate requirements.
func ChallengeRule(spec profile.Spec) (Rule, bool) {
	if spec.Tier != profile.TierB || spec.Certs.Source != profile.CertSourceACMEHTTP {
		return Rule{}, false
	}
	needed := false
	for _, p := range spec.EnabledProtocols() {
		if p.NeedsCertificate() {
			needed = true
			break
		}
	}
	if !needed {
		return Rule{}, false
	}
	port := spec.Certs.AlternativeHTTPPort
	if port == 0 {
		port = 80
	}
	return Rule{Port: port, Network: "tcp", Comment: "spaiter-vpn acme http-01 challenge"}, true
}

// Rules returns what the deployment needs opened.
//
// Only the internet-facing listeners. The two that bind loopback are left out
// on purpose, and that is a correctness matter rather than tidiness: opening
// the shadowsocks port would expose a shadowsocks server that was only ever
// meant to be reachable through shadowtls, and opening the websocket one would
// expose vless in clear text.
func Rules(spec profile.Spec) []Rule {
	var rules []Rule
	for _, p := range spec.EnabledProtocols() {
		if !p.IsInternetFacing(spec) {
			continue
		}
		for _, network := range p.Networks() {
			rules = append(rules, Rule{
				Port:    spec.Ports[p],
				Network: network,
				Comment: "spaiter-vpn " + string(p),
			})
		}
	}
	// The HTTP-01 challenge needs a door of its own, and it is the one port
	// here that belongs to no protocol — so iterating the protocols alone
	// misses it. Without it the challenge times out, the CA records a failed
	// authorisation against an hourly limit, and the deployment serves no TLS
	// while the only clue is an issuance error in the log.
	if challenge, ok := ChallengeRule(spec); ok {
		rules = append(rules, challenge)
	}

	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Port != rules[j].Port {
			return rules[i].Port < rules[j].Port
		}
		return rules[i].Network < rules[j].Network
	})
	return rules
}

// Kind names a firewall backend.
type Kind string

const (
	UFW       Kind = "ufw"
	Firewalld Kind = "firewalld"
	NFTables  Kind = "nftables"
	IPTables  Kind = "iptables"
	// None means no host firewall was found. That is not the same as "the
	// ports are reachable": a cloud provider's firewall sits outside the
	// machine and is invisible from in here.
	None Kind = "none"
)

// Backend is the firewall this host uses.
type Backend struct {
	Kind Kind
	// Active is whether it is actually enforcing. An installed-but-inactive
	// ufw blocks nothing, and reporting its empty rule list as "port not
	// allowed" would send the operator to fix the wrong thing.
	Active bool
	// Detail is how this was determined, for the report.
	Detail string
}

// Detect finds the host firewall.
func Detect() Backend {
	if path, err := exec.LookPath("ufw"); err == nil {
		out, err := exec.Command(sudoIfNeeded(path), ufwArgs(path, "status")...).Output()
		if err == nil {
			active := strings.Contains(string(out), "Status: active")
			return Backend{UFW, active, "ufw reports " + firstLine(string(out))}
		}
		return Backend{UFW, false, "ufw is installed but its status could not be read (needs root)"}
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		out, _ := exec.Command("firewall-cmd", "--state").Output()
		return Backend{Firewalld, strings.Contains(string(out), "running"), "firewall-cmd --state: " + firstLine(string(out))}
	}
	if path, err := exec.LookPath("nft"); err == nil {
		out, err := exec.Command(sudoIfNeeded(path), ufwArgs(path, "list", "ruleset")...).Output()
		if err == nil && len(strings.TrimSpace(string(out))) > 0 {
			return Backend{NFTables, true, "nft has a non-empty ruleset"}
		}
		return Backend{NFTables, false, "nft is present with an empty ruleset"}
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		return Backend{IPTables, true, "iptables is present"}
	}
	return Backend{None, false, "no ufw, firewalld, nft or iptables found"}
}

// Status is what a backend says about one rule.
type Status int

const (
	// Allowed means the backend has a rule permitting it.
	Allowed Status = iota
	// Blocked means the backend is enforcing and has no such rule.
	Blocked
	// Unknown means the backend could not be interrogated. Reported apart
	// from Blocked, because "I could not read the rules" and "the rules say
	// no" call for different reactions — and claiming the second when the
	// first is true sends people to add rules they already have.
	Unknown
)

// Check reports, per rule, whether the backend lets it through.
func (b Backend) Check(rules []Rule) (map[string]Status, error) {
	switch b.Kind {
	case UFW:
		if !b.Active {
			// An inactive ufw enforces nothing, so every port is as open as
			// the machine's other layers allow.
			return allStatuses(rules, Allowed), nil
		}
		return b.checkUFW(rules)
	case None:
		return allStatuses(rules, Allowed), nil
	default:
		// firewalld, nftables and raw iptables all encode "allow this port"
		// in ways too varied to read reliably. Saying so beats guessing:
		// a wrong "allowed" here is a deployment that silently answers nobody.
		return allStatuses(rules, Unknown), nil
	}
}

func (b Backend) checkUFW(rules []Rule) (map[string]Status, error) {
	path, err := exec.LookPath("ufw")
	if err != nil {
		return nil, err
	}
	out, err := exec.Command(sudoIfNeeded(path), ufwArgs(path, "status")...).Output()
	if err != nil {
		return nil, fmt.Errorf("read ufw status (needs root): %w", err)
	}

	allowed := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "ALLOW") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// The first column is the destination: "10861/tcp", "10861", or
		// "10861/tcp (v6)". Anything that is not a bare port spec — "Anywhere
		// on lo", a range, an application profile — is left alone rather than
		// half-parsed.
		spec := fields[0]
		port, network, ok := parsePortSpec(spec)
		if !ok {
			continue
		}
		if network == "" {
			// A rule with no protocol covers both.
			allowed[fmt.Sprintf("%d/tcp", port)] = true
			allowed[fmt.Sprintf("%d/udp", port)] = true
			continue
		}
		allowed[fmt.Sprintf("%d/%s", port, network)] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	statuses := make(map[string]Status, len(rules))
	for _, r := range rules {
		if allowed[r.String()] {
			statuses[r.String()] = Allowed
		} else {
			statuses[r.String()] = Blocked
		}
	}
	return statuses, nil
}

// Script renders the commands that would open what is missing.
func Script(b Backend, rules []Rule, statuses map[string]Status) string {
	var missing []Rule
	for _, r := range rules {
		if statuses[r.String()] != Allowed {
			missing = append(missing, r)
		}
	}

	var s strings.Builder
	s.WriteString("#!/bin/sh\n")
	s.WriteString("# Generated by spaiter-vpn. Read it before running it.\n")
	s.WriteString("#\n")
	s.WriteString("# Only `allow` rules for this deployment's own ports. Nothing here\n")
	s.WriteString("# touches the default policy, and nothing removes a rule — a tool that\n")
	s.WriteString("# adjusts policy on a host it does not understand eventually cuts\n")
	s.WriteString("# someone's SSH.\n")
	s.WriteString("#\n")
	s.WriteString("# The loopback-only listeners are deliberately absent: the shadowsocks\n")
	s.WriteString("# inbound is reachable only as the shadowtls detour target, and the\n")
	s.WriteString("# websocket one speaks clear text behind a CDN. Opening either would be\n")
	s.WriteString("# a hole, not a fix.\n")
	s.WriteString("set -eu\n\n")

	if len(missing) == 0 {
		s.WriteString("# Nothing to do: every port this deployment needs is already allowed.\n")
		return s.String()
	}

	switch b.Kind {
	case UFW:
		for _, r := range missing {
			fmt.Fprintf(&s, "ufw allow %d/%s comment '%s'\n", r.Port, r.Network, r.Comment)
		}
	case Firewalld:
		for _, r := range missing {
			fmt.Fprintf(&s, "firewall-cmd --permanent --add-port=%d/%s  # %s\n", r.Port, r.Network, r.Comment)
		}
		s.WriteString("firewall-cmd --reload\n")
	case NFTables, IPTables, None:
		s.WriteString("# No supported firewall front-end was detected, so these are iptables\n")
		s.WriteString("# rules. Check they land in the chain your host actually uses, and that\n")
		s.WriteString("# your distribution persists them.\n")
		for _, r := range missing {
			fmt.Fprintf(&s, "iptables -I INPUT -p %s --dport %d -j ACCEPT  # %s\n", r.Network, r.Port, r.Comment)
			fmt.Fprintf(&s, "ip6tables -I INPUT -p %s --dport %d -j ACCEPT  # %s\n", r.Network, r.Port, r.Comment)
		}
	}
	return s.String()
}

func parsePortSpec(spec string) (uint16, string, bool) {
	spec = strings.TrimSpace(spec)
	portPart, networkPart := spec, ""
	if slash := strings.Index(spec, "/"); slash >= 0 {
		portPart, networkPart = spec[:slash], spec[slash+1:]
	}
	if networkPart != "" && networkPart != "tcp" && networkPart != "udp" {
		return 0, "", false
	}
	port, err := strconv.ParseUint(portPart, 10, 16)
	if err != nil || port == 0 {
		return 0, "", false
	}
	return uint16(port), networkPart, true
}

func allStatuses(rules []Rule, s Status) map[string]Status {
	out := make(map[string]Status, len(rules))
	for _, r := range rules {
		out[r.String()] = s
	}
	return out
}

// sudoIfNeeded and ufwArgs keep the privileged calls read-only and explicit:
// reading a firewall's rules needs root on most hosts, and a non-interactive
// sudo keeps that from hanging on a password prompt.
func sudoIfNeeded(path string) string {
	if isRoot() {
		return path
	}
	if _, err := exec.LookPath("sudo"); err == nil {
		return "sudo"
	}
	return path
}

func ufwArgs(path string, args ...string) []string {
	if sudoIfNeeded(path) == "sudo" {
		return append([]string{"-n", path}, args...)
	}
	return args
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func isRoot() bool { return os.Geteuid() == 0 }
