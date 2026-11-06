package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Applier adds and removes individual allow rules.
//
// Typed per rule rather than "run this script", and that is the whole point of
// the interface: the emitted script is a thing an operator reads and chooses to
// run, while bootstrap needs a surface that cannot express "change the default
// policy" or "flush the ruleset" at all. A privileged reconciler behind this
// interface can only open or close one port of its own deployment.
type Applier interface {
	// Add opens one rule. It must be idempotent: re-adding an existing rule is
	// how a converging apply behaves.
	Add(ctx context.Context, rule Rule) error
	// Remove closes one rule. Used only to undo additions this process made.
	Remove(ctx context.Context, rule Rule) error
	// Name identifies the backend for a report.
	Name() string
}

// UFWApplier mutates an active UFW.
//
// UFW only, for now, and deliberately: firewalld, raw nftables and iptables all
// encode "allow this port" in ways varied enough that a wrong guess produces a
// deployment that silently answers nobody, or a removal that takes out a rule
// somebody else depends on. An unreadable ruleset is not permission to write to
// it.
type UFWApplier struct {
	command []string
}

// NewUFWApplier finds a usable ufw. It does not enable it, change a policy or
// read the ruleset; those belong to Detect and Check.
func NewUFWApplier() (*UFWApplier, error) {
	path, err := exec.LookPath("ufw")
	if err != nil {
		return nil, fmt.Errorf("ufw is not installed")
	}
	command := []string{path}
	if sudoIfNeeded(path) == "sudo" {
		command = []string{"sudo", "-n", path}
	}
	return &UFWApplier{command: command}, nil
}

func (a *UFWApplier) Name() string { return "ufw" }

func (a *UFWApplier) Add(ctx context.Context, rule Rule) error {
	args := []string{"allow", rule.String()}
	if rule.Comment != "" {
		// The comment is what lets an operator — or a later recovery — tell
		// bootstrap's additions apart from rules that were already there.
		args = append(args, "comment", rule.Comment)
	}
	return a.run(ctx, args...)
}

func (a *UFWApplier) Remove(ctx context.Context, rule Rule) error {
	return a.run(ctx, "delete", "allow", rule.String())
}

func (a *UFWApplier) run(ctx context.Context, args ...string) error {
	full := append(append([]string(nil), a.command[1:]...), args...)
	output, err := exec.CommandContext(ctx, a.command[0], full...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ufw %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

// ParseRule reads a rule back from its canonical "port/protocol" form.
//
// Needed because the receipt records what a deployment opened as that string,
// and retiring one later means handing the backend a rule again. The comment is
// not part of the form and is not recovered: removal matches on port and
// protocol, and inventing a comment here would suggest it had been remembered.
func ParseRule(text string) (Rule, error) {
	port, network, found := strings.Cut(text, "/")
	if !found {
		return Rule{}, fmt.Errorf("%q is not a port/protocol rule", text)
	}
	if network != "tcp" && network != "udp" {
		return Rule{}, fmt.Errorf("%q names neither tcp nor udp", text)
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		return Rule{}, fmt.Errorf("%q does not start with a port", text)
	}
	return Rule{Port: uint16(value), Network: network}, nil
}

// Missing returns the rules the backend does not currently let through, in the
// order they should be added.
func Missing(rules []Rule, statuses map[string]Status) []Rule {
	var missing []Rule
	for _, rule := range rules {
		if statuses[rule.String()] != Allowed {
			missing = append(missing, rule)
		}
	}
	return missing
}
