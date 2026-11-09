package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/secret"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/profile"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// runBootstrap dispatches the bootstrap subcommands.
//
// Bare `bootstrap` is the guided wrapper rather than a second implementation:
// it loads desired state, calls the same planner, prints the plan, asks, and
// calls the same apply engine that `bootstrap apply` does.
func runBootstrap(ctx context.Context, out io.Writer, args []string) error {
	subcommands := map[string]func(context.Context, io.Writer, []string) error{
		"state":      runBootstrapState,
		"credential": runBootstrapCredential,
		"plan":       runBootstrapPlan,
		"apply":      runBootstrapApply,
		"status":     runBootstrapStatus,
		"rollback":   runBootstrapRollback,
		"prune":      runBootstrapPrune,
		"rotate":     runBootstrapRotate,
		"cloud-init": runBootstrapCloudInit,
	}
	// Help about `bootstrap` itself, before the guided fallback: routing -h to
	// apply would describe one subcommand and hide the rest.
	if len(args) == 1 && (args[0] == "-h" || args[0] == "-help" || args[0] == "--help") {
		writeBootstrapUsage(out)
		return flag.ErrHelp
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return runBootstrapApply(ctx, out, args)
	}
	run, known := subcommands[args[0]]
	if !known {
		return fmt.Errorf("%w: unknown bootstrap subcommand %q", ErrUsage, args[0])
	}
	return run(ctx, out, args[1:])
}

func writeBootstrapUsage(out io.Writer) {
	fmt.Fprintf(out, "usage: spaiter-vpn bootstrap [subcommand] [flags]\n\n")
	fmt.Fprintf(out, "Installs this VPN on a fresh server: discover the host, show a plan, apply it\n")
	fmt.Fprintf(out, "under a lock, prove it works, and record the generation.\n\n")
	fmt.Fprintf(out, "  state       write a desired-state document with every default filled in\n")
	fmt.Fprintf(out, "  credential  store a secret by logical name, root-owned and 0600\n")
	fmt.Fprintf(out, "  plan        read-only: what an apply would do, and why\n")
	fmt.Fprintf(out, "  apply       install or converge; the default when no subcommand is given\n")
	fmt.Fprintf(out, "  status      stored intent, recorded generation, current health\n")
	fmt.Fprintf(out, "  rollback    restore an earlier committed generation without rotating users\n")
	fmt.Fprintf(out, "  rotate      reissue the credentials of named users as a new generation\n")
	fmt.Fprintf(out, "  prune       delete old transaction history while retaining rollback points\n")
	fmt.Fprintf(out, "  cloud-init  user-data that installs a verified release on a fresh VPS\n\n")
	fmt.Fprintf(out, "A first install, start to finish:\n\n")
	fmt.Fprintf(out, "  spaiter-vpn bootstrap state -users alice,bob -o desired.json\n")
	fmt.Fprintf(out, "  $EDITOR desired.json\n")
	fmt.Fprintf(out, "  spaiter-vpn bootstrap plan -f desired.json\n")
	fmt.Fprintf(out, "  sudo spaiter-vpn bootstrap apply -f desired.json\n\n")
	fmt.Fprintf(out, "Supported hosts are Ubuntu 24.04 or Debian 12/13 on amd64, with systemd and\n")
	fmt.Fprintf(out, "Docker Engine plus the Compose plugin already installed. There is no remote\n")
	fmt.Fprintf(out, "shell installer, deliberately: piping a downloaded script into root is how a\n")
	fmt.Fprintf(out, "VPN project becomes a supply-chain vector.\n\n")
	fmt.Fprintf(out, "Run `spaiter-vpn bootstrap <subcommand> -h` for its flags.\n")
}

// layoutFlags adds the overrides for the managed filesystem surface.
//
// The defaults are fixed rather than taken from a caller, and these flags exist
// for development and tests. The later control API will expose a logical
// deployment, not an arbitrary host path, so nothing here should grow into a
// remotely settable root.
type layoutFlags struct {
	configRoot  string
	dataRoot    string
	logrotate   string
	controlUnit string
}

func (l *layoutFlags) register(fs interface {
	StringVar(*string, string, string, string)
}) {
	defaults := discover.DefaultLayout()
	fs.StringVar(&l.configRoot, "config-root", defaults.ConfigRoot, "managed configuration root")
	fs.StringVar(&l.dataRoot, "data-root", defaults.DataRoot, "managed data root")
	fs.StringVar(&l.logrotate, "logrotate-path", defaults.LogrotatePath, "logrotate configuration to install")
	fs.StringVar(&l.controlUnit, "control-unit-path", defaults.ControlUnitPath, "systemd unit for the control daemon")
}

func (l layoutFlags) layout() (discover.Layout, error) {
	layout := discover.Layout{ConfigRoot: l.configRoot, DataRoot: l.dataRoot, LogrotatePath: l.logrotate, ControlUnitPath: l.controlUnit}
	for name, path := range map[string]string{
		"-config-root": layout.ConfigRoot, "-data-root": layout.DataRoot, "-logrotate-path": layout.LogrotatePath,
		"-control-unit-path": layout.ControlUnitPath,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return discover.Layout{}, fmt.Errorf("%w: %s must be a clean absolute path, got %q", ErrUsage, name, path)
		}
	}
	return layout, nil
}

// runBootstrapState writes a complete desired-state document.
//
// Defaults are applied here, at document creation, and never while reading one.
// That is what makes a stored document reviewable and hashable, and it is why
// changing a default later cannot alter an existing server on its next apply.
func runBootstrapState(_ context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("bootstrap state", out)
	users := fs.String("users", "", "comma-separated seed user names (required)")
	output := fs.String("o", "-", "where to write the document; - is stdout")
	publicHost := fs.String("public-host", "", "address clients dial: this server's static IP, or a domain")
	dynamicIP := fs.Bool("dynamic-ip", false, "the server's public IP changes; -public-host must then be a domain kept current by dynamic DNS")
	ddnsProvider := fs.String("ddns", "", "with -dynamic-ip: keep -public-host's record from this server through cloudflare, duckdns or dyndns2 (token: `bootstrap credential ddns-token`)")
	ddnsServer := fs.String("ddns-server", "", "dyndns2 update service URL")
	ddnsUser := fs.String("ddns-username", "", "dyndns2 username")
	ddnsIPv6 := fs.Bool("ddns-ipv6", false, "also keep the AAAA record")
	portsFlag := fs.String("ports", "", "fixed ports as tag=port pairs, e.g. vless-reality-in=443,subscription=8443; the rest are drawn at random")
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn bootstrap state -users alice,bob [-ports tag=port,...] [-o FILE]\n\n")
		fmt.Fprintf(out, "Writes a complete desired-state document with every default filled in, for\n")
		fmt.Fprintf(out, "you to read and edit before applying it. It contains no secret values: a\n")
		fmt.Fprintf(out, "credential is referenced by logical name and stored separately with\n")
		fmt.Fprintf(out, "`bootstrap credential`.\n\n")
		fmt.Fprintf(out, "Ports are drawn at random rather than shared by every install, and shown;\n")
		fmt.Fprintf(out, "at a terminal you can keep them or change any of them.\n\n")
		fmt.Fprintf(out, "Seed users are immutable after the first apply. Adding users later is the\n")
		fmt.Fprintf(out, "bot's job, not a desired-state edit.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	names := splitList(*users)
	if len(names) == 0 {
		return fmt.Errorf("%w: -users is required; every protocol is authenticated, so a server with no users accepts nobody", ErrUsage)
	}

	desired := state.Default(names)
	// The table goes where the document does not: stdout may be the document.
	messages := out
	if *output == "-" {
		messages = os.Stderr
	}
	in := newPrompt()
	address, err := choosePublicAddress(context.Background(), in, messages, *publicHost, *dynamicIP, *ddnsProvider == "")
	if err != nil {
		return err
	}
	desired.Bot.PublicHost = address.host
	desired.Bot.DynamicIP = address.dynamic
	desired.DDNS = address.ddns
	if *ddnsProvider != "" {
		if !address.dynamic {
			return fmt.Errorf("%w: -ddns keeps a changing address's record; it needs -dynamic-ip and -public-host", ErrUsage)
		}
		desired.DDNS = &state.DDNS{Provider: *ddnsProvider, Token: ddnsCredential, Server: *ddnsServer, Username: *ddnsUser, IPv6: *ddnsIPv6}
	}
	if err := chooseDocumentPorts(in, messages, &desired, *portsFlag); err != nil {
		return err
	}
	if err := desired.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(desired, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal desired state: %w", err)
	}
	data = append(data, '\n')
	if *output == "-" {
		_, err := out.Write(data)
		return err
	}
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s\n\nNext: edit it, then `spaiter-vpn bootstrap plan -f %s`\n", *output, *output)
	return nil
}

// runBootstrapCredential stores one credential.
//
// Read from stdin rather than taken as an argument: a token in argv is readable
// by any local user through /proc for as long as the process lives, and it ends
// up in the shell history of the person who typed it.
func runBootstrapCredential(_ context.Context, out io.Writer, args []string) error {
	var layoutOpts layoutFlags
	fs := newFlagSet("bootstrap credential", out)
	layoutOpts.register(fs)
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn bootstrap credential <name>\n\n")
		fmt.Fprintf(out, "Stores a credential under its logical name, root-owned and mode 0600. The\n")
		fmt.Fprintf(out, "desired-state document references the name; the value never appears in it.\n\n")
		fmt.Fprintf(out, "The value is read from standard input and is not echoed when that is a\n")
		fmt.Fprintf(out, "terminal:\n\n")
		fmt.Fprintf(out, "  spaiter-vpn bootstrap credential telegram-token < token.txt\n")
		fmt.Fprintf(out, "  spaiter-vpn bootstrap credential telegram-token    # then paste and press enter\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("%w: give exactly one credential name", ErrUsage)
	}
	reference := state.SecretRef(fs.Arg(0))
	if err := reference.Validate("credential name"); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	layout, err := layoutOpts.layout()
	if err != nil {
		return err
	}
	if !runningAsRoot() {
		return fmt.Errorf("storing a credential needs root: run `sudo spaiter-vpn bootstrap credential %s`", reference)
	}

	value, err := readSecretFromStdin(out)
	if err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("the credential is empty; nothing was written")
	}

	dir := layout.CredentialDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("restrict %s: %w", dir, err)
	}
	path := filepath.Join(dir, string(reference))
	// O_NOFOLLOW: a symlink planted here would otherwise redirect the write,
	// and this process is root.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	if _, err := file.WriteString(value + "\n"); err != nil {
		file.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict %s: %w", path, err)
	}
	// Reading it back through the same store apply uses is the only check that
	// proves the file apply will accept exists, rather than one that merely
	// looks right.
	if _, err := (secret.Store{Dir: dir, UID: 0}).Read(reference); err != nil {
		return fmt.Errorf("the credential was written but is not usable: %w", err)
	}
	fmt.Fprintf(out, "stored credential %s (%d bytes, mode 0600)\n", reference, len(value))
	return nil
}

// readSecretFromStdin reads one line without echoing it when stdin is a
// terminal.
func readSecretFromStdin(out io.Writer) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(out, "value (not echoed): ")
		raw, err := term.ReadPassword(fd)
		fmt.Fprintln(out)
		if err != nil {
			return "", fmt.Errorf("read the credential: %w", err)
		}
		return strings.TrimSpace(string(raw)), nil
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 16<<10))
	if err != nil {
		return "", fmt.Errorf("read the credential from stdin: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

var errNoDesiredState = errors.New("no desired state")

// loadDesired reads the document named by -f, or the stored one.
func loadDesired(layout discover.Layout, path string) (state.State, string, error) {
	if path == "" {
		path = layout.DesiredPath()
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return state.State{}, path, fmt.Errorf("%w at %s: create one with `spaiter-vpn bootstrap state -users … -o desired.json`, then pass it with -f", errNoDesiredState, path)
			}
			return state.State{}, path, err
		}
	}
	desired, err := state.Load(path)
	return desired, path, err
}

// managerOwner is who owns the transaction directories: root in production.
// A variable so a test without root can own them itself.
var managerOwner = struct{ UID, GID uint32 }{0, 0}

func newTransactionManager(layout discover.Layout) *transaction.Manager {
	targets, err := layout.TransactionTargets()
	if err != nil {
		targets = layout.ManagedFiles()
	}
	manager := &transaction.Manager{
		StateDir:       layout.BootstrapStateDir(),
		AllowedTargets: targets,
		UID:            managerOwner.UID,
		GID:            managerOwner.GID,
	}
	relayDir := ""
	if desired, err := state.Load(layout.DesiredPath()); err == nil {
		relayDir = desired.Bot.WDTTConfigDirectory
	}
	for _, delegation := range layout.BotDelegations(discover.LookupSystemUser(deploy.BotUserName), relayDir) {
		manager.Delegated = append(manager.Delegated, transaction.Delegation{Root: delegation.Root, UID: delegation.UID, GID: delegation.GID})
	}
	return manager
}

// subscriptionPortName is the -ports key for the bot's subscription server,
// the one public listener that is not a protocol.
const subscriptionPortName = "subscription"

// chooseDocumentPorts replaces the reference ports of a fresh document with
// random ones, keeps those given in assignments, and lets the operator review
// the ones they will forward: the enabled tier's protocols and the bot's
// subscription server. The other tier's ports are drawn too, so switching tier
// later does not bring the reference set back.
func chooseDocumentPorts(in *bufio.Reader, out io.Writer, desired *state.State, assignments string) error {
	fixed := map[profile.Protocol]uint16{}
	subscription, subscriptionFixed := uint16(0), false
	for _, assignment := range splitList(assignments) {
		name, portText, found := strings.Cut(assignment, "=")
		if !found {
			return fmt.Errorf("%w: -ports takes tag=port pairs, got %q", ErrUsage, assignment)
		}
		name = strings.TrimSpace(name)
		port, err := parsePort(portText)
		if err != nil {
			return fmt.Errorf("%w: -ports %s: %v", ErrUsage, assignment, err)
		}
		if name == subscriptionPortName {
			subscription, subscriptionFixed = port, true
			continue
		}
		if _, known := desired.Deployment.Ports[profile.Protocol(name)]; !known {
			return fmt.Errorf("%w: unknown protocol %q in -ports", ErrUsage, name)
		}
		fixed[profile.Protocol(name)] = port
	}

	all := make([]profile.Protocol, 0, len(desired.Deployment.Ports))
	taken := map[uint16]bool{}
	for p := range desired.Deployment.Ports {
		if port, ok := fixed[p]; ok {
			taken[port] = true
			continue
		}
		all = append(all, p)
	}
	if subscriptionFixed {
		taken[subscription] = true
	} else {
		all = append(all, profile.Protocol(subscriptionPortName))
	}
	drawn, err := profile.RandomPorts(nil, all, taken)
	if err != nil {
		return err
	}
	for p, port := range fixed {
		drawn[p] = port
	}
	if !subscriptionFixed {
		subscription = drawn[profile.Protocol(subscriptionPortName)]
		delete(drawn, profile.Protocol(subscriptionPortName))
	}

	shown := profile.Spec{Tier: desired.Deployment.Tier}.TierProtocols()
	isFixed := map[profile.Protocol]bool{}
	for p := range fixed {
		isFixed[p] = true
	}
	items := protocolPortItems(shown, drawn, isFixed)
	items = append(items, portItem{name: "bot " + subscriptionPortName, networks: "tcp", port: subscription, fixed: subscriptionFixed})
	if err := choosePorts(in, out, items); err != nil {
		return err
	}
	for _, item := range items[:len(items)-1] {
		drawn[profile.Protocol(item.name)] = item.port
	}
	desired.Deployment.Ports = drawn
	desired.Bot.SubscriptionPort = items[len(items)-1].port
	return nil
}
