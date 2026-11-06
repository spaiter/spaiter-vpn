// Package cli implements the spaiter-vpn command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// Version is overridden at build time with -ldflags.
var Version = "dev"

// ErrUsage asks the caller to print usage and exit non-zero.
var ErrUsage = errors.New("usage")

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, out io.Writer, args []string) error
}

func commands() []command {
	return []command{
		{"preflight", "check the host before deploying anything", runPreflight},
		{"init", "generate keys, config.json and the compose project", runInit},
		{"bootstrap", "install on a fresh host: plan, confirm, apply, verify", runBootstrap},
		{"check", "run sing-box check against an existing config", runCheck},
		{"up", "start the compose project", runUp},
		{"clients", "render client configs, share URLs and WireGuard files", runClients},
		{"logs", "read the core's log file: detections, levels, a summary", runLogs},
		{"metrics", "serve the traffic accounting in Prometheus format", runMetrics},
		{"stats", "per-user traffic from the core's accounting database", runStats},
		{"probe", "from another machine: are the ports reachable from outside", runProbe},
		{"selftest", "prove BitTorrent detection works on the running server", runSelftest},
		{"control", "the local control plane: a root daemon for typed operations", runControl},
		{"web", "the browser front end of the control daemon", runWeb},
		{"ddns", "keep the server's DNS records on its changing public address", runDDNS},
		{"backup", "write an encrypted backup of the deployment, to keep off this provider", runBackup},
		{"restore", "bring a backup up on a new server with the same keys and users", runRestore},
		{"verify", "send a real request through every node of a user's subscription", runVerify},
		{"bot", "run the provisioning bot: Telegram, /sub and the background loops", runBot},
		{"vk", "sign in to the VK account whose calls carry the WG-over-VK pool", runVK},
		{"version", "print the version", runVersion},
	}
}

// Run dispatches a command. It returns ErrUsage when the arguments make no
// sense, so main can separate "the operator mistyped" from "the operation
// failed".
func Run(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 {
		return ErrUsage
	}
	for _, cmd := range commands() {
		if cmd.name == args[0] {
			err := cmd.run(ctx, out, args[1:])
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
	}
	return fmt.Errorf("%w: unknown command %q", ErrUsage, args[0])
}

// Usage writes the command list.
func Usage(out io.Writer) {
	fmt.Fprintf(out, "spaiter-vpn %s — deploy and verify a sing-box VPN server\n\n", Version)
	fmt.Fprintf(out, "usage: spaiter-vpn <command> [flags]\n\n")
	for _, cmd := range commands() {
		fmt.Fprintf(out, "  %-11s %s\n", cmd.name, cmd.summary)
	}
	fmt.Fprintf(out, "\nRun `spaiter-vpn <command> -h` for the flags of a command.\n")
	fmt.Fprintf(out, "On a fresh server, start with `spaiter-vpn bootstrap -h`.\n")
}

func runVersion(_ context.Context, out io.Writer, _ []string) error {
	fmt.Fprintln(out, Version)
	return nil
}

// newFlagSet builds a flag set that reports errors through flag.ErrHelp rather
// than exiting the process, so Run keeps control of the exit code.
func newFlagSet(name string, out io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("spaiter-vpn "+name, flag.ContinueOnError)
	fs.SetOutput(out)
	return fs
}

// warn writes to stderr regardless of where normal output goes, so a warning
// is not swallowed by a redirect.
func warn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "warning: "+format+"\n", args...)
}
