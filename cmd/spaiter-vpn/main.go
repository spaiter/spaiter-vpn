// Command spaiter-vpn generates, deploys and verifies a sing-box VPN server.
//
// A single static binary rather than a shell installer, for one specific
// reason: the config generator links the fork's own option package, so there is
// one schema instead of a template that drifts from it. Go also supplies
// x25519, UUIDs and secure random numbers from the standard library, so a bare
// VPS needs neither Python nor jq.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spaiter/spaiter-vpn/internal/cli"
	"github.com/spaiter/spaiter-vpn/internal/vk"
)

func main() {
	// Cancel on SIGINT/SIGTERM so a long-running selftest tears its test
	// endpoint and interface down instead of leaving them behind.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Stdout, os.Stderr, os.Args[1:])
	stop()
	os.Exit(code)
}

// run is main without the process: it returns the exit status instead of
// exiting, so the mapping from errors to statuses can be tested.
func run(ctx context.Context, stdout, stderr io.Writer, args []string) int {
	err := cli.Run(ctx, stdout, args)
	if err == nil {
		return 0
	}
	if errors.Is(err, cli.ErrUsage) {
		// ErrUsage is wrapped with %w, so its own text leads the message.
		// Strip it rather than printing "usage: -users is required".
		msg := strings.TrimPrefix(strings.TrimPrefix(err.Error(), cli.ErrUsage.Error()), ": ")
		if msg != "" {
			fmt.Fprintf(stderr, "%s\n\n", msg)
		}
		cli.Usage(stderr)
		return 2
	}
	fmt.Fprintf(stderr, "error: %v\n", err)
	// A dead VK access token is its own exit code (3), so a wrapper around
	// `vk mint` can tell "a human must sign in again" from an ordinary,
	// retryable failure (1).
	if errors.Is(err, vk.ErrAccessTokenExpired) {
		return 3
	}
	return 1
}
