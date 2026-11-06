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
	defer stop()

	err := cli.Run(ctx, os.Stdout, os.Args[1:])
	if err == nil {
		return
	}
	if errors.Is(err, cli.ErrUsage) {
		// ErrUsage is wrapped with %w, so its own text leads the message.
		// Strip it rather than printing "usage: -users is required".
		msg := strings.TrimPrefix(strings.TrimPrefix(err.Error(), cli.ErrUsage.Error()), ": ")
		if msg != "" {
			fmt.Fprintf(os.Stderr, "%s\n\n", msg)
		}
		cli.Usage(os.Stderr)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	// A dead VK access token is its own exit code (3), so a wrapper around
	// `vk mint` can tell "a human must sign in again" from an ordinary,
	// retryable failure (1).
	if errors.Is(err, vk.ErrAccessTokenExpired) {
		os.Exit(3)
	}
	os.Exit(1)
}
