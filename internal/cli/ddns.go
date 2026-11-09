package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/ddns"
)

// runDDNS is `spaiter-vpn ddns run`, what the bootstrap-managed unit runs.
func runDDNS(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 || args[0] != "run" {
		fmt.Fprintf(out, "usage: spaiter-vpn ddns run -provider NAME -host HOST -token-file FILE [flags]\n\n")
		fmt.Fprintf(out, "Keeps DNS records on this server's public address, for a server whose\n")
		fmt.Fprintf(out, "address changes. Normally run by the unit bootstrap installs when the\n")
		fmt.Fprintf(out, "desired state has a ddns section; providers: %s.\n", strings.Join(ddns.Providers, ", "))
		return ErrUsage
	}
	fs := newFlagSet("ddns run", out)
	provider := fs.String("provider", "", "DNS provider: "+strings.Join(ddns.Providers, ", "))
	hosts := fs.String("host", "", "comma-separated names kept on this server (A, and AAAA with -ipv6)")
	ipv4Hosts := fs.String("ipv4-host", "", "comma-separated names that get an A record only")
	tokenFile := fs.String("token-file", "", "file holding the API token (dyndns2: the password)")
	username := fs.String("username", "", "dyndns2 username")
	server := fs.String("server", "", "dyndns2 update service, e.g. https://dynupdate.no-ip.com")
	ipv6 := fs.Bool("ipv6", false, "also keep AAAA records")
	interval := fs.Duration("interval", 5*time.Minute, "how often the address is checked")
	statusPath := fs.String("status", "", "file the result of every round is written to")
	once := fs.Bool("once", false, "run one round and exit, non-zero if it failed")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *tokenFile == "" {
		return fmt.Errorf("%w: -token-file is required; the token never goes on the command line", ErrUsage)
	}
	token, err := os.ReadFile(*tokenFile)
	if err != nil {
		return fmt.Errorf("read the token: %w", err)
	}
	p, err := ddns.NewProvider(ddns.Options{Name: *provider, Token: strings.TrimSpace(string(token)), Username: *username, Server: *server})
	if err != nil {
		return err
	}
	updater, err := ddns.New(ddns.Config{
		Provider: p, Hosts: splitList(*hosts), IPv4Hosts: splitList(*ipv4Hosts), IPv6: *ipv6,
		Interval: *interval, StatusPath: *statusPath, Log: out,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if *once {
		if status := updater.Once(ctx); !status.OK {
			return fmt.Errorf("%s", status.Error)
		}
		return nil
	}
	fmt.Fprintf(out, "ddns: keeping %s through %s, every %s\n", strings.Join(append(splitList(*hosts), splitList(*ipv4Hosts)...), ", "), *provider, *interval)
	updater.Run(ctx)
	return nil
}
