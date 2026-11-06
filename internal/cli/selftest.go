package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/spaiter/spaiter-vpn/internal/selftest"
)

func runSelftest(ctx context.Context, out io.Writer, args []string) error {
	opts := selftest.DefaultOptions()

	fs := newFlagSet("selftest", out)
	fs.StringVar(&opts.ConfigPath, "config", opts.ConfigPath, "the running instance's config.json on the host")
	fs.StringVar(&opts.LogPath, "log", "", "sing-box log file (default: beside the config)")
	fs.StringVar(&opts.Controller, "clash-api", "", "clash API address (default: from the config)")
	fs.StringVar(&opts.Secret, "clash-secret", "", "clash API secret (default: from the config)")
	fs.StringVar(&opts.Tag, "tag", opts.Tag, "tag of the throwaway test endpoint")
	fs.StringVar(&opts.Interface, "interface", opts.Interface, "name of the throwaway WireGuard interface")
	port := fs.Uint("port", uint(opts.Port), "UDP port for the throwaway endpoint")
	subnet := fs.String("subnet", opts.Subnet.String(), "private subnet for the throwaway endpoint")
	fs.IntVar(&opts.MTU, "mtu", opts.MTU, "MTU of the throwaway tunnel")
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn selftest [flags]\n\n")
		fmt.Fprintf(out, "Proves against the running server that BitTorrent traffic is detected and\n")
		fmt.Fprintf(out, "rejected. Creates a throwaway WireGuard endpoint on a free port with its own\n")
		fmt.Fprintf(out, "subnet, sends one benign datagram and three BitTorrent ones to the endpoint's\n")
		fmt.Fprintf(out, "own tunnel address, reads the result from the log file, then removes\n")
		fmt.Fprintf(out, "everything and verifies it is gone.\n\n")
		fmt.Fprintf(out, "Nothing leaves the host: no public swarm, no third party. Needs root, for the\n")
		fmt.Fprintf(out, "WireGuard interface and to read the root-owned config.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	fs.Visit(func(flag *flag.Flag) {
		if flag.Name == "subnet" {
			opts.AutoSubnet = false
		}
	})

	if *port == 0 || *port > 65535 {
		return fmt.Errorf("%w: -port %d is not a port", ErrUsage, *port)
	}
	opts.Port = uint16(*port)

	parsed, err := netip.ParsePrefix(*subnet)
	if err != nil {
		return fmt.Errorf("%w: -subnet %q: %v", ErrUsage, *subnet, err)
	}
	opts.Subnet = parsed

	if os.Geteuid() != 0 {
		warn("not running as root: creating the test interface and reading the live config both need it")
	}

	result, err := selftest.Run(ctx, out, opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "\nPASS — %d detections, %d reject actions\n", len(result.Detections), len(result.Rejections))
	return nil
}
