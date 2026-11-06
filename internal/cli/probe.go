package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/firewall"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func runProbe(ctx context.Context, out io.Writer, args []string) error {
	fs := newFlagSet("probe", out)
	host := fs.String("host", "", "the deployment's public address (required)")
	dir := fs.String("dir", "", "deployment directory, to read the port list from its secrets")
	secretsPath := fs.String("secrets", "", "secrets file to read the port list from")
	tcpList := fs.String("tcp", "", "comma-separated TCP ports, if no secrets file is available")
	udpList := fs.String("udp", "", "comma-separated UDP ports, for the report only")
	timeout := fs.Duration("timeout", 5*time.Second, "per-port connect timeout")
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: spaiter-vpn probe -host <address> [-dir DIR | -tcp 1,2 -udp 3]\n\n")
		fmt.Fprintf(out, "Run this from ANOTHER machine. It answers the one question the server\n")
		fmt.Fprintf(out, "cannot answer about itself: whether its ports are reachable from outside.\n")
		fmt.Fprintf(out, "A cloud provider's firewall, a NAT or an ISP sit outside the host and are\n")
		fmt.Fprintf(out, "invisible from in there, so a clean `preflight` does not imply this.\n\n")
		fmt.Fprintf(out, "⚠️ TCP only. A UDP port cannot be probed this way: there is nothing to\n")
		fmt.Fprintf(out, "distinguish \"dropped\" from \"delivered and ignored\", and the AmneziaWG\n")
		fmt.Fprintf(out, "endpoints answer only a valid handshake. UDP ports are listed so they are\n")
		fmt.Fprintf(out, "not forgotten, and the only proof for them is a client that connects.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" {
		return fmt.Errorf("%w: -host is required", ErrUsage)
	}

	tcpPorts, udpPorts, err := probeTargets(*dir, *secretsPath, *tcpList, *udpList)
	if err != nil {
		return err
	}
	if len(tcpPorts)+len(udpPorts) == 0 {
		return fmt.Errorf("%w: nothing to probe; pass -dir, -secrets, or -tcp/-udp", ErrUsage)
	}

	fmt.Fprintf(out, "probing %s from this machine\n\n", *host)
	failures := 0
	for _, port := range tcpPorts {
		addr := net.JoinHostPort(*host, fmt.Sprint(port))
		dialer := net.Dialer{Timeout: *timeout}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			failures++
			fmt.Fprintf(out, "FAIL  tcp/%-6d %v\n", port, condense(err))
			continue
		}
		conn.Close()
		// A completed TCP handshake proves the path end to end: something
		// accepted on that port, so no firewall in between dropped it.
		fmt.Fprintf(out, "OK    tcp/%-6d accepted a connection\n", port)
	}
	for _, port := range udpPorts {
		fmt.Fprintf(out, "?     udp/%-6d cannot be probed from outside; see below\n", port)
	}

	fmt.Fprintf(out, "\n%d TCP ports reachable, %d not\n", len(tcpPorts)-failures, failures)
	if n := len(udpPorts); n > 0 {
		noun := "ports are"
		if n == 1 {
			noun = "port is"
		}
		fmt.Fprintf(out, "\nThe %d UDP %s unprovable this way: a dropped datagram and an ignored\n", n, noun)
		fmt.Fprintf(out, "one look identical, and the WireGuard endpoints answer only a valid\n")
		fmt.Fprintf(out, "handshake. Use a generated .conf and check `wg show` for a recent\n")
		fmt.Fprintf(out, "handshake — that is the only honest test.\n")
	}
	if failures > 0 {
		return fmt.Errorf("%d of %d TCP ports are not reachable from here", failures, len(tcpPorts))
	}
	return nil
}

// probeTargets works out what to probe, preferring the deployment's own record
// over anything typed by hand.
func probeTargets(dir, secretsPath, tcpList, udpList string) ([]uint16, []uint16, error) {
	resolved := secretsPath
	if resolved == "" && dir != "" {
		resolved = filepath.Join(dir, "secrets", "secrets.json")
	}
	if resolved != "" {
		raw, err := os.ReadFile(resolved)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", resolved, err)
		}
		var secrets profile.Secrets
		if err := json.Unmarshal(raw, &secrets); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", resolved, err)
		}
		spec, err := profile.SpecFromSecrets(secrets)
		if err != nil {
			return nil, nil, err
		}
		// The same rule set the firewall script opens, so the two cannot
		// disagree about which ports are supposed to be public.
		var tcp, udp []uint16
		for _, r := range firewall.Rules(spec) {
			if r.Network == "tcp" {
				tcp = append(tcp, r.Port)
			} else {
				udp = append(udp, r.Port)
			}
		}
		return dedupe(tcp), dedupe(udp), nil
	}

	tcp, err := parsePortList(tcpList)
	if err != nil {
		return nil, nil, fmt.Errorf("-tcp: %w", err)
	}
	udp, err := parsePortList(udpList)
	if err != nil {
		return nil, nil, fmt.Errorf("-udp: %w", err)
	}
	return tcp, udp, nil
}

func parsePortList(list string) ([]uint16, error) {
	var out []uint16
	for _, item := range splitList(list) {
		port, err := parsePort(item)
		if err != nil {
			return nil, err
		}
		out = append(out, port)
	}
	return dedupe(out), nil
}

func dedupe(ports []uint16) []uint16 {
	seen := map[uint16]struct{}{}
	var out []uint16
	for _, p := range ports {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// condense trims a dial error to the part that tells the operator what to do.
// "connection refused" means something answered and nothing is listening;
// a timeout means a firewall swallowed it. Those lead to different fixes.
func condense(err error) string {
	msg := err.Error()
	for _, marker := range []string{"connection refused", "i/o timeout", "no route to host", "network is unreachable"} {
		if strings.Contains(msg, marker) {
			switch marker {
			case "connection refused":
				return "connection refused — the path is open but nothing is listening"
			case "i/o timeout":
				return "timed out — something in between is dropping it (firewall or NAT)"
			default:
				return marker
			}
		}
	}
	return msg
}
