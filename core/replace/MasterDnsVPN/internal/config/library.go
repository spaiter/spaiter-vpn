// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package config: entry points for programs that embed the client as a library
// (hiddify-sing-box). They build a ClientConfig in code, with the resolvers given
// as strings instead of read from client_resolvers.txt.
// ==============================================================================

package config

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// DefaultClientConfig returns the client configuration with every setting at its default,
// the same values the sample client_config.toml documents.
func DefaultClientConfig() ClientConfig {
	return defaultClientConfig()
}

// ParseResolverEntries reads resolver entries in the client_resolvers.txt formats:
// "8.8.8.8", "1.1.1.1:5353", "192.168.1.0/30", "192.168.1.0/30:5353", "[2001:db8::1]:53".
// Empty entries and comments are skipped, an invalid entry is an error. Unlike the resolver
// file, which keeps one port per IP, a library caller may give one IP with several ports (local
// test resolvers, a server answering on more than one port): each IP:port is its own resolver.
func ParseResolverEntries(entries []string) ([]ResolverAddress, map[string]int, error) {
	endpoints := make([]ResolverAddress, 0, len(entries))
	resolverMap := make(map[string]int, len(entries))
	seen := make(map[string]struct{}, len(entries))

	for _, entry := range entries {
		line := strings.TrimSpace(entry)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		target, port, err := parseResolverEntry(line)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid resolver %q: %w", line, err)
		}

		if !target.isPrefix {
			addEndpoint(&endpoints, resolverMap, seen, target.addr.String(), port)
			continue
		}

		usableHosts, ok := usableHostCount(target.prefix)
		if !ok || usableHosts > maxResolverHosts {
			return nil, nil, fmt.Errorf("invalid resolver %q: the range has more than %d addresses", line, maxResolverHosts)
		}

		first, last := hostRange(target.prefix.Masked())
		if !first.IsValid() || !last.IsValid() {
			continue
		}
		for addr := first; ; addr = addr.Next() {
			addEndpoint(&endpoints, resolverMap, seen, addr.String(), port)
			if addr == last {
				break
			}
		}
	}

	if len(endpoints) == 0 {
		return nil, nil, fmt.Errorf("no valid resolvers given")
	}

	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].IP == endpoints[j].IP {
			return endpoints[i].Port < endpoints[j].Port
		}
		return endpoints[i].IP < endpoints[j].IP
	})

	return endpoints, resolverMap, nil
}

// addEndpoint adds ip:port once. resolverMap keeps the first port of each IP, as the file loader does.
func addEndpoint(endpoints *[]ResolverAddress, resolverMap map[string]int, seen map[string]struct{}, ip string, port int) {
	key := net.JoinHostPort(ip, strconv.Itoa(port))
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	if _, exists := resolverMap[ip]; !exists {
		resolverMap[ip] = port
	}
	*endpoints = append(*endpoints, ResolverAddress{IP: ip, Port: port})
}

// FinalizeClientConfig validates a configuration built in code and fills its derived values,
// exactly as loading a configuration file does. When cfg.Resolvers is set (see
// ParseResolverEntries) the resolver file is not read.
func FinalizeClientConfig(cfg ClientConfig) (ClientConfig, error) {
	return finalizeClientConfig(cfg)
}

// MarkExplicitWorkers records that RX_TX_Workers or TunnelProcessWorkers were set on purpose, so
// FinalizeClientConfig keeps them instead of choosing them from the machine. A configuration file
// records this by itself; a configuration built in code calls this before FinalizeClientConfig.
func (c *ClientConfig) MarkExplicitWorkers(rxTxWorkers bool, processWorkers bool) {
	c.explicitRX_TX_Workers = rxTxWorkers
	c.explicitTunnelProcessWorkers = processWorkers
}
