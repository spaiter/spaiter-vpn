package provision

import (
	"encoding/json"
	"fmt"
	"net/netip"
)

// NextIP picks a free address in the endpoint's subnet.
//
// subnet is the endpoint's own address with a prefix, as the core reports it
// ("10.10.0.1/24"), so it names both the range and the address the server
// answers on. used holds the allowed_ips of the peers already there.
//
// Handing out an address twice is the failure this guards: two tunnels with the
// same source address, and the core routing both users' return traffic to
// whichever peer handshook last. So an entry that cannot be parsed stops the
// allocation instead of being skipped -- it may well be the peer that already
// holds the address this would return.
func NextIP(subnet string, used []string) (string, error) {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", fmt.Errorf("provision: endpoint address %q: %w", subnet, err)
	}
	network := prefix.Masked()

	taken := map[netip.Addr]bool{
		// The server's own address, and the first host in case the endpoint is
		// configured on some other address but something still answers on .1.
		prefix.Addr():         true,
		network.Addr().Next(): true,
		network.Addr():        true,
	}
	for _, entry := range used {
		addr, err := parseHostAddr(entry)
		if err != nil {
			return "", err
		}
		taken[addr] = true
	}

	for addr := network.Addr(); prefix.Contains(addr); addr = addr.Next() {
		if taken[addr] {
			continue
		}
		// The broadcast address of an IPv4 subnet is not usable, and the last
		// address of an IPv6 one is conventionally left alone too.
		if isLastInPrefix(addr, network) {
			break
		}
		return addr.String(), nil
	}
	return "", fmt.Errorf("provision: no free address left in %s (%d taken)", subnet, len(taken))
}

// parseHostAddr reads an address that may or may not carry a prefix length,
// which is how both an allowed_ips entry and a bare address arrive.
func parseHostAddr(entry string) (netip.Addr, error) {
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		return prefix.Addr(), nil
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("provision: peer address %q is unreadable, "+
			"refusing to allocate past it: %w", entry, err)
	}
	return addr, nil
}

// isLastInPrefix reports whether addr is the final address of the subnet.
func isLastInPrefix(addr netip.Addr, network netip.Prefix) bool {
	if network.Bits() >= addr.BitLen()-1 {
		// A /31 or /32 has no spare address to reserve; whatever fits is usable.
		return false
	}
	return !network.Contains(addr.Next())
}

// AddrList is an allowed_ips value, which the core's schema allows as either a
// single string or a list.
//
// Both forms occur: this deployment writes one string per peer, while a config
// written by hand or by the installer uses a list. A reader that handles only
// one form sees no addresses in the other and goes on to hand out an address
// that is already in use, which is why this is a type and not an inline cast.
type AddrList []string

// UnmarshalJSON accepts a string, a list of strings, or null.
func (a *AddrList) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		if one == "" {
			*a = nil
		} else {
			*a = AddrList{one}
		}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("provision: allowed_ips is neither a string nor a list: %s", data)
	}
	*a = many
	return nil
}
