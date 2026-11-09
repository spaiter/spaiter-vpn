package awg

import (
	"net/netip"

	"github.com/spaiter/spaiter-vpn/core/option"
)

// peerNameTable maps a tunnel address to the name of the peer that owns it.
// WireGuard has no login step, so a peer's only identity is its allowed_ips:
// the device already refuses to decrypt a packet whose inner source address
// falls outside the prefixes of the peer that sent it, which makes the source
// address a trustworthy identifier by the time the handler sees it. //H
type peerNameTable struct {
	entries []peerNameEntry
}

type peerNameEntry struct {
	prefix netip.Prefix
	name   string
}

func newPeerNameTable(peers []option.AwgPeerOptions) *peerNameTable {
	var table peerNameTable
	for _, peer := range peers {
		if peer.Name == "" {
			continue
		}
		for _, prefix := range peer.AllowedIPs {
			table.entries = append(table.entries, peerNameEntry{prefix: prefix, name: peer.Name})
		}
	}
	if len(table.entries) == 0 {
		return nil
	}
	return &table
}

// Lookup returns the name of the peer owning addr, longest prefix first so that
// a catch-all allowed_ips range cannot shadow a per-peer /32. //H
func (t *peerNameTable) Lookup(addr netip.Addr) string {
	if t == nil || !addr.IsValid() {
		return ""
	}
	addr = addr.Unmap()
	var (
		name string
		bits = -1
	)
	for _, entry := range t.entries {
		if entry.prefix.Bits() > bits && entry.prefix.Contains(addr) {
			name, bits = entry.name, entry.prefix.Bits()
		}
	}
	return name
}
