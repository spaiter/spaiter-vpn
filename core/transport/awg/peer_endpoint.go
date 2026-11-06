package awg

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Resolving a tunnel address to the peer's external endpoint means asking the
// device for its full UAPI dump, so the result is cached: BitTorrent rejects
// arrive in bursts and the peer table changes only on handshake or roaming. //H
const peerEndpointCacheTTL = 3 * time.Second

type peerRoute struct {
	prefix   netip.Prefix
	endpoint netip.Addr
}

type peerEndpointCache struct {
	mu      sync.Mutex
	expires time.Time
	routes  []peerRoute
}

// PeerEndpointFor implements adapter.PeerEndpointResolver: it maps an address
// from inside the tunnel to the external address of the peer that owns it, by
// matching against the peers' allowed_ips. //H
func (d *Device) PeerEndpointFor(addr netip.Addr) (netip.Addr, bool) {
	if !addr.IsValid() || d.awgDevice == nil {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()

	d.peerEndpoints.mu.Lock()
	defer d.peerEndpoints.mu.Unlock()

	if time.Now().After(d.peerEndpoints.expires) {
		dump, err := d.awgDevice.IpcGet()
		if err != nil {
			return netip.Addr{}, false
		}
		d.peerEndpoints.routes = parsePeerRoutes(dump)
		d.peerEndpoints.expires = time.Now().Add(peerEndpointCacheTTL)
	}

	// Longest prefix wins, matching how WireGuard itself resolves allowed_ips.
	var (
		best      netip.Addr
		bestBits  = -1
		bestFound bool
	)
	for _, route := range d.peerEndpoints.routes {
		if route.prefix.Bits() > bestBits && route.prefix.Contains(addr) {
			best, bestBits, bestFound = route.endpoint, route.prefix.Bits(), true
		}
	}
	return best, bestFound
}

// parsePeerRoutes turns a UAPI dump into allowed_ip → endpoint pairs. The dump
// is a flat key=value list where `public_key` opens a peer section and the
// `endpoint` / `allowed_ip` lines that follow belong to it; a peer that has
// never completed a handshake has no `endpoint` line and is skipped. //H
func parsePeerRoutes(dump string) []peerRoute {
	var (
		routes  []peerRoute
		current netip.Addr
	)
	for _, line := range strings.Split(dump, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			current = netip.Addr{}
		case "endpoint":
			if addrPort, err := netip.ParseAddrPort(value); err == nil {
				current = addrPort.Addr().Unmap()
			}
		case "allowed_ip":
			if !current.IsValid() {
				continue
			}
			if prefix, err := netip.ParsePrefix(value); err == nil {
				routes = append(routes, peerRoute{prefix: prefix, endpoint: current})
			}
		}
	}
	return routes
}
