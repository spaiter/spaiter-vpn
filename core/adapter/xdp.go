package adapter

import (
	"net/netip"
	"time"
)

type XDPBlocker interface {
	// user is the account the blocked traffic was attributed to, empty
	// when the inbound could not name it. Carried through so the block
	// can be reported per user, not just per address. //H
	BlockIP(ip netip.Addr, duration time.Duration, user string) error
	UnblockIP(ip netip.Addr) error
	IsBlocked(ip netip.Addr) bool
	BlockedCount() int
	TrackUserIP(user string, ip netip.Addr)
	BlockUserIPs(user string, duration time.Duration) error
}

// PeerEndpointResolver maps a tunnel-internal address back to the external UDP
// endpoint of the peer it belongs to. WireGuard-style endpoints hand the router
// a source address from inside the tunnel (10.10.0.2), which is useless to an
// XDP filter bound to a physical interface — it only ever sees the peer's real
// address. Implemented by the awg endpoint. //H
type PeerEndpointResolver interface {
	PeerEndpointFor(addr netip.Addr) (netip.Addr, bool)
}

// BlockablePeerEndpoint reports whether a resolved peer endpoint is worth
// installing in the XDP filter. Note this deliberately does NOT reject private
// addresses in general: whether an address can appear on the filtered interface
// depends on which interface the filter is attached to, and a LAN client
// torrenting through a proxy inbound is a legitimate target. It only rejects
// endpoints that cannot identify a remote peer at all — a loopback endpoint
// means the "peer" is a local shim (the masque-wg / wdtt relays feed plain
// WireGuard to their endpoints over 127.0.0.1), so banning it would take out
// the relay rather than the offender. //H
func BlockablePeerEndpoint(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsValid() && !addr.IsUnspecified() && !addr.IsLoopback()
}
