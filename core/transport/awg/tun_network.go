package awg

import (
	"context"
	"net"
	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/sagernet/sing/common/metadata"
	C "github.com/spaiter/spaiter-vpn/core/constant"
)

type networkTun struct {
	tun.Device
	conn *netstack.Net
}

func newNetworkTun(address []netip.Prefix, mtu uint32) (tunAdapter, error) {
	var localAddresses []netip.Addr
	for _, prefix := range address {
		localAddresses = append(localAddresses, prefix.Addr())
	}

	tun, conn, err := netstack.CreateNetTUN(localAddresses, []netip.Addr{}, int(mtu))
	if err != nil {
		return nil, err
	}

	return &networkTun{
		Device: tun,
		conn:   conn,
	}, nil
}

func (t *networkTun) Start() error {
	return nil
}

func (t *networkTun) DialContext(ctx context.Context, network string, destination metadata.Socksaddr) (net.Conn, error) {
	// the netstack dial has no timeout of its own: a peer that never answers the SYN
	// would hold the caller (and its goroutine) forever
	ctx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	return t.conn.DialContext(ctx, network, destination.String())
}

func (t *networkTun) ListenPacket(ctx context.Context, destination metadata.Socksaddr) (net.PacketConn, error) {
	return t.conn.DialUDPAddrPort(netip.AddrPort{}, destination.AddrPort())
}
