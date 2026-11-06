package warp

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
	wg "github.com/spaiter/spaiter-vpn/core/protocol/wireguard"
)

func createWARPWireGuardEndpoint(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options option.WARPEndpointOptions,
	config *C.WARPConfig,
	peerAddr string,
	peerPort uint16,
	peerPublicKey string,
) (adapter.Endpoint, error) {
	return wg.NewEndpoint(ctx, router, logger, tag, option.WireGuardEndpointOptions{
		System:        options.System,
		Name:          options.Name,
		ListenPort:    options.ListenPort,
		UDPTimeout:    options.UDPTimeout,
		Workers:       options.Workers,
		Noise:         options.Noise,
		AWG:           options.AWG,
		DialerOptions: options.DialerOptions,
		Address: badoption.Listable[netip.Prefix]{
			netip.MustParsePrefix(config.Interface.Addresses.V4 + "/32"),
			netip.MustParsePrefix(config.Interface.Addresses.V6 + "/128"),
		},
		PrivateKey: config.PrivateKey,
		Peers: []option.WireGuardPeer{
			{
				Address:   peerAddr,
				Port:      peerPort,
				PublicKey: peerPublicKey,
				AllowedIPs: badoption.Listable[netip.Prefix]{
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				},
			},
		},
		MTU: options.MTU,
	})
}
