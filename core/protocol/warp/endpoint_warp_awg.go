//go:build with_awg

package warp

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
	"github.com/spaiter/spaiter-vpn/core/protocol/awg"
)

func createWARPAwgEndpoint(
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
	return awg.NewEndpoint(ctx, router, logger, tag, option.AwgEndpointOptions{
		UseIntegratedTun: options.System,
		PrivateKey:       config.PrivateKey,
		Address: badoption.Listable[netip.Prefix]{
			netip.MustParsePrefix(config.Interface.Addresses.V4 + "/32"),
			netip.MustParsePrefix(config.Interface.Addresses.V6 + "/128"),
		},
		MTU:        options.MTU,
		ListenPort: options.ListenPort,
		Awg:        *options.AWG,
		Peers: []option.AwgPeerOptions{
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
		DialerOptions: options.DialerOptions,
	})
}
