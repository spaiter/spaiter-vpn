//go:build with_quic

package include

import (
	"github.com/spaiter/spaiter-vpn/core/adapter/inbound"
	"github.com/spaiter/spaiter-vpn/core/adapter/outbound"
	"github.com/spaiter/spaiter-vpn/core/adapter/service"
	"github.com/spaiter/spaiter-vpn/core/dns"
	"github.com/spaiter/spaiter-vpn/core/dns/transport/quic"
	"github.com/spaiter/spaiter-vpn/core/protocol/hysteria"
	"github.com/spaiter/spaiter-vpn/core/protocol/hysteria2"
	_ "github.com/spaiter/spaiter-vpn/core/protocol/naive/quic"
	"github.com/spaiter/spaiter-vpn/core/protocol/tuic"
	_ "github.com/spaiter/spaiter-vpn/core/transport/v2rayquic"
)

func registerQUICInbounds(registry *inbound.Registry) {
	hysteria.RegisterInbound(registry)
	tuic.RegisterInbound(registry)
	hysteria2.RegisterInbound(registry)
}

func registerQUICOutbounds(registry *outbound.Registry) {
	hysteria.RegisterOutbound(registry)
	tuic.RegisterOutbound(registry)
	hysteria2.RegisterOutbound(registry)
}

func registerQUICTransports(registry *dns.TransportRegistry) {
	quic.RegisterTransport(registry)
	quic.RegisterHTTP3Transport(registry)
}

func registerQUICServices(registry *service.Registry) {
	hysteria2.RegisterRealmService(registry)
}
