package include

import (
	"context"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spaiter/spaiter-vpn/core"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/adapter/certificate"
	"github.com/spaiter/spaiter-vpn/core/adapter/endpoint"
	"github.com/spaiter/spaiter-vpn/core/adapter/inbound"
	"github.com/spaiter/spaiter-vpn/core/adapter/outbound"
	"github.com/spaiter/spaiter-vpn/core/adapter/service"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/dns"
	"github.com/spaiter/spaiter-vpn/core/dns/transport"
	"github.com/spaiter/spaiter-vpn/core/dns/transport/fakeip"
	"github.com/spaiter/spaiter-vpn/core/dns/transport/hosts"
	"github.com/spaiter/spaiter-vpn/core/dns/transport/local"
	"github.com/spaiter/spaiter-vpn/core/dns/transport/mdns"
	"github.com/spaiter/spaiter-vpn/core/dns/transport/multi"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
	"github.com/spaiter/spaiter-vpn/core/protocol/anytls"
	"github.com/spaiter/spaiter-vpn/core/protocol/block"
	"github.com/spaiter/spaiter-vpn/core/protocol/bridge"
	"github.com/spaiter/spaiter-vpn/core/protocol/direct"
	"github.com/spaiter/spaiter-vpn/core/protocol/group"
	"github.com/spaiter/spaiter-vpn/core/protocol/group/balancer"
	"github.com/spaiter/spaiter-vpn/core/protocol/hiddify/gooserelay"
	"github.com/spaiter/spaiter-vpn/core/protocol/hiddify/hinvalid"
	"github.com/spaiter/spaiter-vpn/core/protocol/hiddify/xray"
	"github.com/spaiter/spaiter-vpn/core/protocol/http"
	"github.com/spaiter/spaiter-vpn/core/protocol/masquewg" //H
	"github.com/spaiter/spaiter-vpn/core/protocol/mieru"
	"github.com/spaiter/spaiter-vpn/core/protocol/mixed"
	"github.com/spaiter/spaiter-vpn/core/protocol/mtproto"
	"github.com/spaiter/spaiter-vpn/core/protocol/naive"
	"github.com/spaiter/spaiter-vpn/core/protocol/redirect"
	"github.com/spaiter/spaiter-vpn/core/protocol/shadowsocks"
	"github.com/spaiter/spaiter-vpn/core/protocol/shadowtls"
	snellprotocol "github.com/spaiter/spaiter-vpn/core/protocol/snell"
	"github.com/spaiter/spaiter-vpn/core/protocol/socks"
	"github.com/spaiter/spaiter-vpn/core/protocol/ssh"
	"github.com/spaiter/spaiter-vpn/core/protocol/tor"
	"github.com/spaiter/spaiter-vpn/core/protocol/trojan"
	"github.com/spaiter/spaiter-vpn/core/protocol/tun"
	"github.com/spaiter/spaiter-vpn/core/protocol/tunnel"
	"github.com/spaiter/spaiter-vpn/core/protocol/vless"
	"github.com/spaiter/spaiter-vpn/core/protocol/vmess"
	legacyWireguard "github.com/spaiter/spaiter-vpn/core/protocol/wireguard"
	"github.com/spaiter/spaiter-vpn/core/service/api"
	originca "github.com/spaiter/spaiter-vpn/core/service/origin_ca"
	"github.com/spaiter/spaiter-vpn/core/service/resolved"
	"github.com/spaiter/spaiter-vpn/core/service/ssmapi"
)

func Context(ctx context.Context) context.Context {
	return box.Context(ctx, InboundRegistry(), OutboundRegistry(), EndpointRegistry(), DNSTransportRegistry(), ServiceRegistry(), CertificateProviderRegistry())
}

func InboundRegistry() *inbound.Registry {
	registry := inbound.NewRegistry()

	tun.RegisterInbound(registry)
	redirect.RegisterRedirect(registry)
	redirect.RegisterTProxy(registry)
	direct.RegisterInbound(registry)

	socks.RegisterInbound(registry)
	http.RegisterInbound(registry)
	mixed.RegisterInbound(registry)

	shadowsocks.RegisterInbound(registry)
	snellprotocol.RegisterInbound(registry)
	vmess.RegisterInbound(registry)
	trojan.RegisterInbound(registry)
	naive.RegisterInbound(registry)
	mtproto.RegisterInbound(registry)  //H
	masquewg.RegisterInbound(registry) //H
	shadowtls.RegisterInbound(registry)
	vless.RegisterInbound(registry)
	anytls.RegisterInbound(registry)
	mieru.RegisterInbound(registry)
	ssh.RegisterInbound(registry)

	registerQUICInbounds(registry)
	registerCloudflaredInbound(registry)
	registerStubForRemovedInbounds(registry)

	return registry
}

func OutboundRegistry() *outbound.Registry {
	registry := outbound.NewRegistry()

	direct.RegisterOutbound(registry)
	bridge.RegisterOutbound(registry)

	block.RegisterOutbound(registry)

	group.RegisterSelector(registry)
	group.RegisterURLTest(registry)

	socks.RegisterOutbound(registry)
	http.RegisterOutbound(registry)
	shadowsocks.RegisterOutbound(registry)
	snellprotocol.RegisterOutbound(registry)
	vmess.RegisterOutbound(registry)
	trojan.RegisterOutbound(registry)
	registerNaiveOutbound(registry)
	tor.RegisterOutbound(registry)
	ssh.RegisterOutbound(registry)
	shadowtls.RegisterOutbound(registry)
	vless.RegisterOutbound(registry)
	anytls.RegisterOutbound(registry)
	masquewg.RegisterOutbound(registry) //H
	mieru.RegisterOutbound(registry)
	hinvalid.RegisterOutbound(registry)
	xray.RegisterOutbound(registry)
	registerDNSTTOutbound(registry)
	gooserelay.RegisterOutbound(registry)
	balancer.RegisterLoadBalance(registry)
	registerMASQUEOutbound(registry)
	legacyWireguard.RegisterOutbound(registry) //H

	registerQUICOutbounds(registry)
	registerStubForRemovedOutbounds(registry)

	return registry
}

func EndpointRegistry() *endpoint.Registry {
	registry := endpoint.NewRegistry()

	registerWireGuardEndpoint(registry)
	registerTailscaleEndpoint(registry)
	tunnel.RegisterServerEndpoint(registry)
	tunnel.RegisterClientEndpoint(registry)
	registerWarpEndpoint(registry)
	registerAwgEndpoint(registry)

	return registry
}

func DNSTransportRegistry() *dns.TransportRegistry {
	registry := dns.NewTransportRegistry()

	transport.RegisterTCP(registry)
	transport.RegisterUDP(registry)
	transport.RegisterTLS(registry)
	transport.RegisterHTTPS(registry)
	hosts.RegisterTransport(registry)
	local.RegisterTransport(registry)
	mdns.RegisterTransport(registry)
	fakeip.RegisterTransport(registry)
	resolved.RegisterTransport(registry)
	transport.RegisterSDNS(registry)
	multi.RegisterTransport(registry) //H

	registerQUICTransports(registry)
	registerDHCPTransport(registry)
	registerTailscaleTransport(registry)

	return registry
}

func ServiceRegistry() *service.Registry {
	registry := service.NewRegistry()

	api.RegisterService(registry)
	resolved.RegisterService(registry)
	ssmapi.RegisterService(registry)
	registerSmartDNSPoolService(registry) //H

	registerQUICServices(registry)
	registerDERPService(registry)
	registerCCMService(registry)
	registerOCMService(registry)
	registerOOMKillerService(registry)
	registerUSBIPServices(registry)
	registerXDPBlockerService(registry) //H

	return registry
}

func CertificateProviderRegistry() *certificate.Registry {
	registry := certificate.NewRegistry()

	registerACMECertificateProvider(registry)
	registerTailscaleCertificateProvider(registry)
	originca.RegisterCertificateProvider(registry)

	return registry
}

func registerStubForRemovedInbounds(registry *inbound.Registry) {
	inbound.Register[option.ShadowsocksInboundOptions](registry, C.TypeShadowsocksR, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksInboundOptions) (adapter.Inbound, error) {
		return nil, E.New("ShadowsocksR is deprecated and removed in sing-box 1.6.0")
	})
}

func registerStubForRemovedOutbounds(registry *outbound.Registry) {
	outbound.Register[option.ShadowsocksROutboundOptions](registry, C.TypeShadowsocksR, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksROutboundOptions) (adapter.Outbound, error) {
		return nil, E.New("ShadowsocksR is deprecated and removed in sing-box 1.6.0")
	})
	outbound.Register[option.StubOptions](registry, C.TypeWireGuard, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.StubOptions) (adapter.Outbound, error) {
		return nil, E.New("WireGuard outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use WireGuard endpoint instead")
	})
}
