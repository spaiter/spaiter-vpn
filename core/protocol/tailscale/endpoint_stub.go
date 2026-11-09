//go:build !with_gvisor

package tailscale

import (
	"context"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/adapter/endpoint"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/dns"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.TailscaleEndpointOptions](registry, C.TypeTailscale, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TailscaleEndpointOptions) (adapter.Endpoint, error) {
		return nil, E.New("Tailscale endpoint requires gVisor, rebuild with -tags with_gvisor")
	})
}

func RegistryTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.TailscaleDNSServerOptions](registry, C.DNSTypeTailscale, func(ctx context.Context, logger log.ContextLogger, tag string, options option.TailscaleDNSServerOptions) (adapter.DNSTransport, error) {
		return nil, E.New("Tailscale DNS transport requires gVisor, rebuild with -tags with_gvisor")
	})
}
