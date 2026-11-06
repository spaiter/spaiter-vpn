//go:build with_tailscale

package include

import (
	"github.com/spaiter/spaiter-vpn/core/adapter/certificate"
	"github.com/spaiter/spaiter-vpn/core/adapter/endpoint"
	"github.com/spaiter/spaiter-vpn/core/adapter/service"
	"github.com/spaiter/spaiter-vpn/core/dns"
	"github.com/spaiter/spaiter-vpn/core/protocol/tailscale"
	"github.com/spaiter/spaiter-vpn/core/service/derp"
)

func registerTailscaleEndpoint(registry *endpoint.Registry) {
	tailscale.RegisterEndpoint(registry)
}

func registerTailscaleTransport(registry *dns.TransportRegistry) {
	tailscale.RegistryTransport(registry)
}

func registerTailscaleCertificateProvider(registry *certificate.Registry) {
	tailscale.RegisterCertificateProvider(registry)
}

func registerDERPService(registry *service.Registry) {
	derp.Register(registry)
}
