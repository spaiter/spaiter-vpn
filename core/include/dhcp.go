//go:build with_dhcp

package include

import (
	"github.com/spaiter/spaiter-vpn/core/dns"
	"github.com/spaiter/spaiter-vpn/core/dns/transport/dhcp"
)

func registerDHCPTransport(registry *dns.TransportRegistry) {
	dhcp.RegisterTransport(registry)
}
