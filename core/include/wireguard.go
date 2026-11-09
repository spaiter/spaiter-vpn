//go:build with_wireguard

package include

import (
	"github.com/spaiter/spaiter-vpn/core/adapter/endpoint"
	"github.com/spaiter/spaiter-vpn/core/protocol/wireguard"
)

func registerWireGuardEndpoint(registry *endpoint.Registry) {
	wireguard.RegisterEndpoint(registry)
}
