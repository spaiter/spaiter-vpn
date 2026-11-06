//go:build with_wireguard

package include

import (
	"github.com/spaiter/spaiter-vpn/core/adapter/endpoint"
	"github.com/spaiter/spaiter-vpn/core/protocol/warp"
)

func registerWarpEndpoint(registry *endpoint.Registry) {
	warp.RegisterWARPEndpoint(registry)
}
