//go:build !with_wireguard

package include

import (
	"context"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/adapter/endpoint"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
)

func registerWireGuardEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.WireGuardEndpointOptions](registry, C.TypeWireGuard, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WireGuardEndpointOptions) (adapter.Endpoint, error) {
		return nil, E.New(`WireGuard is not included in this build, rebuild with -tags with_wireguard`)
	})
}
