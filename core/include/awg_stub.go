//go:build !with_awg

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

func registerAwgEndpoint(registry *endpoint.Registry) {
	endpoint.Register(registry, C.TypeAwg, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AwgEndpointOptions) (adapter.Endpoint, error) {
		return nil, E.New(`Awg is not included in this build, rebuild with -tags with_awg`)
	})
}
