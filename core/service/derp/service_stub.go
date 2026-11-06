//go:build !with_gvisor

package derp

import (
	"context"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	boxService "github.com/spaiter/spaiter-vpn/core/adapter/service"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
)

func Register(registry *boxService.Registry) {
	boxService.Register[option.DERPServiceOptions](registry, C.TypeDERP, func(ctx context.Context, logger log.ContextLogger, tag string, options option.DERPServiceOptions) (adapter.Service, error) {
		return nil, E.New("DERP service requires gVisor, rebuild with -tags with_gvisor")
	})
}
