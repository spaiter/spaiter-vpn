//go:build !with_masque

package include

import (
	"context"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/adapter/outbound"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
)

func registerMASQUEOutbound(registry *outbound.Registry) {
	outbound.Register[option.MASQUEOutboundOptions](registry, C.TypeMASQUE, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MASQUEOutboundOptions) (adapter.Outbound, error) {
		return nil, E.New(`MASQUE outbound is not included in this build, rebuild with -tags with_masque`)
	})
}
