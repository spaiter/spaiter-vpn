//go:build !with_dnstt

package include

import (
	"context"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/adapter/outbound"
	"github.com/spaiter/spaiter-vpn/core/adapter/service"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
)

func registerDNSTTOutbound(registry *outbound.Registry) {
	outbound.Register[option.DnsttOptions](registry, C.TypeDNSTT, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DnsttOptions) (adapter.Outbound, error) {
		return nil, E.New(`dnstt outbound is not included in this build, rebuild with -tags with_dnstt`)
	})
}

func registerSmartDNSPoolService(registry *service.Registry) {
	service.Register[option.SmartDNSPoolServiceOptions](registry, C.TypeSmartDNSPool, func(ctx context.Context, logger log.ContextLogger, tag string, options option.SmartDNSPoolServiceOptions) (adapter.Service, error) {
		return nil, E.New(`smart_dns_pool service is not included in this build, rebuild with -tags with_dnstt`)
	})
}
