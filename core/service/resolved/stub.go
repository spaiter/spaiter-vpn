//go:build !linux

package resolved

import (
	"context"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	boxService "github.com/spaiter/spaiter-vpn/core/adapter/service"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/dns"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
)

func RegisterService(registry *boxService.Registry) {
	boxService.Register[option.ResolvedServiceOptions](registry, C.TypeResolved, func(ctx context.Context, logger log.ContextLogger, tag string, options option.ResolvedServiceOptions) (adapter.Service, error) {
		return nil, E.New("resolved service is only supported on Linux")
	})
}

func RegisterTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.ResolvedDNSServerOptions](registry, C.TypeResolved, func(ctx context.Context, logger log.ContextLogger, tag string, options option.ResolvedDNSServerOptions) (adapter.DNSTransport, error) {
		return nil, E.New("resolved DNS server is only supported on Linux")
	})
}
