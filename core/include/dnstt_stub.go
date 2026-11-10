//go:build !with_dnstt

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func notIncluded[T any](registry *outbound.Registry, outboundType string) {
	outbound.Register[T](registry, outboundType, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options T) (adapter.Outbound, error) {
		return nil, E.New(outboundType, ` outbound is not included in this build, rebuild with -tags with_dnstt`)
	})
}

func registerDNSResolverOutbounds(registry *outbound.Registry) {
	notIncluded[option.DnsttOptions](registry, C.TypeDNSTT)
	notIncluded[option.MasterDNSOptions](registry, C.TypeMasterDNS)
	notIncluded[option.SoarOptions](registry, C.TypeSoar)
}
