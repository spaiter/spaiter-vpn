package adapter

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
)

// Note: for proxy protocols, outbound creates early connections by default.

type Outbound interface {
	Type() string
	Tag() string
	Network() []string
	Dependencies() []string
	IsReady() bool //H
	N.Dialer
}

type OutboundWithPreferredRoutes interface {
	Outbound
	PreferredDomain(metadata *InboundContext, domain string) bool
	PreferredAddress(metadata *InboundContext, address netip.Addr) bool
}

type FlowOutbound interface {
	Outbound
	tun.Port
	PreMatchFlow(network string, destination netip.Addr) PreMatchAction
}

type OutboundRegistry interface {
	option.OutboundOptionsRegistry
	CreateOutbound(ctx context.Context, router Router, logger log.ContextLogger, tag string, outboundType string, options any) (Outbound, error)
}

type OutboundManager interface {
	Lifecycle
	Outbounds() []Outbound
	Outbound(tag string) (Outbound, bool)
	Default() Outbound
	Remove(tag string) error
	Create(ctx context.Context, router Router, logger log.ContextLogger, tag string, outboundType string, options any) error
}
