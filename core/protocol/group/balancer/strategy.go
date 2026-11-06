package balancer

import "github.com/spaiter/spaiter-vpn/core/adapter"

type Strategy interface {
	UpdateOutboundsInfo(outbounds map[string]*adapter.URLTestHistory) (changed bool)
	Select(metadata adapter.InboundContext, network string, touch bool) adapter.Outbound
	Now() string
}
