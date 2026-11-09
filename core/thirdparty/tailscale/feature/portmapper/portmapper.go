// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package portmapper registers support for NAT-PMP, PCP, and UPnP port
// mapping protocols to help get direction connections through NATs.
package portmapper

import (
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/feature"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/net/netmon"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/net/portmapper"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/net/portmapper/portmappertype"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/types/logger"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/util/eventbus"
)

func init() {
	feature.Register("portmapper")
	portmappertype.HookNewPortMapper.Set(newPortMapper)
}

func newPortMapper(
	logf logger.Logf,
	bus *eventbus.Bus,
	netMon *netmon.Monitor,
	disableUPnPOrNil func() bool,
	onlyTCP443OrNil func() bool,
) portmappertype.Client {
	pm := portmapper.NewClient(portmapper.Config{
		EventBus: bus,
		Logf:     logf,
		NetMon:   netMon,
		DebugKnobs: &portmapper.DebugKnobs{
			DisableAll:      onlyTCP443OrNil,
			DisableUPnPFunc: disableUPnPOrNil,
		},
	})
	pm.SetGatewayLookupFunc(netMon.GatewayAndSelfIP)
	return pm
}
