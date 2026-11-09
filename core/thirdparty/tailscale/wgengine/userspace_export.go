package wgengine

import (
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/net/dns"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/wgengine/router"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/wgengine/wgcfg"
)

type ExportedUserspaceEngine interface {
	SetOnReconfigListener(listener ReconfigListener)
}

type ReconfigListener = func(cfg *wgcfg.Config, routerCfg *router.Config, dnsCfg *dns.Config)

func (e *userspaceEngine) SetOnReconfigListener(listener ReconfigListener) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onReconfig = listener
}
