package tsnet

import (
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/ipn/ipnlocal"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/wgengine/netstack"
)

func (s *Server) ExportNetstack() *netstack.Impl {
	return s.netstack
}

func (s *Server) ExportLocalBackend() *ipnlocal.LocalBackend {
	return s.lb
}
