//go:build !with_dhcp

package local

import (
	"context"

	N "github.com/sagernet/sing/common/network"
	"github.com/spaiter/spaiter-vpn/core/dns"
	"github.com/spaiter/spaiter-vpn/core/log"
)

func newDHCPTransport(transportAdapter dns.TransportAdapter, ctx context.Context, dialer N.Dialer, logger log.ContextLogger) dhcpTransport {
	return nil
}
