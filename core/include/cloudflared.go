//go:build with_cloudflared

package include

import (
	"github.com/spaiter/spaiter-vpn/core/adapter/inbound"
	"github.com/spaiter/spaiter-vpn/core/protocol/cloudflare"
)

func registerCloudflaredInbound(registry *inbound.Registry) {
	cloudflare.RegisterInbound(registry)
}
