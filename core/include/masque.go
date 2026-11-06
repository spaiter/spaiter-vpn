//go:build with_masque

package include

import (
	"github.com/spaiter/spaiter-vpn/core/adapter/outbound"
	"github.com/spaiter/spaiter-vpn/core/protocol/masque"
)

func registerMASQUEOutbound(registry *outbound.Registry) {
	masque.RegisterOutbound(registry)
}
