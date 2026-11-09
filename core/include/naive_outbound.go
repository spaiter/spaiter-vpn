//go:build with_naive_outbound

package include

import (
	"github.com/spaiter/spaiter-vpn/core/adapter/outbound"
	"github.com/spaiter/spaiter-vpn/core/protocol/naive"
)

func registerNaiveOutbound(registry *outbound.Registry) {
	naive.RegisterOutbound(registry)
}
