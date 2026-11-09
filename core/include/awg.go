//go:build with_awg

package include

import (
	"github.com/spaiter/spaiter-vpn/core/adapter/endpoint"
	"github.com/spaiter/spaiter-vpn/core/protocol/awg"
)

func registerAwgEndpoint(registry *endpoint.Registry) {
	awg.RegisterEndpoint(registry)
}
