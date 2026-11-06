//go:build with_xdp && linux

package include

import (
	"github.com/spaiter/spaiter-vpn/core/adapter/service"
	"github.com/spaiter/spaiter-vpn/core/service/xdp"
)

func registerXDPBlockerService(registry *service.Registry) {
	xdp.RegisterService(registry)
}
