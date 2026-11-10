//go:build with_xdp && linux

package include

import (
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/service/xdp"
)

func registerXDPBlockerService(registry *service.Registry) {
	xdp.RegisterService(registry)
}
