//go:build with_ccm && (!darwin || cgo)

package include

import (
	"github.com/spaiter/spaiter-vpn/core/adapter/service"
	"github.com/spaiter/spaiter-vpn/core/service/ccm"
)

func registerCCMService(registry *service.Registry) {
	ccm.RegisterService(registry)
}
