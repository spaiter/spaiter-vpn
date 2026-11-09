//go:build with_ocm

package include

import (
	"github.com/spaiter/spaiter-vpn/core/adapter/service"
	"github.com/spaiter/spaiter-vpn/core/service/ocm"
)

func registerOCMService(registry *service.Registry) {
	ocm.RegisterService(registry)
}
