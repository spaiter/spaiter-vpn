package include

import (
	"github.com/spaiter/spaiter-vpn/core/adapter/service"
	"github.com/spaiter/spaiter-vpn/core/service/oomkiller"
)

func registerOOMKillerService(registry *service.Registry) {
	oomkiller.RegisterService(registry)
}
