//go:build with_usbip && (linux || (darwin && cgo) || windows)

package include

import (
	"github.com/spaiter/spaiter-vpn/core/adapter/service"
	"github.com/spaiter/spaiter-vpn/core/service/usbip"
)

func registerUSBIPServices(registry *service.Registry) {
	usbip.RegisterService(registry)
}
