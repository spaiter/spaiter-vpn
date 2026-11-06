//go:build !linux

package device

import (
	"github.com/spaiter/spaiter-vpn/core/thirdparty/wireguard-go/conn"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/wireguard-go/rwcancel"
)

func (device *Device) startRouteListener(_ conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
