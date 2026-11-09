//go:build !with_quic

package networkquality

import (
	N "github.com/sagernet/sing/common/network"
	C "github.com/spaiter/spaiter-vpn/core/constant"
)

func NewHTTP3MeasurementClientFactory(dialer N.Dialer) (MeasurementClientFactory, error) {
	return nil, C.ErrQUICNotIncluded
}
