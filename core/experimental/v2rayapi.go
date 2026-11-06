package experimental

import (
	"os"

	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
)

type V2RayServerConstructor = func(logger log.Logger, options option.V2RayAPIOptions) (adapter.V2RayServer, error)

var v2rayServerConstructor V2RayServerConstructor

func RegisterV2RayServerConstructor(constructor V2RayServerConstructor) {
	v2rayServerConstructor = constructor
}

func NewV2RayServer(logger log.Logger, options option.V2RayAPIOptions) (adapter.V2RayServer, error) {
	if v2rayServerConstructor == nil {
		return nil, os.ErrInvalid
	}
	return v2rayServerConstructor(logger, options)
}
