//go:build !with_v2ray_api

package include

import (
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/experimental"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
)

func init() {
	experimental.RegisterV2RayServerConstructor(func(logger log.Logger, options option.V2RayAPIOptions) (adapter.V2RayServer, error) {
		return nil, E.New(`v2ray api is not included in this build, rebuild with -tags with_v2ray_api`)
	})
}
