//go:build !with_awg

package warp

import (
	"context"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
)

func createWARPAwgEndpoint(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options option.WARPEndpointOptions,
	config *C.WARPConfig,
	peerAddr string,
	peerPort uint16,
	peerPublicKey string,
) (adapter.Endpoint, error) {
	return nil, E.New(`Awg is not included in this build, rebuild with -tags with_awg`)
}
