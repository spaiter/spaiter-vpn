//go:build !with_grpc

package v2ray

import (
	"context"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/common/tls"
	"github.com/spaiter/spaiter-vpn/core/option"
	"github.com/spaiter/spaiter-vpn/core/transport/v2raygrpclite"
)

func NewGRPCServer(ctx context.Context, logger logger.ContextLogger, options option.V2RayGRPCOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (adapter.V2RayServerTransport, error) {
	return v2raygrpclite.NewServer(ctx, logger, options, tlsConfig, handler)
}

func NewGRPCClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayGRPCOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	return v2raygrpclite.NewClient(ctx, dialer, serverAddr, options, tlsConfig), nil
}
