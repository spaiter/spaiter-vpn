package xray

import (
	"context"
	"net"
	"syscall"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/adapter/outbound"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.XrayOutboundOptions](registry, C.TypeXray, New)
}

type Outbound struct {
	outbound.Adapter
	logger logger.ContextLogger
}

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.XrayOutboundOptions) (adapter.Outbound, error) {
	// return &Outbound{
	// 	Adapter: outbound.NewAdapter(C.TypeBlock, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
	// 	logger:  logger,
	// }, nil
	return nil, E.New("Xray is not implemented yet")
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	h.logger.InfoContext(ctx, "blocked connection to ", destination)
	return nil, syscall.EPERM
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	h.logger.InfoContext(ctx, "blocked packet connection to ", destination)
	return nil, syscall.EPERM
}
