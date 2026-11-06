//go:build !linux && !darwin && !(windows && (amd64 || 386))

package bridge

import (
	"context"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/option"
)

func newBackend(ctx context.Context, logger logger.ContextLogger, networkManager adapter.NetworkManager, tag string, options option.BridgeOutboundOptions) (Backend, error) {
	return nil, E.New("bridge outbound is only supported on Linux, macOS, Windows (x86 and x64), rooted Android and jailbroken iOS")
}
