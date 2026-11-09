//go:build !darwin || !cgo

package httpclient

import (
	"context"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	"github.com/spaiter/spaiter-vpn/core/option"
)

func newAppleTransport(ctx context.Context, logger logger.ContextLogger, rawDialer N.Dialer, options option.HTTPClientOptions) (innerTransport, error) {
	return nil, E.New("Apple HTTP engine is not available on non-Apple platforms")
}
