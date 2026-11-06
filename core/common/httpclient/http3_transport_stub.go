//go:build !with_quic

package httpclient

import (
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/spaiter/spaiter-vpn/core/common/tls"
	"github.com/spaiter/spaiter-vpn/core/option"
)

func newHTTP3FallbackTransport(
	rawDialer N.Dialer,
	baseTLSConfig tls.Config,
	h2Fallback innerTransport,
	options option.QUICOptions,
	fallbackDelay time.Duration,
) (innerTransport, error) {
	return nil, E.New("HTTP/3 requires building with the with_quic tag")
}

func newHTTP3Transport(
	rawDialer N.Dialer,
	baseTLSConfig tls.Config,
	options option.QUICOptions,
) (innerTransport, error) {
	return nil, E.New("HTTP/3 requires building with the with_quic tag")
}
