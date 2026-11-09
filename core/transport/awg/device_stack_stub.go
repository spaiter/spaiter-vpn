//go:build !with_gvisor

package awg

import (
	"context"
	"net/netip"
	"time"

	singTun "github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
)

func newStackTun(ctx context.Context, address []netip.Prefix, mtu uint32, handler singTun.Handler, udpTimeout time.Duration) (tunAdapter, error) {
	return nil, E.New("AWG handler support requires gvisor (build with with_gvisor tag)")
}
