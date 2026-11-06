//go:build !(with_xdp && linux)

package xdp

import (
	"context"
	"net/netip"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	boxService "github.com/spaiter/spaiter-vpn/core/adapter/service"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
)

func RegisterService(registry *boxService.Registry) {
	boxService.Register[option.XDPBlockerServiceOptions](registry, C.TypeXDPBlocker, func(ctx context.Context, logger log.ContextLogger, tag string, options option.XDPBlockerServiceOptions) (adapter.Service, error) {
		return nil, E.New("XDP blocker is only supported on Linux with -tags with_xdp")
	})
}

// Stub type to satisfy interface at compile time when needed.
type stubService struct{}

func (s *stubService) BlockIP(netip.Addr, time.Duration, string) error { return nil }
func (s *stubService) UnblockIP(netip.Addr) error                      { return nil }
func (s *stubService) IsBlocked(netip.Addr) bool                       { return false }
func (s *stubService) BlockedCount() int                               { return 0 }
func (s *stubService) TrackUserIP(string, netip.Addr)                  {}
func (s *stubService) BlockUserIPs(string, time.Duration) error        { return nil }
