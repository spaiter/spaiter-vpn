//go:build with_xdp && linux

package xdp

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

func RegisterService(registry *boxService.Registry) {
	boxService.Register[option.XDPBlockerServiceOptions](registry, C.TypeXDPBlocker, NewService)
}

type Service struct {
	boxService.Adapter
	ctx             context.Context
	cancel          context.CancelFunc
	logger          log.ContextLogger
	options         option.XDPBlockerServiceOptions
	filters         []*Filter
	banDuration     time.Duration
	cleanupInterval time.Duration
	logBlocked      bool
	userIPs         map[string]map[netip.Addr]struct{}
	userIPsMu       sync.RWMutex
}

func NewService(ctx context.Context, logger log.ContextLogger, tag string, options option.XDPBlockerServiceOptions) (adapter.Service, error) {
	if len(options.Interfaces) == 0 {
		return nil, E.New("at least one interface is required")
	}

	banDuration := time.Duration(options.BanDuration)
	if banDuration == 0 {
		banDuration = 5 * time.Hour
	}
	cleanupInterval := time.Duration(options.CleanupInterval)
	if cleanupInterval == 0 {
		cleanupInterval = 5 * time.Minute
	}

	logBlocked := true
	if options.LogBlocked != nil {
		logBlocked = *options.LogBlocked
	}

	return &Service{
		Adapter:         boxService.NewAdapter(C.TypeXDPBlocker, tag),
		ctx:             ctx,
		logger:          logger,
		options:         options,
		banDuration:     banDuration,
		cleanupInterval: cleanupInterval,
		logBlocked:      logBlocked,
		userIPs:         make(map[string]map[netip.Addr]struct{}),
	}, nil
}

func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		scope.Add(s.Close) // closed with the box
		service.MustRegister[adapter.XDPBlocker](s.ctx, s)
	case adapter.StartStateStart:
		ctx, cancel := context.WithCancel(s.ctx)
		s.cancel = cancel
		for _, ifaceName := range s.options.Interfaces {
			filter, err := NewFilter(ifaceName, s.logger, s.logBlocked)
			if err != nil {
				cancel()
				s.closeFilters()
				return E.Cause(err, "failed to create XDP filter on ", ifaceName)
			}
			s.logger.Info("XDP filter loaded on interface ", ifaceName)
			filter.MapManager().StartPeriodicCleanup(ctx, s.cleanupInterval)
			s.filters = append(s.filters, filter)
		}
	}
	return nil
}

func (s *Service) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	s.closeFilters()
	return nil
}

func (s *Service) closeFilters() {
	for _, filter := range s.filters {
		s.logger.Info("detaching XDP filter from interface ", filter.ifaceName)
		filter.Close()
	}
	s.filters = nil
}

func (s *Service) BlockIP(ip netip.Addr, duration time.Duration, user string) error {
	if duration == 0 {
		duration = s.banDuration
	}
	var firstErr error
	for _, filter := range s.filters {
		if err := filter.MapManager().AddIP(ip, duration); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		if s.logBlocked {
			s.logger.Error("failed to XDP block ", ip, ": ", firstErr)
		}
		return firstErr
	}
	if s.logBlocked {
		// user= is parsed by the Grafana exporter; keep the field present even
		// when unknown so the format stays uniform. //H
		if user == "" {
			user = "-"
		}
		s.logger.Info("XDP blocked ", ip, " user=", user, " for ", duration, " (total: ", s.BlockedCount(), ")")
	}
	return nil
}

func (s *Service) UnblockIP(ip netip.Addr) error {
	var firstErr error
	for _, filter := range s.filters {
		if err := filter.MapManager().RemoveIP(ip); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		if s.logBlocked {
			s.logger.Error("failed to XDP unblock ", ip, ": ", firstErr)
		}
		return firstErr
	}
	if s.logBlocked {
		s.logger.Info("XDP unblocked ", ip, " (total: ", s.BlockedCount(), ")")
	}
	return nil
}

func (s *Service) IsBlocked(ip netip.Addr) bool {
	for _, filter := range s.filters {
		if filter.MapManager().IsBlocked(ip) {
			return true
		}
	}
	return false
}

func (s *Service) BlockedCount() int {
	if len(s.filters) == 0 {
		return 0
	}
	return s.filters[0].MapManager().BlockedCount()
}

func (s *Service) TrackUserIP(user string, ip netip.Addr) {
	if user == "" {
		return
	}
	s.userIPsMu.Lock()
	defer s.userIPsMu.Unlock()
	ips, ok := s.userIPs[user]
	if !ok {
		ips = make(map[netip.Addr]struct{})
		s.userIPs[user] = ips
	}
	ips[ip] = struct{}{}
}

func (s *Service) BlockUserIPs(user string, duration time.Duration) error {
	if user == "" {
		return nil
	}
	s.userIPsMu.RLock()
	ips, ok := s.userIPs[user]
	if !ok {
		s.userIPsMu.RUnlock()
		return nil
	}
	// Copy the IPs under read lock to avoid holding it during blocking
	ipList := make([]netip.Addr, 0, len(ips))
	for ip := range ips {
		ipList = append(ipList, ip)
	}
	s.userIPsMu.RUnlock()

	var firstErr error
	for _, ip := range ipList {
		if err := s.BlockIP(ip, duration, user); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
