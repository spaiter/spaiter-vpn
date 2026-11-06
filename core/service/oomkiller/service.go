package oomkiller

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/service"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	boxService "github.com/spaiter/spaiter-vpn/core/adapter/service"
	boxConstant "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
)

type OOMReporter interface {
	WriteReport(memoryUsage uint64) error
	WriteDraft(memoryUsage uint64) error
	DiscardDraft() error
}

func RegisterService(registry *boxService.Registry) {
	boxService.Register[option.OOMKillerServiceOptions](registry, boxConstant.TypeOOMKiller, NewService)
}

type Service struct {
	boxService.Adapter
	ctx            context.Context
	logger         log.ContextLogger
	network        adapter.NetworkManager
	timerConfig    timerConfig
	adaptiveTimer  *adaptiveTimer
	lastReportTime atomic.Int64
	//nolint:unused // touched only on darwin && cgo via writeOOMDraft/discardOOMDraft.
	draftCancelled atomic.Bool
}

func NewService(ctx context.Context, logger log.ContextLogger, tag string, options option.OOMKillerServiceOptions) (adapter.Service, error) {
	memoryLimit, mode := resolvePolicyMode(ctx, options)
	config, err := buildTimerConfig(options, memoryLimit, mode, options.KillerDisabled)
	if err != nil {
		return nil, err
	}
	return &Service{
		Adapter:     boxService.NewAdapter(boxConstant.TypeOOMKiller, tag),
		ctx:         ctx,
		logger:      logger,
		network:     service.FromContext[adapter.NetworkManager](ctx),
		timerConfig: config,
	}, nil
}

func (s *Service) createTimer() {
	s.adaptiveTimer = newAdaptiveTimer(s.logger, s.network, s.timerConfig, s.writeOOMReport)
}

func (s *Service) startTimer() {
	s.createTimer()
	s.adaptiveTimer.start()
}

func (s *Service) stopTimer() {
	if s.adaptiveTimer != nil {
		s.adaptiveTimer.stop()
	}
}

func (s *Service) writeOOMReport(memoryUsage uint64) {
	now := time.Now().Unix()
	lastReport := s.lastReportTime.Load()
	if now-lastReport < 3600 {
		return
	}
	if !s.lastReportTime.CompareAndSwap(lastReport, now) {
		return
	}
	reporter := service.FromContext[OOMReporter](s.ctx)
	if reporter == nil {
		return
	}
	err := reporter.WriteReport(memoryUsage)
	if err != nil {
		s.logger.Warn("failed to write OOM report: ", err)
	} else {
		s.logger.Info("OOM report saved")
	}
}
