//go:build !darwin || !cgo

package oomkiller

import (
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spaiter/spaiter-vpn/core/adapter"
)

func (s *Service) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if !s.timerConfig.policyMode.hasTimerMode() {
		return E.New("memory pressure monitoring is not available on this platform without memory_limit")
	}
	s.startTimer()
	return nil
}

func (s *Service) Close() error {
	s.stopTimer()
	return nil
}
