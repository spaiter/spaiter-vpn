//go:build with_xdp && linux

package xdp

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common/logger"

	"github.com/cilium/ebpf"
)

type IPMapManager struct {
	bpfMap     *ebpf.Map
	bpfMapV6   *ebpf.Map
	logger     logger.ContextLogger
	logBlocked bool
	mu         sync.RWMutex
	localMap   map[netip.Addr]time.Time
}

func NewIPMapManager(bpfMap *ebpf.Map, bpfMapV6 *ebpf.Map, logger logger.ContextLogger, logBlocked bool) *IPMapManager {
	return &IPMapManager{
		bpfMap:     bpfMap,
		bpfMapV6:   bpfMapV6,
		logger:     logger,
		logBlocked: logBlocked,
		localMap:   make(map[netip.Addr]time.Time),
	}
}

func (m *IPMapManager) AddIP(ip netip.Addr, duration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	expiresAt := time.Now().Add(duration)
	expiresAtSec := uint64(expiresAt.Unix())

	if ip.Is4() {
		raw := ip.As4()
		ipKey := binary.NativeEndian.Uint32(raw[:])
		if err := m.bpfMap.Put(&ipKey, &expiresAtSec); err != nil {
			return err
		}
	} else {
		ipKey := ip.As16()
		if err := m.bpfMapV6.Put(&ipKey, &expiresAtSec); err != nil {
			return err
		}
	}

	m.localMap[ip] = expiresAt
	return nil
}

func (m *IPMapManager) RemoveIP(ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ip.Is4() {
		raw := ip.As4()
		ipKey := binary.NativeEndian.Uint32(raw[:])
		if err := m.bpfMap.Delete(&ipKey); err != nil {
			return err
		}
	} else {
		ipKey := ip.As16()
		if err := m.bpfMapV6.Delete(&ipKey); err != nil {
			return err
		}
	}

	delete(m.localMap, ip)
	return nil
}

func (m *IPMapManager) IsBlocked(ip netip.Addr) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if expiresAt, exists := m.localMap[ip]; exists {
		return time.Now().Before(expiresAt)
	}
	return false
}

func (m *IPMapManager) BlockedCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.localMap)
}

func (m *IPMapManager) CleanupExpired(ctx context.Context) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	removed := 0

	for ip, expiresAt := range m.localMap {
		if now.After(expiresAt) {
			if ip.Is4() {
				raw := ip.As4()
				ipKey := binary.NativeEndian.Uint32(raw[:])
				if err := m.bpfMap.Delete(&ipKey); err != nil {
					m.logger.DebugContext(ctx, "failed to remove expired IP ", ip, " from XDP map: ", err)
					continue
				}
			} else {
				ipKey := ip.As16()
				if err := m.bpfMapV6.Delete(&ipKey); err != nil {
					m.logger.DebugContext(ctx, "failed to remove expired IPv6 ", ip, " from XDP map: ", err)
					continue
				}
			}

			delete(m.localMap, ip)
			removed++
		}
	}

	return removed
}

func (m *IPMapManager) StartPeriodicCleanup(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				removed := m.CleanupExpired(ctx)
				if removed > 0 && m.logBlocked {
					m.logger.InfoContext(ctx, "XDP cleanup: removed ", removed, " expired IPs, ", len(m.localMap), " remaining")
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}
