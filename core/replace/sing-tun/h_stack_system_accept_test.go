package tun

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

func hTCPSystem(t *testing.T) *System {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &System{
		ctx:              ctx,
		logger:           logger.NOP(),
		inet4Address:     netip.MustParseAddr("127.0.0.1"),
		inet4NextAddress: netip.MustParseAddr("127.0.0.2"),
	}
	s.tcpNat4 = NewNat(ctx, time.Minute)
	if err := s.startTCPListener(false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.closing.Store(true)
		s.listenerAccess.Lock()
		s.tcpListener.Close()
		s.listenerAccess.Unlock()
	})
	return s
}

func hDialable(port uint16) bool {
	conn, err := net.DialTimeout("tcp4", "127.0.0.1:"+strconv.Itoa(int(port)), 200*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// A listener closed behind the stack's back is recreated, and new TCP gets through again.
func TestH_SystemAcceptLoopRecreatesListener(t *testing.T) {
	s := hTCPSystem(t)
	oldPort := s.currentTCPPort(false)
	s.listenerAccess.Lock()
	s.tcpListener.Close()
	s.listenerAccess.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		port := s.currentTCPPort(false)
		if port != oldPort && hDialable(port) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the listener was not recreated (port %d)", port)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s.tcpRecoveries.Load() != 1 {
		t.Fatalf("recoveries: %d", s.tcpRecoveries.Load())
	}
}

// Closing the stack ends the loop without recreating anything.
func TestH_SystemAcceptLoopQuietOnClose(t *testing.T) {
	s := hTCPSystem(t)
	s.closing.Store(true)
	s.listenerAccess.Lock()
	s.tcpListener.Close()
	s.listenerAccess.Unlock()
	time.Sleep(300 * time.Millisecond)
	if s.tcpRecoveries.Load() != 0 {
		t.Fatalf("a closing stack recreated its listener")
	}
}
