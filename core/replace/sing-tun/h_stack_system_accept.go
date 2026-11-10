package tun

import (
	"errors"
	"net"
	"syscall"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// The system stack sends every new TCP connection from the TUN to a local listener. When its
// accept loop ended on an error, the stack went on rewriting SYNs to the dead listener's port,
// and every new TCP connection was refused until the stack restarted. The loop now waits out
// temporary errors (EMFILE) and recreates a listener that died, unless the stack is closing.
// Ported from Leadaxe/sing-box-lx SPEC 040.

func (s *System) startTCPListener(ipv6 bool) error {
	network, address := "tcp4", s.inet4Address
	if ipv6 {
		network, address = "tcp6", s.inet6Address
	}
	var (
		listener net.Listener
		err      error
	)
	for range 3 {
		listener, err = listenNetworkNamespace(s.ctx, s.netNs, s.listenConfig, network, net.JoinHostPort(address.String(), "0"))
		if !retryableListenError(err) {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return err
	}
	port := M.SocksaddrFromNet(listener.Addr()).Port
	s.listenerAccess.Lock()
	if s.closing.Load() {
		s.listenerAccess.Unlock()
		listener.Close()
		return net.ErrClosed
	}
	s.processAccess.Lock()
	if ipv6 {
		s.tcpListener6, s.tcpPort6 = listener, port
	} else {
		s.tcpListener, s.tcpPort = listener, port
	}
	s.processAccess.Unlock()
	s.listenerAccess.Unlock()
	tcpNat := s.tcpNat4
	if ipv6 {
		tcpNat = s.tcpNat6
	}
	go s.acceptLoop(listener, tcpNat, ipv6)
	return nil
}

// recoverAccept handles an Accept error. It returns the listener to go on accepting from, or
// nil when the loop must end; a new listener has its own loop already.
func (s *System) recoverAccept(listener net.Listener, err error, ipv6 bool, tempDelay time.Duration) (net.Listener, time.Duration) {
	if s.closing.Load() || s.ctx.Err() != nil {
		return nil, 0
	}
	if temporaryAcceptError(err) {
		tempDelay = min(max(tempDelay*2, 5*time.Millisecond), time.Second)
		s.logger.Warn(E.Cause(err, "system stack: accept"), ", retrying in ", tempDelay)
		time.Sleep(tempDelay)
		return listener, tempDelay
	}
	oldPort := M.SocksaddrFromNet(listener.Addr()).Port
	s.logger.Warn("system stack: ", listener.Addr().Network(), " listener (port ", oldPort, ") accept failed: ", err, ", recreating listener")
	listener.Close()
	err = s.startTCPListener(ipv6)
	if err != nil {
		if !s.closing.Load() {
			s.logger.Error(E.Cause(err, "system stack: recreate listener"))
		}
		return nil, 0
	}
	recoveries := s.tcpRecoveries.Add(1)
	s.logger.Warn("system stack: listener recreated (port ", oldPort, " -> ", s.currentTCPPort(ipv6), ", recoveries: ", recoveries, ")")
	return nil, 0
}

func (s *System) currentTCPPort(ipv6 bool) uint16 {
	s.processAccess.Lock()
	defer s.processAccess.Unlock()
	if ipv6 {
		return s.tcpPort6
	}
	return s.tcpPort
}

func temporaryAcceptError(err error) bool {
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) || errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ENOMEM) || errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	var netErr interface{ Temporary() bool }
	return errors.As(err, &netErr) && netErr.Temporary() && !errors.Is(err, net.ErrClosed)
}
