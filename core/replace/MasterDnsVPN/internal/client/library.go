// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client: the hooks a program that embeds the client as a library uses
// (hiddify-sing-box, through package lib). In library mode the client opens no
// local SOCKS, TCP or DNS listener; the program opens streams with DialStream
// and gets a net.Conn for each. The sockets to the resolvers can be given a
// socket control function, so a VPN app keeps them outside its own tunnel.
// ==============================================================================

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
)

// ErrNotReady is returned by DialStream before the session with the server is established.
var ErrNotReady = errors.New("session is not ready")

// ErrNoStreamID is returned by DialStream when every stream id is in use.
var ErrNoStreamID = errors.New("no free stream id")

// ErrConnectTimeout is returned by DialStream when the server does not answer the connect in time.
var ErrConnectTimeout = errors.New("connect timeout")

// ConnectError is the server's answer to a connect that failed: a SOCKS5 reply code.
type ConnectError struct {
	Reply byte
}

func (e *ConnectError) Error() string {
	return fmt.Sprintf("connect failed: %s", socksReplyName(e.Reply))
}

func socksReplyName(rep byte) string {
	switch rep {
	case SOCKS5_REPLY_GENERAL_FAILURE:
		return "general failure"
	case SOCKS5_REPLY_RULESET_DENIED:
		return "connection not allowed by the server"
	case SOCKS5_REPLY_NETWORK_UNREACHABLE:
		return "network unreachable"
	case SOCKS5_REPLY_HOST_UNREACHABLE:
		return "host unreachable"
	case SOCKS5_REPLY_CONNECTION_REFUSED:
		return "connection refused"
	case SOCKS5_REPLY_TTL_EXPIRED:
		return "TTL expired"
	case SOCKS5_REPLY_CMD_NOT_SUPPORTED:
		return "command not supported"
	case SOCKS5_REPLY_ATYP_NOT_SUPPORTED:
		return "address type not supported"
	default:
		return fmt.Sprintf("reply %d", rep)
	}
}

// SetLibraryMode turns the local listeners off: no SOCKS or TCP proxy and no local DNS server
// are opened when the runtime starts. Streams are opened with DialStream. Set it before Run.
func (c *Client) SetLibraryMode(enabled bool) {
	c.libraryMode = enabled
}

// SetSocketControl sets a function that runs on every UDP socket to a resolver before it is
// bound or connected, in addition to FD_CONTROL_UNIX_SOCKET. Set it before Run.
func (c *Client) SetSocketControl(control func(network, address string, rc syscall.RawConn) error) {
	c.socketControl = control
}

// LibraryMode reports whether SetLibraryMode(true) was called.
func (c *Client) LibraryMode() bool {
	return c.libraryMode
}

func (c *Client) addConnectWaiter(streamID uint16) chan byte {
	ch := make(chan byte, 1)
	c.connectWaitersMu.Lock()
	if c.connectWaiters == nil {
		c.connectWaiters = make(map[uint16]chan byte)
	}
	c.connectWaiters[streamID] = ch
	c.connectWaitersMu.Unlock()
	return ch
}

func (c *Client) removeConnectWaiter(streamID uint16) {
	c.connectWaitersMu.Lock()
	delete(c.connectWaiters, streamID)
	c.connectWaitersMu.Unlock()
}

// deliverLibraryConnectResult hands the connect result of a stream opened by DialStream to its
// caller. It returns false when the stream is not a library stream, so the SOCKS reply goes to
// the local proxy connection as usual.
func (c *Client) deliverLibraryConnectResult(streamID uint16, rep byte) bool {
	c.connectWaitersMu.Lock()
	ch, ok := c.connectWaiters[streamID]
	if ok {
		delete(c.connectWaiters, streamID)
	}
	c.connectWaitersMu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- rep:
	default:
	}
	return true
}

// socksTargetPayload encodes host and port as a SOCKS5 address: an IPv4, an IPv6 or a domain name.
func socksTargetPayload(host string, port uint16) ([]byte, error) {
	var payload []byte
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if addr.Is4() {
			a4 := addr.As4()
			payload = append(payload, SOCKS5_ATYP_IPV4)
			payload = append(payload, a4[:]...)
		} else {
			a16 := addr.As16()
			payload = append(payload, SOCKS5_ATYP_IPV6)
			payload = append(payload, a16[:]...)
		}
	} else {
		if host == "" || len(host) > 255 {
			return nil, fmt.Errorf("invalid destination host %q", host)
		}
		payload = append(payload, SOCKS5_ATYP_DOMAIN, byte(len(host)))
		payload = append(payload, host...)
	}
	return binary.BigEndian.AppendUint16(payload, port), nil
}

// DialStream opens a stream through the tunnel and returns its local end. In SOCKS5 mode the
// server connects to host:port; in TCP mode host and port are ignored, because the server
// forwards every stream to its fixed target. It returns once the server reports the result of
// the connect, or after timeout (0 means 30 seconds).
func (c *Client) DialStream(ctx context.Context, host string, port uint16, timeout time.Duration) (net.Conn, error) {
	if !c.SessionReady() {
		return nil, ErrNotReady
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	tcpMode := c.cfg.ProtocolType == "TCP"
	var targetPayload []byte
	if !tcpMode {
		var err error
		targetPayload, err = socksTargetPayload(host, port)
		if err != nil {
			return nil, err
		}
	}

	streamID, ok := c.get_new_stream_id()
	if !ok {
		return nil, ErrNoStreamID
	}

	local, remote := newLibraryPipe()
	waiter := c.addConnectWaiter(streamID)
	s := c.new_stream(streamID, remote, nil)
	if s == nil {
		c.removeConnectWaiter(streamID)
		_ = local.Close()
		return nil, fmt.Errorf("stream %d setup failed", streamID)
	}
	arqObj, ok := s.Stream.(*arq.ARQ)
	if !ok || arqObj == nil {
		c.removeConnectWaiter(streamID)
		c.removeStream(streamID)
		_ = local.Close()
		return nil, fmt.Errorf("stream %d has no ARQ", streamID)
	}

	if tcpMode {
		c.log.Infof("🔌 <green>New TCP CONNECT, Stream ID: <cyan>%d</cyan></green>", streamID)
		arqObj.SendControlPacketWithTTL(
			Enums.PACKET_STREAM_SYN,
			0, 0, 0, nil,
			Enums.DefaultPacketPriority(Enums.PACKET_STREAM_SYN),
			true, nil, 120*time.Second,
		)
	} else {
		s.LocalSocksVersion = SOCKS5_VERSION
		c.log.Infof("🔌 <green>New TCP CONNECT to <cyan>%s:%d</cyan>, Stream ID: <cyan>%d</cyan></green>", host, port, streamID)
		fragments := fragmentPayload(targetPayload, c.syncedUploadMTU)
		total := uint8(len(fragments))
		for i, frag := range fragments {
			arqObj.SendControlPacketWithTTL(
				Enums.PACKET_SOCKS5_SYN,
				0,
				uint8(i),
				total,
				frag,
				Enums.DefaultPacketPriority(Enums.PACKET_SOCKS5_SYN),
				true, nil, 120*time.Second,
			)
		}
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case rep := <-waiter:
		if rep == SOCKS5_REPLY_SUCCESS {
			return local, nil
		}
		_ = local.Close()
		return nil, &ConnectError{Reply: rep}
	case <-ctx.Done():
		c.cancelLibraryConnect(streamID, "connect cancelled by the caller")
		_ = local.Close()
		return nil, ctx.Err()
	case <-timer.C:
		c.cancelLibraryConnect(streamID, "connect timeout")
		_ = local.Close()
		return nil, ErrConnectTimeout
	}
}

// cancelLibraryConnect gives up on a stream whose connect result has not arrived: the stream is
// marked cancelled and reset, and a late result is ignored.
func (c *Client) cancelLibraryConnect(streamID uint16, reason string) {
	c.removeConnectWaiter(streamID)
	s, ok := c.getStream(streamID)
	if !ok || s == nil {
		return
	}
	s.socksResultMu.Lock()
	switch s.StatusValue() {
	case streamStatusSocksConnecting, streamStatusConnecting, streamStatusPending:
	default:
		s.socksResultMu.Unlock()
		return
	}
	s.SetStatus(streamStatusCancelled)
	if s.NetConn != nil {
		_ = s.NetConn.Close()
	}
	s.MarkTerminal(time.Now())
	s.socksResultMu.Unlock()

	if arqObj, err := c.getStreamARQ(streamID); err == nil {
		arqObj.Close(reason, arq.CloseOptions{SendRST: true})
	}
}

// ActiveResolverCount is the number of resolvers that passed the MTU test and are in use.
func (c *Client) ActiveResolverCount() int {
	if c.balancer == nil {
		return 0
	}
	return c.balancer.ActiveCount()
}

// TotalResolverCount is the number of domain and resolver pairs the client knows.
func (c *Client) TotalResolverCount() int {
	if c.balancer == nil {
		return 0
	}
	return c.balancer.TotalCount()
}

// SyncedMTU returns the upload and download MTU agreed with the server, 0 before the MTU test.
func (c *Client) SyncedMTU() (upload int, download int) {
	return c.syncedMTUs()
}
