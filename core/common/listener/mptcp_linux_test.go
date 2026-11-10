package listener

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	"github.com/stretchr/testify/require"

	"github.com/sagernet/sing-box/option"
)

// TestListenerMultipathTCPOnlyWhenAsked: an inbound listens on MPTCP only when
// tcp_multi_path asks for it. Go 1.24+ listens on MPTCP by default, and
// CVE-2026-98432 made an IPv4 MPTCP listener a remote root; every inbound of a
// build without the godebug setting was one, and the build's link flag that
// was meant to prevent it named a symbol that does not exist. This test holds
// regardless of how the binary is linked.
func TestListenerMultipathTCPOnlyWhenAsked(t *testing.T) {
	accepted := func(multiPath bool) bool {
		listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
		l := New(Options{
			Context: context.Background(),
			Logger:  logger.NOP(),
			Listen:  option.ListenOptions{Listen: &listen, TCPMultiPath: multiPath},
		})
		tcpListener, err := l.ListenTCP()
		require.NoError(t, err)
		defer tcpListener.Close()
		conn, err := net.Dial("tcp", tcpListener.Addr().String())
		require.NoError(t, err)
		defer conn.Close()
		server, err := tcpListener.Accept()
		require.NoError(t, err)
		defer server.Close()
		isMultipath, err := server.(*net.TCPConn).MultipathTCP()
		require.NoError(t, err)
		return isMultipath
	}
	require.False(t, accepted(false), "the default must not be MPTCP")
	if !accepted(true) {
		t.Log("tcp_multi_path did not give MPTCP: the kernel has it off, or the dialer did not use it")
	}
}
