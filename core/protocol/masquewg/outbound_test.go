package masquewg

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/json/badoption"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/common/tls"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
	"github.com/stretchr/testify/require"
)

const testServerName = "masque.test"

func wgKey(t *testing.T) string {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

// wgSink stands in for the server's WireGuard listener and counts what reaches
// it through the proxy. Nothing answers, so the client keeps retrying its
// handshake, which is all a test of the flow needs.
type wgSink struct {
	conn    *net.UDPConn
	packets atomic.Int64
}

func newWGSink(t *testing.T) *wgSink {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	s := &wgSink{conn: c}
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := c.ReadFrom(buf); err != nil {
				return
			}
			s.packets.Add(1)
		}
	}()
	t.Cleanup(func() { c.Close() })
	return s
}

func startInbound(t *testing.T, port uint16, target string) *Inbound {
	t.Helper()
	keyPEM, certPEM, err := tls.GenerateCertificate(nil, nil, time.Now, testServerName, time.Now().Add(time.Hour))
	require.NoError(t, err)
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	in, err := NewInbound(context.Background(), nil, log.NewNOPFactory().Logger(), "masque-in", option.MASQUEWGInboundOptions{
		ListenOptions: option.ListenOptions{Listen: &listen, ListenPort: port},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
			Enabled:     true,
			ServerName:  testServerName,
			Certificate: badoption.Listable[string]{string(certPEM)},
			Key:         badoption.Listable[string]{string(keyPEM)},
		}},
		Target: target,
	})
	require.NoError(t, err)
	inbound := in.(*Inbound)
	require.NoError(t, inbound.Start(adapter.StartStateStart))
	return inbound
}

func newOutbound(t *testing.T, port uint16) *Outbound {
	t.Helper()
	out, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "masque-out", option.MASQUEWGOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
		PrivateKey:    wgKey(t),
		PeerPublicKey: wgKey(t),
		LocalAddress:  badoption.Listable[netip.Prefix]{netip.MustParsePrefix("10.99.0.2/32")},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: testServerName,
			Insecure:   true,
		}},
	})
	require.NoError(t, err)
	return out.(*Outbound)
}

// An unreachable server used to fail PostStart, which stopped the whole core.
func TestOutboundStartsWithoutServer(t *testing.T) {
	out := newOutbound(t, freeUDPPort(t))
	start := time.Now()
	require.NoError(t, out.PostStart())
	require.Less(t, time.Since(start), 5*time.Second)
	require.True(t, out.ready())

	closed := make(chan struct{})
	go func() { out.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return while the flow was still being dialled")
	}
}

// The flow comes up once the server does, and is redialled when the server
// goes away and comes back.
func TestOutboundDialsInBackgroundAndRedials(t *testing.T) {
	sink := newWGSink(t)
	port := freeUDPPort(t)

	out := newOutbound(t, port)
	require.NoError(t, out.PostStart())
	defer out.Close()

	time.Sleep(1500 * time.Millisecond)
	require.Zero(t, sink.packets.Load())

	first := startInbound(t, port, sink.conn.LocalAddr().String())
	require.Eventually(t, func() bool { return sink.packets.Load() > 0 }, 30*time.Second, 100*time.Millisecond,
		"no WireGuard packet reached the server after it came up")

	require.NoError(t, first.Close())
	time.Sleep(time.Second)
	before := sink.packets.Load()

	second := startInbound(t, port, sink.conn.LocalAddr().String())
	defer second.Close()
	require.Eventually(t, func() bool { return sink.packets.Load() > before }, 60*time.Second, 100*time.Millisecond,
		"the flow was not redialled after the server restarted")
}
