package mtproto

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/9seconds/mtg/v2/essentials"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// mtgNetwork implements github.com/9seconds/mtg/v2/mtglib.Network on top of a
// sing-box dialer, so that all upstream connections mtg makes to Telegram data
// centers go through sing-box routing/outbounds. //H
type mtgNetwork struct {
	ctx    context.Context
	dialer N.Dialer
	// Without a dialer, connections are handed to the router as the user
	// this network serves, from the client mtg is relaying for. //H
	router adapter.Router
	tag    string
	user   string
}

func (n *mtgNetwork) Dial(network, address string) (essentials.Conn, error) {
	return n.DialContext(n.ctx, network, address)
}

func (n *mtgNetwork) DialContext(ctx context.Context, network, address string) (essentials.Conn, error) {
	if n.dialer == nil {
		return n.route(ctx, address), nil
	}
	conn, err := n.dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
	if err != nil {
		return nil, err
	}
	return essentialsConn{Conn: conn}, nil
}

// route hands one end of a pipe to the router as a connection from the client
// to address, and gives mtg the other. mtg's stream context names the client.
func (n *mtgNetwork) route(ctx context.Context, address string) essentials.Conn {
	local, remote := net.Pipe()
	metadata := adapter.InboundContext{
		Inbound:     n.tag,
		InboundType: C.TypeMTProto,
		User:        n.user,
		Destination: M.ParseSocksaddr(address),
	}
	if client, ok := ctx.(interface{ ClientIP() net.IP }); ok {
		if ip, ok := netip.AddrFromSlice(client.ClientIP()); ok {
			metadata.Source = M.SocksaddrFrom(ip.Unmap(), 0)
		}
	}
	go n.router.RouteConnectionEx(n.ctx, remote, metadata, N.OnceClose(func(error) { remote.Close() }))
	return essentialsConn{Conn: routedConn{Conn: local, remote: tcpAddr(metadata.Destination)}}
}

// routedConn is mtg's end of a routed pipe. mtg asserts that a data-centre
// connection's RemoteAddr is a *net.TCPAddr and panics otherwise, so the pipe's
// own address is replaced by the destination's. //H
type routedConn struct {
	net.Conn
	remote *net.TCPAddr
}

func (c routedConn) RemoteAddr() net.Addr { return c.remote }
func (c routedConn) LocalAddr() net.Addr  { return &net.TCPAddr{} }

func tcpAddr(destination M.Socksaddr) *net.TCPAddr {
	addr := &net.TCPAddr{Port: int(destination.Port)}
	if destination.IsIP() {
		addr.IP = destination.Addr.Unmap().AsSlice()
	}
	return addr
}

func (n *mtgNetwork) MakeHTTPClient(dialFunc func(ctx context.Context, network, address string) (essentials.Conn, error)) *http.Client {
	if dialFunc == nil {
		dialFunc = n.DialContext
	}
	return &http.Client{
		Timeout: time.Minute,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialFunc(ctx, network, address)
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}
}

func (n *mtgNetwork) NativeDialer() *net.Dialer {
	return &net.Dialer{}
}
