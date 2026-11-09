//go:build with_gvisor

package awg

import (
	"context"
	"net"
	"net/netip"
	"os"
	"time"

	awgTun "github.com/amnezia-vpn/amneziawg-go/v3/tun"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	singTun "github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ tunAdapter = (*stackTun)(nil)

type stackTun struct {
	ctx          context.Context
	stack        *stack.Stack
	mtu          uint32
	events       chan awgTun.Event
	outbound     chan *stack.PacketBuffer
	done         chan struct{}
	dispatcher   stack.NetworkDispatcher
	inet4Address netip.Addr
	inet6Address netip.Addr
}

func newStackTun(ctx context.Context, address []netip.Prefix, mtu uint32, handler singTun.Handler, udpTimeout time.Duration) (tunAdapter, error) {
	dev := &stackTun{
		ctx:      ctx,
		mtu:      mtu,
		events:   make(chan awgTun.Event, 1),
		outbound: make(chan *stack.PacketBuffer, 256),
		done:     make(chan struct{}),
	}

	ipStack, err := singTun.NewGVisorStackWithOptions((*awgLinkEndpoint)(dev), stack.NICOptions{}, true)
	if err != nil {
		return nil, err
	}

	for _, prefix := range address {
		addr := singTun.AddressFromAddr(prefix.Addr())
		protoAddr := tcpip.ProtocolAddress{
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   addr,
				PrefixLen: prefix.Bits(),
			},
		}
		if prefix.Addr().Is4() {
			dev.inet4Address = prefix.Addr()
			protoAddr.Protocol = ipv4.ProtocolNumber
		} else {
			dev.inet6Address = prefix.Addr()
			protoAddr.Protocol = ipv6.ProtocolNumber
		}
		gErr := ipStack.AddProtocolAddress(singTun.DefaultNIC, protoAddr, stack.AddressProperties{})
		if gErr != nil {
			return nil, E.New("add address ", protoAddr.AddressWithPrefix, ": ", gErr.String())
		}
	}

	dev.stack = ipStack

	// Use sing-tun's TCP/UDP forwarders (with lazy connection pattern)
	ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, singTun.NewTCPForwarder(ctx, ipStack, handler).HandlePacket)
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, singTun.NewUDPForwarder(ctx, ipStack, handler, udpTimeout).HandlePacket)

	return dev, nil
}

func addrFromGvisor(addr tcpip.Address) netip.Addr {
	ip, _ := netip.AddrFromSlice(addr.AsSlice())
	return ip
}

// tunAdapter: Start
func (t *stackTun) Start() error {
	t.events <- awgTun.EventUp
	return nil
}

// tunAdapter: DialContext (for outbound connections through the tunnel)
func (t *stackTun) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination address")
	}
	addr := tcpip.FullAddress{
		NIC:  singTun.DefaultNIC,
		Port: destination.Port,
		Addr: singTun.AddressFromAddr(destination.Addr),
	}
	bind := tcpip.FullAddress{
		NIC: singTun.DefaultNIC,
	}
	var networkProtocol tcpip.NetworkProtocolNumber
	if destination.IsIPv4() {
		if !t.inet4Address.IsValid() {
			return nil, E.New("missing IPv4 local address")
		}
		networkProtocol = header.IPv4ProtocolNumber
		bind.Addr = singTun.AddressFromAddr(t.inet4Address)
	} else {
		if !t.inet6Address.IsValid() {
			return nil, E.New("missing IPv6 local address")
		}
		networkProtocol = header.IPv6ProtocolNumber
		bind.Addr = singTun.AddressFromAddr(t.inet6Address)
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return gonet.DialContextTCP(ctx, t.stack, addr, networkProtocol)
	case N.NetworkUDP:
		return gonet.DialUDP(t.stack, &bind, &addr, networkProtocol)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

// tunAdapter: ListenPacket (for outbound packet connections through the tunnel)
func (t *stackTun) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	bind := tcpip.FullAddress{
		NIC: singTun.DefaultNIC,
	}
	var networkProtocol tcpip.NetworkProtocolNumber
	if destination.IsIPv4() {
		if !t.inet4Address.IsValid() {
			return nil, E.New("missing IPv4 local address")
		}
		networkProtocol = header.IPv4ProtocolNumber
		bind.Addr = singTun.AddressFromAddr(t.inet4Address)
	} else {
		if !t.inet6Address.IsValid() {
			return nil, E.New("missing IPv6 local address")
		}
		networkProtocol = header.IPv6ProtocolNumber
		bind.Addr = singTun.AddressFromAddr(t.inet6Address)
	}
	return gonet.DialUDP(t.stack, &bind, nil, networkProtocol)
}

// awgTun.Device interface

func (t *stackTun) File() *os.File {
	return nil
}

func (t *stackTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case packet, ok := <-t.outbound:
		if !ok {
			return 0, os.ErrClosed
		}
		defer packet.DecRef()
		var copyN int
		for _, view := range packet.AsSlices() {
			copyN += copy(bufs[0][offset+copyN:], view)
		}
		sizes[0] = copyN
		return 1, nil
	case <-t.done:
		return 0, os.ErrClosed
	}
}

func (t *stackTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		b = b[offset:]
		if len(b) == 0 {
			continue
		}
		var networkProtocol tcpip.NetworkProtocolNumber
		switch header.IPVersion(b) {
		case header.IPv4Version:
			networkProtocol = header.IPv4ProtocolNumber
		case header.IPv6Version:
			networkProtocol = header.IPv6ProtocolNumber
		}
		packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(b),
		})
		t.dispatcher.DeliverNetworkPacket(networkProtocol, packetBuffer)
		packetBuffer.DecRef()
	}
	return len(bufs), nil
}

func (t *stackTun) MTU() (int, error) {
	return int(t.mtu), nil
}

func (t *stackTun) Name() (string, error) {
	return "sing-box-awg", nil
}

func (t *stackTun) Events() <-chan awgTun.Event {
	return t.events
}

func (t *stackTun) Close() error {
	close(t.done)
	close(t.events)
	t.stack.Close()
	for _, endpoint := range t.stack.CleanupEndpoints() {
		endpoint.Abort()
	}
	t.stack.Wait()
	return nil
}

func (t *stackTun) BatchSize() int {
	return 1
}

// Link endpoint for the gvisor stack

var _ stack.LinkEndpoint = (*awgLinkEndpoint)(nil)

type awgLinkEndpoint stackTun

func (ep *awgLinkEndpoint) MTU() uint32 {
	return ep.mtu
}

func (ep *awgLinkEndpoint) SetMTU(mtu uint32) {
}

func (ep *awgLinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (ep *awgLinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (ep *awgLinkEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
}

func (ep *awgLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (ep *awgLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	ep.dispatcher = dispatcher
}

func (ep *awgLinkEndpoint) IsAttached() bool {
	return ep.dispatcher != nil
}

func (ep *awgLinkEndpoint) Wait() {
}

func (ep *awgLinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (ep *awgLinkEndpoint) AddHeader(buffer *stack.PacketBuffer) {
}

func (ep *awgLinkEndpoint) ParseHeader(ptr *stack.PacketBuffer) bool {
	return true
}

func (ep *awgLinkEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	for _, packetBuffer := range list.AsSlice() {
		packetBuffer.IncRef()
		select {
		case <-ep.done:
			return 0, &tcpip.ErrClosedForSend{}
		case ep.outbound <- packetBuffer:
		}
	}
	return list.Len(), nil
}

func (ep *awgLinkEndpoint) Close() {
}

func (ep *awgLinkEndpoint) SetOnCloseAction(f func()) {
}
