package masquewg

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/masque-go"
	qgo "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/adapter/outbound"
	sbdialer "github.com/spaiter/spaiter-vpn/core/common/dialer"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
	"github.com/spaiter/spaiter-vpn/core/transport/awg"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.MASQUEWGOutboundOptions](registry, C.TypeMASQUEWG, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	ctx        context.Context
	logger     log.ContextLogger
	options    option.MASQUEWGOutboundOptions
	serverName string
	serverAddr string
	template   *uritemplate.Template
	tlsConfig  *tls.Config
	dialer     N.Dialer
	bind       *masqueBind
	device     *awg.Device
	dnsRouter  adapter.DNSRouter

	mu       sync.Mutex
	started  bool
	cancel   context.CancelFunc
	loopDone chan struct{}
	flow     net.PacketConn
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MASQUEWGOutboundOptions) (adapter.Outbound, error) {
	if options.Server == "" || options.ServerPort == 0 {
		return nil, E.New("masque-wg: server and server_port are required")
	}
	if options.PrivateKey == "" || options.PeerPublicKey == "" {
		return nil, E.New("masque-wg: private_key and peer_public_key are required")
	}
	if len(options.LocalAddress) == 0 {
		return nil, E.New("masque-wg: local_address is required")
	}
	path := options.Path
	if path == "" {
		path = defaultPath
	}
	serverName := ""
	insecure := false
	if options.TLS != nil {
		serverName = options.TLS.ServerName
		insecure = options.TLS.Insecure
	}
	if serverName == "" {
		serverName = options.Server
	}
	tmpl := uritemplate.MustNew(fmt.Sprintf("https://%s:%d%s?h={target_host}&p={target_port}",
		serverName, options.ServerPort, path))
	outerDialer, err := sbdialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, E.Cause(err, "masque-wg: create outer dialer")
	}

	ipc, err := genIpc(options)
	if err != nil {
		return nil, err
	}
	mtu := options.MTU
	if mtu == 0 {
		mtu = 1280
	}
	bind := newMasqueBind()
	dev, err := awg.NewDevice(ctx, logger, nil, ipc, awg.DeviceOpts{
		Address: options.LocalAddress,
		MTU:     mtu,
		Context: ctx,
		Bind:    bind,
	})
	if err != nil {
		return nil, E.Cause(err, "masque-wg: create device")
	}

	return &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeMASQUEWG, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:        ctx,
		logger:     logger,
		options:    options,
		serverName: serverName,
		serverAddr: net.JoinHostPort(options.Server, fmt.Sprint(options.ServerPort)),
		template:   tmpl,
		tlsConfig: &tls.Config{
			ServerName:         serverName,
			NextProtos:         []string{http3.NextProtoH3},
			InsecureSkipVerify: insecure,
		},
		dialer:    outerDialer,
		bind:      bind,
		device:    dev,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
	}, nil
}

// PostStart brings the WireGuard device up and leaves the MASQUE flow to a
// background loop, as the other endpoints do with their peers: a server that is
// unreachable now must not stop the whole core, and one that goes away later is
// redialled rather than leaving the device deaf. //H
func (o *Outbound) PostStart() error {
	if err := o.device.Start(adapter.StartStateStart); err != nil {
		return E.Cause(err, "masque-wg: start wireguard device")
	}
	ctx, cancel := context.WithCancel(o.ctx)
	o.mu.Lock()
	o.started = true
	o.cancel = cancel
	o.loopDone = make(chan struct{})
	o.mu.Unlock()
	go o.connectLoop(ctx)
	return nil
}

const (
	minRedialDelay = time.Second
	maxRedialDelay = 30 * time.Second
	// dialTimeout bounds one attempt past the QUIC handshake, which has its own
	// timeout: a server that completes QUIC but never answers the CONNECT-UDP
	// request would otherwise hold the loop forever.
	dialTimeout = 20 * time.Second
)

func (o *Outbound) connectLoop(ctx context.Context) {
	defer close(o.loopDone)
	delay := minRedialDelay
	for {
		flow, err := o.connect(ctx)
		if ctx.Err() != nil {
			if flow != nil {
				flow.Close()
			}
			return
		}
		if err != nil {
			o.logger.Error(err, "; retrying in ", delay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			delay = min(delay*2, maxRedialDelay)
			continue
		}
		delay = minRedialDelay
		o.mu.Lock()
		o.flow = flow
		o.mu.Unlock()
		f := o.bind.SetConn(flow)
		o.logger.Info("masque-wg: tunnel up (WireGuard over MASQUE CONNECT-UDP to ", o.serverAddr, ")")
		select {
		case <-ctx.Done():
			return
		case <-o.bind.lost:
		}
		o.bind.drop(f)
		o.mu.Lock()
		o.flow = nil
		o.mu.Unlock()
		flow.Close()
		o.logger.Warn("masque-wg: MASQUE flow to ", o.serverAddr, " lost, redialling")
	}
}

// connect dials one CONNECT-UDP flow. The returned connection also closes the
// outer UDP socket it rides on.
func (o *Outbound) connect(ctx context.Context) (net.PacketConn, error) {
	var (
		outerMu sync.Mutex
		outer   net.PacketConn
	)
	closeOuter := func() {
		outerMu.Lock()
		if outer != nil {
			outer.Close()
		}
		outerMu.Unlock()
	}
	tr := &masque.Transport{
		TLSClientConfig: o.tlsConfig,
		QUICConfig:      &qgo.Config{EnableDatagrams: true, InitialPacketSize: 1350},
		DialAddr: func(ctx context.Context, _ string, tlsConf *tls.Config, quicConf *qgo.Config) (*qgo.Conn, error) {
			udpAddr, err := net.ResolveUDPAddr(N.NetworkUDP, o.serverAddr)
			if err != nil {
				return nil, err
			}
			destination := M.ParseSocksaddrHostPort(udpAddr.IP.String(), uint16(udpAddr.Port))
			packetConn, err := o.dialer.ListenPacket(ctx, destination)
			if err != nil {
				return nil, err
			}
			outerMu.Lock()
			outer = packetConn
			outerMu.Unlock()
			return qgo.Dial(ctx, packetConn, udpAddr, tlsConf, quicConf)
		},
	}
	// The server locks the CONNECT-UDP target to its WG port, so the requested
	// target here is only used to expand the URI template; any valid host:port works.
	// The request lives as long as the flow, so it carries the loop's context and
	// the attempt is bounded by closing its socket instead.
	req, err := masque.NewRequest(ctx, o.template, "127.0.0.1:10863")
	if err != nil {
		return nil, E.Cause(err, "masque-wg: build request")
	}
	// Closing the outer socket is the one thing that interrupts every step of
	// the dial, so both the timeout and the outbound's Close end it that way.
	timer := time.AfterFunc(dialTimeout, closeOuter)
	stopOnClose := context.AfterFunc(ctx, closeOuter)
	defer stopOnClose()
	pconn, rsp, err := tr.Dial(req)
	if !timer.Stop() && err == nil {
		pconn.Close()
		err = E.New("timed out")
	}
	if err == nil && pconn == nil {
		err = E.New("dial returned nil conn")
	}
	if err == nil && rsp != nil && rsp.StatusCode/100 != 2 {
		pconn.Close()
		err = E.New("proxy rejected CONNECT-UDP, status ", rsp.StatusCode)
	}
	if err != nil {
		closeOuter()
		return nil, E.Cause(err, "masque-wg: establish CONNECT-UDP to ", o.serverAddr)
	}
	return &flowConn{PacketConn: pconn, closeOuter: closeOuter}, nil
}

// flowConn closes the outer socket together with the flow.
type flowConn struct {
	net.PacketConn
	closeOuter func()
}

func (c *flowConn) Close() error {
	err := c.PacketConn.Close()
	c.closeOuter()
	return err
}

func (o *Outbound) ready() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.started
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !o.ready() {
		return nil, E.New("masque-wg: not started")
	}
	// The embedded netstack cannot resolve names itself; resolve FQDNs via
	// sing-box's DNS router and dial by IP (like the awg endpoint). //H
	if destination.IsFqdn() {
		if o.dnsRouter == nil {
			return nil, E.New("masque-wg: cannot resolve ", destination.Fqdn, " (no DNS router)")
		}
		addrs, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, o.device, network, destination, addrs)
	}
	return o.device.DialContext(ctx, network, destination)
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !o.ready() {
		return nil, E.New("masque-wg: not started")
	}
	if destination.IsFqdn() {
		if o.dnsRouter == nil {
			return nil, E.New("masque-wg: cannot resolve ", destination.Fqdn, " (no DNS router)")
		}
		addrs, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		conn, _, err := N.ListenSerial(ctx, o.device, destination, addrs)
		return conn, err
	}
	return o.device.ListenPacket(ctx, destination)
}

func (o *Outbound) Close() error {
	o.mu.Lock()
	dev := o.device
	cancel := o.cancel
	loopDone := o.loopDone
	o.started = false
	o.cancel = nil
	o.mu.Unlock()
	if cancel != nil {
		cancel()
		<-loopDone
	}
	// The device first: its Close waits for the bind's receivers, which the
	// bind wakes itself, and its last packets still have a flow to go out on.
	if dev != nil {
		dev.Close()
	}
	o.mu.Lock()
	flow := o.flow
	o.flow = nil
	o.mu.Unlock()
	if flow != nil {
		flow.Close()
	}
	return nil
}

// genIpc renders the WireGuard/AmneziaWG IPC config for the embedded device. The
// endpoint is a placeholder (the masqueBind ignores it — there is one peer, the
// server WG behind the proxy). AWG obfuscation params must match the server. //H
func genIpc(o option.MASQUEWGOutboundOptions) (string, error) {
	priv, err := base64.StdEncoding.DecodeString(o.PrivateKey)
	if err != nil {
		return "", E.Cause(err, "decode private_key")
	}
	pub, err := base64.StdEncoding.DecodeString(o.PeerPublicKey)
	if err != nil {
		return "", E.Cause(err, "decode peer_public_key")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s", hex.EncodeToString(priv))
	a := o.Awg
	if a.Jc != 0 {
		fmt.Fprintf(&b, "\njc=%d", a.Jc)
	}
	if a.Jmin != 0 {
		fmt.Fprintf(&b, "\njmin=%d", a.Jmin)
	}
	if a.Jmax != 0 {
		fmt.Fprintf(&b, "\njmax=%d", a.Jmax)
	}
	if a.S1 != 0 {
		fmt.Fprintf(&b, "\ns1=%d", a.S1)
	}
	if a.S2 != 0 {
		fmt.Fprintf(&b, "\ns2=%d", a.S2)
	}
	if a.S3 != 0 {
		fmt.Fprintf(&b, "\ns3=%d", a.S3)
	}
	if a.S4 != 0 {
		fmt.Fprintf(&b, "\ns4=%d", a.S4)
	}
	for k, v := range map[string]string{"h1": a.H1, "h2": a.H2, "h3": a.H3, "h4": a.H4,
		"i1": a.I1, "i2": a.I2, "i3": a.I3, "i4": a.I4, "i5": a.I5} {
		if v != "" {
			fmt.Fprintf(&b, "\n%s=%s", k, v)
		}
	}
	fmt.Fprintf(&b, "\npublic_key=%s", hex.EncodeToString(pub))
	if o.PreSharedKey != "" {
		psk, err := base64.StdEncoding.DecodeString(o.PreSharedKey)
		if err != nil {
			return "", E.Cause(err, "decode pre_shared_key")
		}
		fmt.Fprintf(&b, "\npreshared_key=%s", hex.EncodeToString(psk))
	}
	// Placeholder endpoint (bind ignores it); WireGuard requires one to be set.
	b.WriteString("\nendpoint=127.0.0.1:1")
	ka := o.PersistentKeepaliveInterval
	if ka == 0 {
		ka = 25
	}
	fmt.Fprintf(&b, "\npersistent_keepalive_interval=%d", ka)
	b.WriteString("\nallowed_ip=0.0.0.0/0")
	b.WriteString("\nallowed_ip=::/0")
	return b.String(), nil
}
