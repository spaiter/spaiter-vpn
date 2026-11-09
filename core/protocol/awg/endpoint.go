package awg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	singTun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/adapter/endpoint"
	"github.com/spaiter/spaiter-vpn/core/common/dialer"
	"github.com/spaiter/spaiter-vpn/core/common/monitoring"
	"github.com/spaiter/spaiter-vpn/core/constant"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"
	"github.com/spaiter/spaiter-vpn/core/transport/awg"
	"go4.org/netipx"
)

// Mirrors device.HeaderCipherNonceSize in amneziawg-go/v3: the header cipher
// takes its nonce out of the S1-S4 padding. //H awg3
const awgHeaderProtectionMinPadding = 12

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register(registry, constant.TypeAwg, NewEndpoint)
}

type Endpoint struct {
	*awg.Device
	endpoint.Adapter
	address   []netip.Prefix
	router    adapter.Router
	logger    log.ContextLogger
	dnsRouter adapter.DNSRouter
	started   bool
	ctx       context.Context
	// peerNames is swapped atomically: ReloadPeers can replace it while
	// connection handlers are reading it. //H
	peerNames atomic.Pointer[peerNameTable]
	peerState *peerState //H peers currently programmed into the device
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AwgEndpointOptions) (adapter.Endpoint, error) {
	if options.MTU == 0 {
		options.MTU = 1408
	}

	options.UDPFragmentDefault = true
	// Check if any peer has a domain address
	remoteIsDomain := common.Any(options.Peers, func(peer option.AwgPeerOptions) bool {
		return !M.ParseAddr(peer.Address).IsValid()
	})
	dial, err := dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   remoteIsDomain,
		ResolverOnDetour: true,
		DirectOutbound:   true,
	})
	if err != nil {
		return nil, err
	}

	var allowedPrefixBuilder netipx.IPSetBuilder
	var excludedPrefixBuilder netipx.IPSetBuilder
	for _, peer := range options.Peers {
		for _, prefix := range peer.AllowedIPs {
			allowedPrefixBuilder.AddPrefix(prefix)
		}

		if addr, err := netip.ParseAddr(peer.Address); err == nil {
			excludedPrefixBuilder.Add(addr)
		}
	}
	allowedIps, err := allowedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	excludedIps, err := excludedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}

	// Create peer resolver function for domain endpoints
	// Always use system resolver for peer endpoints because:
	// 1. VPN server must be resolved before VPN tunnel is established
	// 2. dnsRouter may not be fully initialized at this stage
	var resolvePeer func(domain string) (netip.Addr, error)
	if remoteIsDomain {
		resolvePeer = func(domain string) (netip.Addr, error) {
			addrs, lookupErr := net.DefaultResolver.LookupNetIP(ctx, "ip", domain)
			if lookupErr != nil {
				return netip.Addr{}, lookupErr
			}
			return addrs[0], nil
		}
	}

	ipc, err := genIpcConfig(options, resolvePeer)
	if err != nil {
		return nil, err
	}

	logger.Debug("AWG IPC config:\n", ipc)

	ep := &Endpoint{
		Adapter:   endpoint.NewAdapterWithDialerOptions("awg", tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		address:   options.Address,
		router:    router,
		logger:    logger,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
		ctx:       ctx,
		peerState: newPeerState(options.Peers),
	}
	ep.peerNames.Store(newPeerNameTable(options.Peers))

	dev, err := awg.NewDevice(ctx, logger, dial, ipc, awg.DeviceOpts{
		UseIntegratedTun: options.UseIntegratedTun,
		Address:          options.Address,
		AllowedIps:       allowedIps.Prefixes(),
		ExcludedIps:      excludedIps.Prefixes(),
		MTU:              options.MTU,
		Handler:          ep,
		UDPTimeout:       constant.UDPTimeout,
		Context:          ctx,
	})
	if err != nil {
		return nil, err
	}
	ep.Device = dev

	return ep, nil
}

func genIpcConfig(opts option.AwgEndpointOptions, resolvePeer func(domain string) (netip.Addr, error)) (string, error) {
	privateKeyBytes, err := base64.StdEncoding.DecodeString(opts.PrivateKey)
	if err != nil {
		return "", err
	}
	s := "private_key=" + hex.EncodeToString(privateKeyBytes)
	if opts.ListenPort != 0 {
		s += "\nlisten_port=" + format.ToString(opts.ListenPort)
	}
	awg := opts.Awg
	if awg.Jc != 0 {
		s += "\njc=" + format.ToString(awg.Jc)
	}
	if awg.Jmin != 0 {
		s += "\njmin=" + format.ToString(awg.Jmin)
	}
	if awg.Jmax != 0 {
		s += "\njmax=" + format.ToString(awg.Jmax)
	}
	if awg.S1 != 0 {
		s += "\ns1=" + format.ToString(awg.S1)
	}
	if awg.S2 != 0 {
		s += "\ns2=" + format.ToString(awg.S2)
	}
	if awg.S3 != 0 {
		s += "\ns3=" + format.ToString(awg.S3)
	}
	if awg.S4 != 0 {
		s += "\ns4=" + format.ToString(awg.S4)
	}
	if awg.H1 != "" {
		s += "\nh1=" + awg.H1
	}
	if awg.H2 != "" {
		s += "\nh2=" + awg.H2
	}
	if awg.H3 != "" {
		s += "\nh3=" + awg.H3
	}
	if awg.H4 != "" {
		s += "\nh4=" + awg.H4
	}
	if awg.I1 != "" {
		s += "\ni1=" + awg.I1
	}
	if awg.I2 != "" {
		s += "\ni2=" + awg.I2
	}
	if awg.I3 != "" {
		s += "\ni3=" + awg.I3
	}
	if awg.I4 != "" {
		s += "\ni4=" + awg.I4
	}
	if awg.I5 != "" {
		s += "\ni5=" + awg.I5
	}
	// AWG 3.x. The UAPI takes the header protection key as hex, while the
	// Amnezia .conf spells it base64 — same split as private_key above. //H awg3
	if awg.HeaderProtectionKey != "" {
		// Header protection draws its per-packet nonce from the S1-S4 crypto
		// padding, so anything shorter than the ChaCha20 nonce silently breaks
		// the handshake instead of erroring out. Fail loudly here.
		for _, sv := range [][2]any{
			{"s1", awg.S1}, {"s2", awg.S2}, {"s3", awg.S3}, {"s4", awg.S4},
		} {
			if sv[1].(int) < awgHeaderProtectionMinPadding {
				return "", E.New("awg: header_protection_key requires ", sv[0], " >= ", awgHeaderProtectionMinPadding, ", got ", sv[1])
			}
		}
		headerKeyBytes, err := base64.StdEncoding.DecodeString(awg.HeaderProtectionKey)
		if err != nil {
			return "", E.Cause(err, "decode header_protection_key")
		}
		s += "\nheader_protection_key=" + hex.EncodeToString(headerKeyBytes)
	}
	for _, kv := range [][2]string{
		{"content_padding_addition", awg.ContentPaddingAddition},
		{"rekey_after_time", awg.RekeyAfterTime},
		{"rekey_timeout", awg.RekeyTimeout},
		{"reject_after_time", awg.RejectAfterTime},
		{"keepalive_timeout", awg.KeepaliveTimeout},
		{"max_handshake_attempts", awg.MaxHandshakeAttempts},
	} {
		if kv[1] != "" {
			s += "\n" + kv[0] + "=" + kv[1]
		}
	}
	if awg.RandomTrailers {
		s += "\nrandom_trailers=true"
	}
	if awg.DisableCookies {
		s += "\ndisable_cookies=true"
	}

	for _, peer := range opts.Peers {
		peerConfig, err := genIpcPeer(peer, resolvePeer)
		if err != nil {
			return "", err
		}
		s += peerConfig
	}
	return s, nil
}

// genIpcPeer renders one peer's UAPI lines, each prefixed with a newline.
// Split out of genIpcConfig so ReloadPeers can emit the same wire format for a
// single peer without rebuilding the whole device config. //H
func genIpcPeer(peer option.AwgPeerOptions, resolvePeer func(domain string) (netip.Addr, error)) (string, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
	if err != nil {
		return "", err
	}
	s := "\npublic_key=" + hex.EncodeToString(publicKeyBytes)
	if peer.PresharedKey != "" {
		presharedKeyBytes, err := base64.StdEncoding.DecodeString(peer.PresharedKey)
		if err != nil {
			return "", err
		}
		s += "\npreshared_key=" + hex.EncodeToString(presharedKeyBytes)
	}
	if peer.Address != "" && peer.Port != 0 {
		// Resolve domain to IP if necessary
		endpointAddr := peer.Address
		if addr := M.ParseAddr(peer.Address); !addr.IsValid() {
			// It's a domain, resolve it
			if resolvePeer == nil {
				return "", E.New("peer address is a domain but no resolver provided: ", peer.Address)
			}
			resolvedAddr, resolveErr := resolvePeer(peer.Address)
			if resolveErr != nil {
				return "", E.Cause(resolveErr, "resolve peer endpoint ", peer.Address)
			}
			endpointAddr = resolvedAddr.String()
		}
		s += "\nendpoint=" + endpointAddr + ":" + format.ToString(peer.Port)
	}
	if peer.PersistentKeepaliveInterval != 0 {
		s += "\npersistent_keepalive_interval=" + format.ToString(peer.PersistentKeepaliveInterval)
	}
	for _, allowedIp := range peer.AllowedIPs {
		s += "\nallowed_ip=" + allowedIp.String()
	}
	return s, nil
}

func (e *Endpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = e.Tag()
	metadata.InboundType = e.Type()
	metadata.InboundOptions.SniffEnabled = true
	metadata.Source = source
	metadata.User = e.peerNames.Load().Lookup(source.Addr) //H
	metadata.Destination = destination
	for _, addr := range e.address {
		if addr.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				metadata.Destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				metadata.Destination.Addr = netip.IPv6Loopback()
			}
			conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, metadata.Destination)
		}
	}
	e.logger.InfoContext(ctx, "inbound packet connection from ", source)
	e.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	e.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		e.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		e.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if destination.IsFqdn() {
		destinationAddresses, err := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, e.Device, network, destination, destinationAddresses)
	} else if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return e.Device.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	e.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsFqdn() {
		destinationAddresses, err := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		packetConn, _, err := N.ListenSerial(ctx, e.Device, destination, destinationAddresses)
		if err != nil {
			return nil, err
		}
		return packetConn, nil
	}
	return e.Device.ListenPacket(ctx, destination)
}

func (w *Endpoint) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) singTun.FlowVerdict {
	// Accept every flow so it is dispatched to NewConnectionEx / NewPacketConnectionEx
	// (routed through sing-box for sniffing + per-user stats). Zero value == ActionAccept.
	return singTun.FlowVerdict{}
}

func (w *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = w.Tag()
	metadata.InboundType = w.Type()
	metadata.InboundOptions.SniffEnabled = true
	metadata.Source = source
	metadata.User = w.peerNames.Load().Lookup(source.Addr) //H
	for _, addr := range w.address {
		if addr.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				destination.Addr = netip.IPv6Loopback()
			}
			break
		}
	}
	metadata.Destination = destination
	w.logger.InfoContext(ctx, "inbound connection from ", source)
	w.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	w.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (o *Endpoint) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateStart:
		return o.Device.Start(stage)
	case adapter.StartStatePostStart:
		go o.readyChecker()
	}
	return nil
}

func (w *Endpoint) readyChecker() {
	for i := 0; i < 10; i++ {
		if w.deviceReady() {
			break
		}
		select {
		case <-w.ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
	w.started = true
	if m := monitoring.Get(w.ctx); m != nil {
		m.TestNow(w.Tag())
	}
}

func (w *Endpoint) deviceReady() bool {
	return w.Device != nil && w.Device.IsUnderLoad()
}

func (w *Endpoint) IsReady() bool {
	return w.started || w.deviceReady()
}

func (w *Endpoint) DisplayType() string {
	str := C.ProxyDisplayName(w.Type())
	if !w.IsReady() {
		str += " ⚠️ Connecting..."
	}
	return str
}
