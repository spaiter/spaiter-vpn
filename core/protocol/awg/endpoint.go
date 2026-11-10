package awg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/netip"
	"sync"        //H
	"sync/atomic" //H
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/peeruser"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/awg"
	singTun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
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
	peerUsers atomic.Pointer[peeruser.Users] //H: swapped by ReloadPeers (reload_peers.go)
	peerState *peerState                     //H: peers programmed into the device, see reload_peers.go
	router    adapter.Router
	logger    log.ContextLogger
	dnsRouter adapter.DNSRouter
	started   bool
	tracker   adapter.StatusTracker //H
	ctx       context.Context
	// H: see h_interface_update.go //H
	deviceStarted atomic.Bool  //H
	bindAccess    sync.Mutex   //H
	peers         *domainPeers //H: see h_domain_peer.go
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AwgEndpointOptions) (adapter.Endpoint, error) {
	if options.MTU == 0 {
		options.MTU = 1408
	}
	if options.Detour != "" && options.ListenPort != 0 { //H: a server listens itself, as WireGuard's
		return nil, E.New("`listen_port` is conflict with `detour`") //H
	} //H

	options.UDPFragmentDefault = true
	reserved, err := reservedOptions(options) //H
	if err != nil {                           //H
		return nil, err //H
	} //H
	fallback, err := peerFallback(options) //H
	if err != nil {                        //H
		return nil, err //H
	} //H
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

	// H: a peer given by a domain is resolved by the DNS router once the box started, not by the
	// system resolver here: see h_domain_peer.go //H
	ipcOptions, domainPeers, err := deferDomainPeers(options) //H
	if err != nil {                                           //H
		return nil, err //H
	} //H

	ipc, err := genIpcConfig(ipcOptions, nil) //H
	if err != nil {
		return nil, err
	}

	logger.Debug("AWG IPC config:\n", ipc)

	ep := &Endpoint{
		Adapter:   endpoint.NewAdapterWithDialerOptions("awg", tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		address:   options.Address,
		peerState: newPeerState(options.Peers), //H
		router:    router,
		logger:    logger,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
		ctx:       ctx,
		peers:     newDomainPeers(dial, domainPeers, len(options.Peers)), //H
	}
	ep.peerUsers.Store(newPeerUsers(options.Peers)) //H

	dev, err := awg.NewDevice(ctx, logger, dial, ipc, awg.DeviceOpts{
		UseIntegratedTun: options.UseIntegratedTun,
		Address:          options.Address,
		AllowedIps:       allowedIps.Prefixes(),
		ExcludedIps:      excludedIps.Prefixes(),
		MTU:              options.MTU,
		Peer:             singlePeer(options.Peers),                            //H: one packet connection to the peer
		Reserved:         reserved,                                             //H
		MTUDiscovery:     options.MTUDiscovery == nil || *options.MTUDiscovery, //H
		Fallback:         fallback,                                             //H
		ListenPort:       options.ListenPort,                                   //H
		PeerPending:      len(options.Peers) == 1 && len(domainPeers) == 1,     //H: see h_domain_peer.go
		Handler:          ep,                                                   // peers' flows go through the router: sniffing, per-user stats, XDP
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
	if err := applyMasquerade(&awg); err != nil { //H
		return "", err
	}
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
	// AmneziaWG 3.x
	// H: the Amnezia .conf (and our subscriptions) spell header_protection_key in base64, like
	// private_key; the UAPI takes hex. 64 hex digits are passed through for upstream configs. //H
	if awg.HeaderProtectionKey != "" { //H
		// Header protection draws its per-packet nonce from the S1-S4 padding; shorter padding
		// breaks the handshake silently, so fail loudly here. //H
		for _, sv := range []struct { //H
			name  string //H
			value int    //H
		}{{"s1", awg.S1}, {"s2", awg.S2}, {"s3", awg.S3}, {"s4", awg.S4}} { //H
			if sv.value < awgHeaderProtectionMinPadding { //H
				return "", E.New("awg: header_protection_key requires ", sv.name, " >= ", awgHeaderProtectionMinPadding, ", got ", sv.value) //H
			} //H
		} //H
		headerKey := awg.HeaderProtectionKey                                           //H
		if _, err := hex.DecodeString(headerKey); err != nil || len(headerKey) != 64 { //H
			headerKeyBytes, err := base64.StdEncoding.DecodeString(headerKey) //H
			if err != nil {                                                   //H
				return "", E.Cause(err, "decode header_protection_key") //H
			} //H
			headerKey = hex.EncodeToString(headerKeyBytes) //H
		} //H
		s += "\nheader_protection_key=" + headerKey //H
	} //H
	for _, setting := range []struct{ key, value string }{
		{"content_padding_addition", string(awg.ContentPaddingAddition)},
		{"rekey_after_time", string(awg.RekeyAfterTime)},
		{"rekey_timeout", string(awg.RekeyTimeout)},
		{"reject_after_time", string(awg.RejectAfterTime)},
		{"keepalive_timeout", string(awg.KeepaliveTimeout)},
		{"max_handshake_attempts", string(awg.MaxHandshakeAttempts)},
	} {
		if setting.value != "" {
			s += "\n" + setting.key + "=" + setting.value
		}
	}
	if awg.RandomTrailers {
		s += "\nrandom_trailers=true"
	}
	if awg.DisableCookies {
		s += "\ndisable_cookies=true"
	}

	for _, peer := range opts.Peers {
		peerConfig, err := genIpcPeer(peer, resolvePeer) //H
		if err != nil {                                  //H
			return "", err //H
		} //H
		s += peerConfig //H
	}
	return s, nil
}

// genIpcPeer renders one peer's UAPI lines, each prefixed with a newline. Split out of
// genIpcConfig so ReloadPeers can emit the same wire format for a single peer without
// rebuilding the whole device config. //H
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
		s += "\nendpoint=" + net.JoinHostPort(endpointAddr, format.ToString(peer.Port)) // brackets an IPv6 address
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
	metadata.User = e.peerUsers.Load().Lookup(source.Addr) //H
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

// JudgeFlow accepts every flow so it is dispatched to NewConnectionEx / NewPacketConnectionEx
// and routed through sing-box (sniffing + per-user stats).
func (w *Endpoint) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) singTun.FlowVerdict {
	return singTun.FlowVerdict{Action: singTun.ActionAccept}
}

func (w *Endpoint) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	ctx := log.ContextWithNewID(w.ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = w.Tag()
	metadata.InboundType = w.Type()
	metadata.Network = N.NetworkUDP
	metadata.Source = source
	metadata.User = w.peerUsers.Load().Lookup(source.Addr)
	metadata.Destination = destination
	metadata.Protocol = constant.ProtocolDNS
	w.logger.InfoContext(ctx, "inbound DNS packet from ", source)
	w.router.HijackDNSPacket(ctx, payload, writer, metadata)
}

func (w *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = w.Tag()
	metadata.InboundType = w.Type()
	metadata.InboundOptions.SniffEnabled = true
	metadata.Source = source
	metadata.User = w.peerUsers.Load().Lookup(source.Addr) //H
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

func (o *Endpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(o.Close) // H: closed with the box
	}
	switch stage {
	case adapter.StartStateStart:
		err := o.Device.Start(stage)      //H
		o.deviceStarted.Store(err == nil) //H
		return err                        //H
	case adapter.StartStatePostStart:
		o.startResolvingPeers() //H: the DNS router is ready now
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

func (w *Endpoint) Status() adapter.Status { //H
	return w.tracker.Status(w.started || w.deviceReady()) //H
} //H

// singlePeer is the address of the only peer, when there is one with an IP address. //H
func singlePeer(peers []option.AwgPeerOptions) netip.AddrPort {
	if len(peers) != 1 {
		return netip.AddrPort{}
	}
	address := M.ParseAddr(peers[0].Address)
	if !address.IsValid() || peers[0].Port == 0 {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(address, peers[0].Port)
}
