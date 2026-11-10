package profile

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/spaiter/spaiter-vpn/internal/keys"
)

// Bundle is the result of generation: a config and the secrets that went into
// it. They are produced together so the two can never disagree.
type Bundle struct {
	Options option.Options
	Secrets Secrets
}

// Generate builds a complete sing-box configuration from the spec, minting
// every key and password it needs.
func Generate(spec Spec) (*Bundle, error) { return generate(spec, nil) }

// generate renders the configuration, reusing prev's credentials where they
// exist. prev is nil for a first install; see Regenerate for why a migration
// must not mint fresh ones.
func generate(spec Spec, prev *Secrets) (*Bundle, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}

	enabled := spec.EnabledProtocols()
	secrets := Secrets{
		Endpoints: map[Protocol]EndpointSecrets{},
		Deployment: DeploymentFacts{
			Ports:              map[Protocol]uint16{},
			RealitySNI:         spec.RealityHandshakeServer,
			ShadowTLSSNI:       spec.ShadowTLSHandshakeServer,
			ShadowTLSVersion:   spec.ShadowTLSVersion,
			SnellVersion:       spec.SnellVersion,
			ShadowsocksMethod:  spec.ShadowsocksMethod,
			MTProtoFrontDomain: spec.MTProtoFrontDomain,
		},
	}
	for _, p := range enabled {
		secrets.Deployment.Ports[p] = spec.Ports[p]
	}
	if spec.Tier == TierB {
		secrets.TierB.Facts.Domain = spec.Domain
		secrets.TierB.Facts.CertSource = spec.Certs.Source
		secrets.TierB.Facts.TUICCongestionControl = spec.TUICCongestionControl
	}

	var err error
	if secrets.ClashAPISecret = spec.ClashAPISecret; secrets.ClashAPISecret == "" && prev != nil {
		// The bot and the self-test authenticate with this; reissuing it turns
		// every management call into a 401 until they are reconfigured.
		secrets.ClashAPISecret = prev.ClashAPISecret
	}
	if secrets.ClashAPISecret == "" {
		if secrets.ClashAPISecret, err = keys.ClashAPISecret(); err != nil {
			return nil, fmt.Errorf("generate clash API secret: %w", err)
		}
	}

	for _, user := range spec.Users {
		// By name, not by position: the list may have gained or lost entries
		// since the credentials were issued, and matching by index would hand
		// one user another user's keys.
		if existing, ok := prev.user(user); ok {
			secrets.Users = append(secrets.Users, existing.clone())
			continue
		}
		secrets.Users = append(secrets.Users, UserSecrets{
			Name:  user,
			Peers: map[Protocol]PeerSecrets{},
		})
	}

	options := option.Options{
		Log: &option.LogOptions{
			Level:     spec.LogLevel,
			Output:    spec.LogOutput,
			Timestamp: true,
		},
		Outbounds: []option.Outbound{{
			Type: C.TypeDirect,
			Tag:  "direct",
			// A bare direct outbound: this server is the exit, so there is
			// nothing to chain to.
			Options: &option.DirectOutboundOptions{},
		}},
		Route:        routeOptions(spec),
		Experimental: experimentalOptions(spec, secrets.ClashAPISecret),
	}
	if svc := xdpService(spec); svc != nil {
		options.Services = []option.Service{*svc}
	}

	// One shared certificate provider for every certificate-bearing inbound,
	// declared before them. See certProviderTag.
	if spec.needsCertificateSource() {
		if provider := spec.Certs.provider(spec.Domain); provider != nil {
			options.CertificateProviders = []option.CertificateProvider{*provider}
		}
	}

	for _, p := range enabled {
		if p.IsWireGuard() {
			endpoint, err := buildEndpoint(spec, p, &secrets, prev)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			options.Endpoints = append(options.Endpoints, *endpoint)
			continue
		}
		build := buildInbound
		if builtWithTierB(p) {
			build = buildTierBInbound
		}
		inbound, err := build(spec, p, &secrets, prev)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		options.Inbounds = append(options.Inbounds, *inbound)
	}

	return &Bundle{Options: options, Secrets: secrets}, nil
}

func routeOptions(spec Spec) *option.RouteOptions {
	// Two rules, in this order and no other: sniff first so that the protocol
	// is known, then reject what the sniffer identified. Note that route rules
	// cannot be hot-applied — the clash API's applyConfig handles inbounds and
	// endpoints only and ignores route.rules silently — so changing these
	// needs a restart, not an apply.
	return &option.RouteOptions{
		Rules: []option.Rule{
			{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeSniff,
						SniffOptions: option.RouteActionSniff{
							Sniffer: badoption.Listable[string]{C.ProtocolBitTorrent},
							Timeout: badoption.Duration(spec.SniffTimeout),
						},
					},
				},
			},
			{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						Protocol: badoption.Listable[string]{C.ProtocolBitTorrent},
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeReject,
						RejectOptions: option.RejectActionOptions{
							Method:      C.RuleActionRejectMethodDrop,
							XDPBlock:    true,
							BanDuration: badoption.Duration(spec.BanDuration),
						},
					},
				},
			},
		},
		Final: "direct",
	}
}

func experimentalOptions(spec Spec, secret string) *option.ExperimentalOptions {
	return &option.ExperimentalOptions{
		ClashAPI: &option.ClashAPIOptions{
			ExternalController: spec.ClashAPIListen,
			Secret:             secret,
			ConfigOutputPath:   spec.ConfigOutputPath,
		},
	}
}

func xdpService(spec Spec) *option.Service {
	if len(spec.XDPInterfaces) == 0 {
		return nil
	}
	logBlocked := true
	return &option.Service{
		Type: C.TypeXDPBlocker,
		Tag:  "xdp",
		Options: &option.XDPBlockerServiceOptions{
			Interfaces:      badoption.Listable[string](spec.XDPInterfaces),
			CleanupInterval: badoption.Duration(time.Minute),
			LogBlocked:      &logBlocked,
		},
	}
}

func buildInbound(spec Spec, p Protocol, secrets *Secrets, prev *Secrets) (*option.Inbound, error) {
	port := spec.Ports[p]

	switch p {
	case VLESSReality:
		// Preserved as one unit. The public key and the short_id are both in
		// every client's config, and the transport path is derived from the
		// short_id — so reissuing any of them without the others produces a
		// server no existing client can complete a handshake with.
		if prev != nil && prev.Reality.PrivateKey != "" {
			secrets.Reality = prev.Reality
			secrets.Deployment.RealityTransportPath = prev.Deployment.RealityTransportPath
		} else {
			reality, err := keys.NewX25519()
			if err != nil {
				return nil, fmt.Errorf("generate reality keypair: %w", err)
			}
			shortID, err := keys.ShortID()
			if err != nil {
				return nil, fmt.Errorf("generate reality short_id: %w", err)
			}
			secrets.Reality = RealitySecrets{
				PrivateKey: reality.PrivateURL(),
				PublicKey:  reality.PublicURL(),
				ShortID:    shortID,
			}
			secrets.Deployment.RealityTransportPath = "/" + pathSuffix(shortID)
		}
		realityPrivateKey := secrets.Reality.PrivateKey
		shortID := secrets.Reality.ShortID
		realityTransportPath := secrets.Deployment.RealityTransportPath

		users := make([]option.VLESSUser, 0, len(spec.Users))
		for i := range secrets.Users {
			if secrets.Users[i].VLESSRealityUUID == "" && !spec.mayMint(secrets.Users[i].Name, SlotVLESSReality) {
				continue
			}
			uuid, err := reuseOrMint(&secrets.Users[i].VLESSRealityUUID, "vless UUID", keys.UUID)
			if err != nil {
				return nil, err
			}
			users = append(users, option.VLESSUser{Name: secrets.Users[i].Name, UUID: uuid})
		}

		return &option.Inbound{
			Type: C.TypeVLESS,
			Tag:  string(p),
			Options: &option.VLESSInboundOptions{
				ListenOptions: listenOn(spec.PublicListen, port),
				Users:         users,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &option.InboundTLSOptions{
						Enabled: true,
						// The server name must equal the borrowed host: the
						// client sends it as SNI and Reality forwards
						// non-authenticated handshakes there verbatim.
						ServerName: spec.RealityHandshakeServer,
						Reality: &option.InboundRealityOptions{
							Enabled: true,
							Handshake: option.InboundRealityHandshakeOptions{
								ServerOptions: option.ServerOptions{
									Server:     spec.RealityHandshakeServer,
									ServerPort: spec.RealityHandshakePort,
								},
							},
							PrivateKey: realityPrivateKey,
							ShortID:    badoption.Listable[string]{shortID},
						},
					},
				},
				Transport: &option.V2RayTransportOptions{
					Type: C.V2RayTransportTypeHTTP,
					HTTPOptions: option.V2RayHTTPOptions{
						Path:        realityTransportPath,
						IdleTimeout: badoption.Duration(5 * time.Minute),
					},
				},
			},
		}, nil

	case Shadowsocks:
		keyLen, err := shadowsocksKeyLength(spec.ShadowsocksMethod)
		if err != nil {
			return nil, err
		}
		if prev != nil && prev.Shadowsocks.Password != "" && prev.Shadowsocks.Method == spec.ShadowsocksMethod {
			// Only when the method matches: a password is a key of a
			// method-specific length, so carrying it across a method change
			// would produce an inbound that cannot start.
			secrets.Shadowsocks = prev.Shadowsocks
		}
		password, err := reuseOrMint(&secrets.Shadowsocks.Password, "shadowsocks password", func() (string, error) { return keys.Base64(keyLen) })
		if err != nil {
			return nil, err
		}
		secrets.Shadowsocks.Method = spec.ShadowsocksMethod

		return &option.Inbound{
			Type: C.TypeShadowsocks,
			Tag:  string(p),
			Options: &option.ShadowsocksInboundOptions{
				// Bound to loopback on purpose: this inbound is reachable only
				// through the shadowtls detour, never from the internet.
				ListenOptions: listenOn(spec.ShadowsocksListen, port),
				Method:        spec.ShadowsocksMethod,
				Password:      password,
				Multiplex:     &option.InboundMultiplexOptions{Enabled: true},
			},
		}, nil

	case ShadowTLS:
		users := make([]option.ShadowTLSUser, 0, len(spec.Users))
		for i := range secrets.Users {
			if secrets.Users[i].ShadowTLSPassword == "" && !spec.mayMint(secrets.Users[i].Name, SlotShadowTLS) {
				continue
			}
			password, err := reuseOrMint(&secrets.Users[i].ShadowTLSPassword, "shadowtls password", func() (string, error) { return keys.Password(16) })
			if err != nil {
				return nil, err
			}
			users = append(users, option.ShadowTLSUser{Name: secrets.Users[i].Name, Password: password})
		}

		return &option.Inbound{
			Type: C.TypeShadowTLS,
			Tag:  string(p),
			Options: &option.ShadowTLSInboundOptions{
				ListenOptions: listenOn(spec.PublicListen, port),
				Version:       spec.ShadowTLSVersion,
				Users:         users,
				Handshake: option.ShadowTLSHandshakeOptions{
					ServerOptions: option.ServerOptions{
						Server:     spec.ShadowTLSHandshakeServer,
						ServerPort: spec.ShadowTLSHandshakePort,
					},
				},
			},
		}, nil

	case Snell:
		if prev != nil {
			secrets.Snell.PSK = prev.Snell.PSK
		}
		psk, err := reuseOrMint(&secrets.Snell.PSK, "snell PSK", func() (string, error) { return keys.Password(16) })
		if err != nil {
			return nil, err
		}
		secrets.Snell.Version = spec.SnellVersion

		users := make([]option.SnellUser, 0, len(spec.Users))
		for i := range secrets.Users {
			if secrets.Users[i].SnellUserKey == "" && !spec.mayMint(secrets.Users[i].Name, SlotSnell) {
				continue
			}
			userKey, err := reuseOrMint(&secrets.Users[i].SnellUserKey, "snell user key", func() (string, error) { return keys.Password(16) })
			if err != nil {
				return nil, err
			}
			users = append(users, option.SnellUser{Name: secrets.Users[i].Name, UserKey: userKey})
		}

		return &option.Inbound{
			Type: C.TypeSnell,
			Tag:  string(p),
			Options: &option.SnellInboundOptions{
				ListenOptions: listenOn(spec.PublicListen, port),
				Version:       spec.SnellVersion,
				PSK:           psk,
				Users:         users,
			},
		}, nil

	case Mieru:
		users := make([]option.MieruUser, 0, len(spec.Users))
		for i := range secrets.Users {
			if secrets.Users[i].MieruPassword == "" && !spec.mayMint(secrets.Users[i].Name, SlotMieru) {
				continue
			}
			password, err := reuseOrMint(&secrets.Users[i].MieruPassword, "mieru password", func() (string, error) { return keys.Password(16) })
			if err != nil {
				return nil, err
			}
			users = append(users, option.MieruUser{Name: secrets.Users[i].Name, Password: password})
		}

		return &option.Inbound{
			Type: C.TypeMieru,
			Tag:  string(p),
			Options: &option.MieruInboundOptions{
				ListenOptions: listenOn(spec.PublicListen, port),
				Users:         users,
				// mieru carries its own port table in addition to
				// listen_port; without it the inbound does not bind.
				PortBindings: []option.MieruPortBinding{{Protocol: "TCP", Port: port}},
			},
		}, nil

	case MTProto:
		if !spec.MTProtoPerUser {
			// The shared secret, for a core that predates per-user MTProto:
			// preserved while its front domain, which it encodes, is unchanged.
			if prev != nil && prev.MTProto.FrontDomain == spec.MTProtoFrontDomain {
				secrets.MTProto.Secret = prev.MTProto.Secret
			}
			secret, err := reuseOrMint(&secrets.MTProto.Secret, "mtproto secret", func() (string, error) {
				return keys.MTProtoFakeTLSSecret(spec.MTProtoFrontDomain)
			})
			if err != nil {
				return nil, err
			}
			secrets.MTProto.FrontDomain = spec.MTProtoFrontDomain
			for i := range secrets.Users {
				secrets.Users[i].MTProtoSecret = ""
			}
			return &option.Inbound{
				Type: C.TypeMTProto,
				Tag:  string(p),
				Options: &option.MTProtoInboundOptions{
					ListenOptions: listenOn(spec.PublicListen, port),
					Secret:        secret,
				},
			}, nil
		}
		// Per user: the legacy shared secret survives only where it was
		// already handed out, and only while its front domain is unchanged.
		// A new deployment has none.
		secrets.MTProto.Secret = ""
		if prev != nil && prev.MTProto.FrontDomain == spec.MTProtoFrontDomain && !spec.RetireSharedMTProto {
			secrets.MTProto.Secret = prev.MTProto.Secret
		}
		secrets.MTProto.FrontDomain = spec.MTProtoFrontDomain

		users := make([]option.MTProtoUser, 0, len(spec.Users))
		for i := range secrets.Users {
			user := &secrets.Users[i]
			// A secret for another front domain answers nobody, so it is
			// reissued like an empty slot.
			if domain, ok := mtprotoFrontDomain(user.MTProtoSecret); user.MTProtoSecret != "" && (!ok || domain != spec.MTProtoFrontDomain) {
				user.MTProtoSecret = ""
			}
			if user.MTProtoSecret == "" && !spec.mayMint(user.Name, SlotMTProto) {
				continue
			}
			secret, err := reuseOrMint(&user.MTProtoSecret, "mtproto secret", func() (string, error) {
				return keys.MTProtoFakeTLSSecret(spec.MTProtoFrontDomain)
			})
			if err != nil {
				return nil, err
			}
			users = append(users, option.MTProtoUser{Name: user.Name, Secret: secret})
		}
		if len(users) == 0 && secrets.MTProto.Secret == "" {
			return nil, fmt.Errorf("%s has no user and no shared secret", p)
		}

		return &option.Inbound{
			Type: C.TypeMTProto,
			Tag:  string(p),
			Options: &option.MTProtoInboundOptions{
				ListenOptions: listenOn(spec.PublicListen, port),
				Secret:        secrets.MTProto.Secret,
				Users:         users,
			},
		}, nil

	case VLESSWSCDN:
		users := make([]option.VLESSUser, 0, len(spec.Users))
		for i := range secrets.Users {
			if secrets.Users[i].VLESSWSCDNUUID == "" && !spec.mayMint(secrets.Users[i].Name, SlotVLESSWSCDN) {
				continue
			}
			uuid, err := reuseOrMint(&secrets.Users[i].VLESSWSCDNUUID, "vless UUID", keys.UUID)
			if err != nil {
				return nil, err
			}
			users = append(users, option.VLESSUser{Name: secrets.Users[i].Name, UUID: uuid})
		}

		return &option.Inbound{
			Type: C.TypeVLESS,
			Tag:  string(p),
			Options: &option.VLESSInboundOptions{
				// No TLS here by design: a CDN or reverse proxy in front
				// terminates it. Hence the loopback bind — exposing this port
				// directly would serve vless in clear text.
				ListenOptions: listenOn(spec.CDNListen, port),
				Users:         users,
				Transport: &option.V2RayTransportOptions{
					Type: C.V2RayTransportTypeWebsocket,
					WebsocketOptions: option.V2RayWebsocketOptions{
						Path: "/cdnws",
						// Cloudflare strips most request headers but passes
						// Sec-WebSocket-Protocol through, which is what makes
						// early data survive the hop.
						EarlyDataHeaderName: "Sec-WebSocket-Protocol",
					},
				},
			},
		}, nil
	}

	return nil, fmt.Errorf("no inbound builder for protocol %q", p)
}

func buildEndpoint(spec Spec, p Protocol, secrets *Secrets, prev *Secrets) (*option.Endpoint, error) {
	prefix := spec.Subnets[p]
	preserved, hasPreserved := EndpointSecrets{}, false
	if prev != nil {
		preserved, hasPreserved = prev.Endpoints[p]
	}
	// The endpoint's public key is in every peer's config and its obfuscation
	// parameters have to match on both sides, so both are preserved together
	// or not at all.
	if hasPreserved && !prefix.Contains(preserved.Address.Addr()) {
		return nil, fmt.Errorf("the endpoint's address %s is outside the configured subnet %s; moving a subnet has to reassign every peer deliberately", preserved.Address, prefix)
	}

	var serverPrivate, serverPublic string
	var err error
	if hasPreserved && preserved.PrivateKey != "" {
		serverPrivate, serverPublic = preserved.PrivateKey, preserved.PublicKey
	} else {
		serverKey, keyErr := keys.NewX25519()
		if keyErr != nil {
			return nil, fmt.Errorf("generate endpoint keypair: %w", keyErr)
		}
		serverPrivate, serverPublic = serverKey.PrivateStd(), serverKey.PublicStd()
	}

	serverAddr, err := hostInPrefix(prefix, 1)
	if err != nil {
		return nil, err
	}

	var obfuscation keys.AWGObfuscation
	hasObfuscation := false
	switch p {
	case AWG2:
		if hasPreserved && preserved.HasAWGParams {
			obfuscation = preserved.Obfuscation
		} else if obfuscation, err = keys.NewAWG2Obfuscation(); err != nil {
			return nil, fmt.Errorf("generate AmneziaWG 2.0 parameters: %w", err)
		}
		hasObfuscation = true
	case AWG3:
		if hasPreserved && preserved.HasAWGParams {
			obfuscation = preserved.Obfuscation
		} else if obfuscation, err = keys.NewAWG3Obfuscation(); err != nil {
			return nil, fmt.Errorf("generate AmneziaWG 3.1 parameters: %w", err)
		}
		hasObfuscation = true
	case WGMasque, WGWDTT:
		// Deliberately plain WireGuard: these endpoints sit behind MASQUE and
		// the WG-over-VK relay respectively, which supply the obfuscation.
		// Adding AmneziaWG junk on top would only cost MTU on paths that are
		// already at the 1280-byte floor.
	}

	peers := make([]option.AwgPeerOptions, 0, len(spec.Users))
	// Addresses already in use are claimed first, so a new peer cannot be
	// handed one that an existing client is configured with.
	taken := map[netip.Addr]bool{serverAddr.Addr(): true}
	for i := range secrets.Users {
		if existing, ok := secrets.Users[i].Peers[p]; ok && existing.Address.IsValid() {
			taken[existing.Address.Addr()] = true
		}
	}
	for i := range secrets.Users {
		existing, held := secrets.Users[i].Peers[p]
		if !held && !spec.mayMint(secrets.Users[i].Name, PeerSlot(p)) {
			continue
		}
		peerSingle, err := allocatePeerAddress(prefix, existing, taken)
		if err != nil {
			return nil, err
		}
		// Keyed off the PUBLIC half, which is the only one the server has.
		//
		// A peer the bot provisioned is recoverable from the live config, but
		// the config holds only its public key — the private half is the
		// client's and lives in the bot's store. Deciding to mint on an empty
		// private key would therefore reissue a keypair for every bot user on
		// every migration, handing the server a new public key while the
		// client still holds the old private one: a tunnel that handshakes
		// with nobody.
		privateKey, publicKey := existing.PrivateKey, existing.PublicKey
		if publicKey == "" {
			peerKey, keyErr := keys.NewX25519()
			if keyErr != nil {
				return nil, fmt.Errorf("generate peer keypair: %w", keyErr)
			}
			privateKey, publicKey = peerKey.PrivateStd(), peerKey.PublicStd()
		}

		secrets.Users[i].Peers[p] = PeerSecrets{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
			Address:    peerSingle,
		}
		peers = append(peers, option.AwgPeerOptions{
			// Name attributes the peer's traffic to a user, which is what
			// drives the per-user stats and lets the XDP blocker ban the
			// offender's other addresses rather than just this one.
			Username:   secrets.Users[i].Name,
			PublicKey:  publicKey,
			AllowedIPs: badoption.Listable[netip.Prefix]{peerSingle},
		})
	}

	mtu := spec.MTU[p]
	secrets.Endpoints[p] = EndpointSecrets{
		PrivateKey:   serverPrivate,
		PublicKey:    serverPublic,
		Address:      serverAddr,
		ListenPort:   spec.Ports[p],
		MTU:          mtu,
		Obfuscation:  obfuscation,
		HasAWGParams: hasObfuscation,
	}

	endpointOptions := &option.AwgEndpointOptions{
		// Integrated tun is off on purpose: the fork's gvisor stack is what
		// puts endpoint traffic through sniffing, per-user stats and the XDP
		// blocker. The native tun paths bypass all three.
		UseIntegratedTun: false,
		PrivateKey:       serverPrivate,
		Address:          badoption.Listable[netip.Prefix]{serverAddr},
		MTU:              mtu,
		ListenPort:       spec.Ports[p],
		Peers:            peers,
	}
	if hasObfuscation {
		endpointOptions.Awg = awgOptions(obfuscation)
	}

	return &option.Endpoint{
		Type:    C.TypeAwg,
		Tag:     string(p),
		Options: endpointOptions,
	}, nil
}

// awgOptions copies the generated parameters into the fork's schema. The copy
// is explicit rather than a shared struct so that a field appearing or
// disappearing upstream is a compile error here instead of a silently dropped
// obfuscation parameter — which is exactly the failure mode the flat-to-nested
// AWG schema migration had to recover from.
func awgOptions(o keys.AWGObfuscation) option.AwgOptions {
	return option.AwgOptions{
		Jc:   o.Jc,
		Jmin: o.Jmin,
		Jmax: o.Jmax,
		S1:   o.S1,
		S2:   o.S2,
		S3:   o.S3,
		S4:   o.S4,
		H1:   o.H1,
		H2:   o.H2,
		H3:   o.H3,
		H4:   o.H4,
		I1:   o.I1,
		I2:   o.I2,

		HeaderProtectionKey:    o.HeaderProtectionKey,
		ContentPaddingAddition: option.AwgRange(o.ContentPaddingAddition),
		RekeyAfterTime:         option.AwgRange(o.RekeyAfterTime),
		RekeyTimeout:           option.AwgRange(o.RekeyTimeout),
		RejectAfterTime:        option.AwgRange(o.RejectAfterTime),
		KeepaliveTimeout:       option.AwgRange(o.KeepaliveTimeout),
		MaxHandshakeAttempts:   option.AwgRange(o.MaxHandshakeAttempts),
		RandomTrailers:         o.RandomTrailers,
	}
}

func listenOn(addr netip.Addr, port uint16) option.ListenOptions {
	listen := badoption.Addr(addr)
	return option.ListenOptions{
		Listen:     &listen,
		ListenPort: port,
	}
}

// hostInPrefix returns the nth host address of the prefix, carrying the
// prefix's own length so the config expresses a subnet rather than a single
// address.
func hostInPrefix(prefix netip.Prefix, n int) (netip.Prefix, error) {
	addr := prefix.Masked().Addr()
	for range n {
		addr = addr.Next()
		if !addr.IsValid() {
			return netip.Prefix{}, fmt.Errorf("ran off the end of %s looking for host %d", prefix, n)
		}
	}
	if !prefix.Contains(addr) {
		return netip.Prefix{}, fmt.Errorf("host %d does not fit in %s", n, prefix)
	}
	return netip.PrefixFrom(addr, prefix.Bits()), nil
}

func shadowsocksKeyLength(method string) (int, error) {
	// The 2022 methods derive the key from the password, so its decoded length
	// has to match the cipher exactly; a mismatch is rejected at startup.
	switch method {
	case "2022-blake3-aes-128-gcm":
		return 16, nil
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32, nil
	}
	if strings.HasPrefix(method, "2022-") {
		return 0, fmt.Errorf("unknown shadowsocks 2022 method %q: its key length is not known, and guessing it would produce a config that fails at startup", method)
	}
	// Pre-2022 methods take an arbitrary passphrase.
	return 32, nil
}

// pathSuffix derives a short, stable HTTP path from an already-random value, so
// the transport path is not a guessable constant across installs.
func pathSuffix(seed string) string {
	if len(seed) > 8 {
		return seed[:8]
	}
	return seed
}
