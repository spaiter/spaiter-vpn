package profile

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/spaiter/spaiter-vpn/core/option"
	"github.com/spaiter/spaiter-vpn/internal/keys"
)

// SecretsFromConfig recovers the credential bundle from a live configuration.
//
// This is what makes the installer and the running deployment agree about who
// exists. There is no second credential store to merge with: `config.json` is
// already the single source of truth for every server-side credential. The
// bot mints a user's credentials, pushes them through the management API and
// reads them back from there whenever it needs them again; the core persists
// them into the config through config_output_path. The installer's
// `secrets.json` is a handover copy of the users it created at install time —
// a snapshot, not a store — so on a server the bot has been running it names a
// only the users that existed at installation time.
//
// So the fix for "the installer does not know the deployment's users" is to
// read the store that already holds them, not to invent a shared one.
//
// What cannot be recovered is each client's PRIVATE half: a peer's private key
// is the client's and the server only ever had the public one. That is correct
// and not a gap — the server config does not need it. It does mean a bundle
// recovered here is enough to re-render the server, and not enough to re-emit
// a client configuration; the bot's own store holds those halves.
func SecretsFromConfig(options option.Options) (Secrets, error) {
	out := Secrets{
		Endpoints: map[Protocol]EndpointSecrets{},
		Deployment: DeploymentFacts{
			Ports: map[Protocol]uint16{},
		},
	}
	if options.Experimental != nil && options.Experimental.ClashAPI != nil {
		out.ClashAPISecret = options.Experimental.ClashAPI.Secret
	}

	users := newUserIndex(&out)
	for i := range options.Inbounds {
		if err := recoverInbound(&out, users, options.Inbounds[i]); err != nil {
			return Secrets{}, err
		}
	}
	for i := range options.Endpoints {
		if err := recoverEndpoint(&out, users, options.Endpoints[i]); err != nil {
			return Secrets{}, err
		}
	}
	users.sort()
	return out, nil
}

// userIndex hands out a stable slot per user name, so credentials recovered
// from different inbounds land on the same record.
type userIndex struct {
	secrets *Secrets
	byName  map[string]int
}

func newUserIndex(secrets *Secrets) *userIndex {
	return &userIndex{secrets: secrets, byName: map[string]int{}}
}

func (u *userIndex) slot(name string) *UserSecrets {
	if name == "" {
		return nil
	}
	if index, ok := u.byName[name]; ok {
		return &u.secrets.Users[index]
	}
	u.secrets.Users = append(u.secrets.Users, UserSecrets{Name: name, Peers: map[Protocol]PeerSecrets{}})
	u.byName[name] = len(u.secrets.Users) - 1
	return &u.secrets.Users[len(u.secrets.Users)-1]
}

// sort orders users by name so a recovered bundle is deterministic. Without
// it the order follows whichever inbound happened to mention a user first,
// which makes two recoveries of the same config compare unequal.
func (u *userIndex) sort() {
	recovered := u.secrets.Users
	for i := 1; i < len(recovered); i++ {
		for j := i; j > 0 && recovered[j].Name < recovered[j-1].Name; j-- {
			recovered[j], recovered[j-1] = recovered[j-1], recovered[j]
		}
	}
}

// Names lists the users a configuration actually serves, in order.
//
// The list a migration must re-render for, as opposed to the seed users in
// desired state — which on any server the bot has touched is a minority of
// them.
func (s Secrets) Names() []string {
	names := make([]string, 0, len(s.Users))
	for _, user := range s.Users {
		names = append(names, user.Name)
	}
	return names
}

func recoverInbound(out *Secrets, users *userIndex, inbound option.Inbound) error {
	protocol := Protocol(inbound.Tag)
	switch opts := inbound.Options.(type) {
	case *option.VLESSInboundOptions:
		out.Deployment.Ports[protocol] = opts.ListenPort
		var assign func(slot *UserSecrets, uuid string)
		switch protocol {
		case VLESSReality:
			if err := recoverReality(&out.Reality, opts); err != nil {
				return err
			}
			if opts.Transport != nil {
				out.Deployment.RealityTransportPath = opts.Transport.HTTPOptions.Path
			}
			out.Deployment.RealitySNI = realitySNI(opts)
			assign = func(slot *UserSecrets, uuid string) { slot.VLESSRealityUUID = uuid }
		case VLESSWSCDN:
			assign = func(slot *UserSecrets, uuid string) { slot.VLESSWSCDNUUID = uuid }
		case VLESSXHTTP:
			if err := recoverReality(&out.TierB.XHTTPReality, opts); err != nil {
				return err
			}
			out.TierB.Facts.XHTTPSNI = realitySNI(opts)
			if opts.Transport != nil {
				out.TierB.Facts.XHTTPPath = opts.Transport.XHTTPOptions.Path
			}
			assign = func(slot *UserSecrets, uuid string) { slot.VLESSXHTTPUUID = uuid }
		default:
			return fmt.Errorf("recover: unexpected vless inbound tag %q", inbound.Tag)
		}
		for _, user := range opts.Users {
			if slot := users.slot(user.Name); slot != nil {
				assign(slot, user.UUID)
			}
		}

	case *option.ShadowsocksInboundOptions:
		out.Deployment.Ports[protocol] = opts.ListenPort
		out.Shadowsocks = ShadowsocksSecrets{Method: opts.Method, Password: opts.Password}
		out.Deployment.ShadowsocksMethod = opts.Method

	case *option.ShadowTLSInboundOptions:
		out.Deployment.Ports[protocol] = opts.ListenPort
		out.Deployment.ShadowTLSVersion = opts.Version
		out.Deployment.ShadowTLSSNI = opts.Handshake.Server
		for _, user := range opts.Users {
			if slot := users.slot(user.Name); slot != nil {
				slot.ShadowTLSPassword = user.Password
			}
		}

	case *option.SnellInboundOptions:
		out.Deployment.Ports[protocol] = opts.ListenPort
		out.Snell = SnellSecrets{Version: opts.Version, PSK: opts.PSK}
		out.Deployment.SnellVersion = opts.Version
		for _, user := range opts.Users {
			if slot := users.slot(user.Name); slot != nil {
				slot.SnellUserKey = user.UserKey
			}
		}

	case *option.MieruInboundOptions:
		out.Deployment.Ports[protocol] = opts.ListenPort
		for _, user := range opts.Users {
			if slot := users.slot(user.Name); slot != nil {
				slot.MieruPassword = user.Password
			}
		}

	case *option.MTProtoInboundOptions:
		out.Deployment.Ports[protocol] = opts.ListenPort
		out.MTProto = MTProtoSecrets{Secret: opts.Secret}
		for _, user := range opts.Users {
			if slot := users.slot(user.Name); slot != nil {
				slot.MTProtoSecret = user.Secret
			}
		}
		// The front domain is encoded in the secret's tail, and recovering it is
		// what lets the generator decide the secret may be preserved.
		domainSource := opts.Secret
		if domainSource == "" && len(opts.Users) > 0 {
			domainSource = opts.Users[0].Secret
		}
		if domain, ok := mtprotoFrontDomain(domainSource); ok {
			out.MTProto.FrontDomain = domain
			out.Deployment.MTProtoFrontDomain = domain
		}

	case *option.Hysteria2InboundOptions:
		out.Deployment.Ports[protocol] = opts.ListenPort
		out.TierB.Hysteria2ObfsType = opts.Obfs.Type
		out.TierB.Hysteria2ObfsPassword = opts.Obfs.Password
		for _, user := range opts.Users {
			if slot := users.slot(user.Name); slot != nil {
				slot.Hysteria2Password = user.Password
			}
		}

	case *option.TUICInboundOptions:
		out.Deployment.Ports[protocol] = opts.ListenPort
		out.TierB.Facts.TUICCongestionControl = opts.CongestionControl
		for _, user := range opts.Users {
			if slot := users.slot(user.Name); slot != nil {
				slot.TUICUUID = user.UUID
				slot.TUICPassword = user.Password
			}
		}

	case *option.AnyTLSInboundOptions:
		out.Deployment.Ports[protocol] = opts.ListenPort
		for _, user := range opts.Users {
			if slot := users.slot(user.Name); slot != nil {
				slot.AnyTLSPassword = user.Password
			}
		}

	case *option.NaiveInboundOptions:
		out.Deployment.Ports[protocol] = opts.ListenPort
		for _, user := range opts.Users {
			if slot := users.slot(user.Username); slot != nil {
				slot.NaivePassword = user.Password
			}
		}

	default:
		// Not an error: a configuration may carry inbounds this generator does
		// not produce, and refusing to read the rest because of one of them
		// would make recovery brittle for no gain.
		return nil
	}
	return nil
}

func recoverReality(into *RealitySecrets, opts *option.VLESSInboundOptions) error {
	if opts.TLS == nil || opts.TLS.Reality == nil {
		return fmt.Errorf("recover: the reality inbound carries no reality options")
	}
	reality := opts.TLS.Reality
	pair, err := keys.X25519FromPrivate(reality.PrivateKey)
	if err != nil {
		return fmt.Errorf("recover: the reality private key is unreadable: %w", err)
	}
	into.PrivateKey = reality.PrivateKey
	// Derived, because a config stores only the private half — and the public
	// one is what every client config needs.
	into.PublicKey = pair.PublicURL()
	if len(reality.ShortID) > 0 {
		into.ShortID = reality.ShortID[0]
	}
	return nil
}

func realitySNI(opts *option.VLESSInboundOptions) string {
	if opts.TLS == nil {
		return ""
	}
	return opts.TLS.ServerName
}

// mtprotoFrontDomain reads the domain back out of a fake-TLS secret, which
// encodes it as hex after the "ee" marker and 16 random bytes.
func mtprotoFrontDomain(secret string) (string, bool) {
	const prefix = "ee"
	const randomHexLen = 32
	if !strings.HasPrefix(secret, prefix) || len(secret) <= len(prefix)+randomHexLen {
		return "", false
	}
	decoded, err := hex.DecodeString(secret[len(prefix)+randomHexLen:])
	if err != nil || len(decoded) == 0 {
		return "", false
	}
	return string(decoded), true
}

// obfuscationFromOptions is the inverse of awgOptions.
func obfuscationFromOptions(opts *option.AwgEndpointOptions) keys.AWGObfuscation {
	o := opts.Awg
	return keys.AWGObfuscation{
		Jc: o.Jc, Jmin: o.Jmin, Jmax: o.Jmax,
		S1: o.S1, S2: o.S2, S3: o.S3, S4: o.S4,
		H1: o.H1, H2: o.H2, H3: o.H3, H4: o.H4,
		I1: o.I1, I2: o.I2,
		HeaderProtectionKey:    o.HeaderProtectionKey,
		ContentPaddingAddition: o.ContentPaddingAddition,
		RekeyAfterTime:         o.RekeyAfterTime,
		RekeyTimeout:           o.RekeyTimeout,
		RejectAfterTime:        o.RejectAfterTime,
		KeepaliveTimeout:       o.KeepaliveTimeout,
		MaxHandshakeAttempts:   o.MaxHandshakeAttempts,
		RandomTrailers:         o.RandomTrailers,
	}
}

func recoverEndpoint(out *Secrets, users *userIndex, endpoint option.Endpoint) error {
	opts, ok := endpoint.Options.(*option.AwgEndpointOptions)
	if !ok {
		return nil
	}
	protocol := Protocol(endpoint.Tag)
	pair, err := keys.X25519FromPrivate(opts.PrivateKey)
	if err != nil {
		return fmt.Errorf("recover: the private key of endpoint %s is unreadable: %w", endpoint.Tag, err)
	}
	var address netip.Prefix
	if len(opts.Address) > 0 {
		address = opts.Address[0]
	}
	out.Deployment.Ports[protocol] = opts.ListenPort
	out.Endpoints[protocol] = EndpointSecrets{
		PrivateKey:   opts.PrivateKey,
		PublicKey:    pair.PublicStd(),
		Address:      address,
		ListenPort:   opts.ListenPort,
		MTU:          opts.MTU,
		Obfuscation:  obfuscationFromOptions(opts),
		HasAWGParams: opts.Awg.IsAvailble(),
	}

	for _, peer := range opts.Peers {
		slot := users.slot(peer.Name)
		if slot == nil {
			// An unnamed peer predates per-peer naming or was made by hand.
			// Skipped rather than guessed at: attaching it to the wrong user
			// would hand somebody else's address out.
			continue
		}
		var peerAddress netip.Prefix
		if len(peer.AllowedIPs) > 0 {
			peerAddress = peer.AllowedIPs[0]
		}
		slot.Peers[protocol] = PeerSecrets{
			// No private key: it is the client's half and the server never had
			// it. Preservation keys off the public one for exactly this reason.
			PublicKey: peer.PublicKey,
			Address:   peerAddress,
		}
	}
	return nil
}
