package profile

import (
	"fmt"
	"net/netip"

	"github.com/spaiter/spaiter-vpn/internal/keys"
)

// Secrets is everything the generator minted. It is returned alongside the
// config rather than only written into it, because the operator needs the
// client-side half — a server config nobody can connect to is not a
// deployment.
//
// Treat a Secrets value as the config itself: it carries private keys.
type Secrets struct {
	ClashAPISecret string

	// Deployment records the facts a client needs that are not secrets and
	// cannot be recovered from anywhere else. Without them the client side has
	// to assume defaults, and a deployment that moved a port or borrowed a
	// different SNI then gets share URLs that point at the wrong place and say
	// nothing about it.
	Deployment DeploymentFacts

	Reality     RealitySecrets
	Shadowsocks ShadowsocksSecrets
	Snell       SnellSecrets
	MTProto     MTProtoSecrets

	// TierB is zero when only Tier A was generated.
	TierB TierBSecrets

	// Endpoints holds the server-side keypair of each WireGuard endpoint,
	// keyed by protocol.
	Endpoints map[Protocol]EndpointSecrets

	Users []UserSecrets
}

// DeploymentFacts is the non-secret half of the handover: what was actually
// deployed, as opposed to what the defaults would have been.
type DeploymentFacts struct {
	// Ports as generated, including any override. Endpoint ports are also in
	// EndpointSecrets; the proxy inbounds have nowhere else to record theirs.
	Ports map[Protocol]uint16

	// RealitySNI is the host whose handshake Reality borrows. A client must
	// send exactly this as SNI or the handshake is forwarded to the wrong
	// place.
	RealitySNI string
	// RealityTransportPath is the HTTP transport path. It is derived from the
	// short_id at generation time, and recording it beats re-deriving it on
	// the client side and hoping the two derivations stay identical.
	RealityTransportPath string

	ShadowTLSSNI     string
	ShadowTLSVersion int

	SnellVersion       int
	ShadowsocksMethod  string
	MTProtoFrontDomain string
}

// RealitySecrets carries the Reality server keypair. The public key is not a
// secret and is what the client config needs; the private key never leaves the
// server.
type RealitySecrets struct {
	PrivateKey string // base64 raw-url, the encoding the fork decodes
	PublicKey  string // base64 raw-url, for client configs
	ShortID    string
}

// ShadowsocksSecrets is the single inbound password. There is deliberately no
// per-user list here: the shadowsocks inbound exists only as the detour target
// of shadowtls, and user identity is established one layer up.
type ShadowsocksSecrets struct {
	Method   string
	Password string
}

// SnellSecrets is the shared pre-shared key; per-user keys live in UserSecrets.
type SnellSecrets struct {
	Version int
	PSK     string
}

// MTProtoSecrets is the legacy shared fake-TLS secret. New deployments give
// every user an MTProto secret of their own (UserSecrets.MTProtoSecret); this
// one is kept only where it was already handed out, and is attributed to
// nobody.
type MTProtoSecrets struct {
	Secret      string
	FrontDomain string
}

// EndpointSecrets is the server side of one WireGuard-family endpoint.
type EndpointSecrets struct {
	PrivateKey   string // base64 standard, the encoding protocol/awg decodes
	PublicKey    string // base64 standard, for client configs
	Address      netip.Prefix
	ListenPort   uint16
	MTU          uint32
	Obfuscation  keys.AWGObfuscation
	HasAWGParams bool
}

// UserSecrets is one client's credentials across every generated protocol.
// A field is empty when its protocol was not generated.
type UserSecrets struct {
	Name string

	VLESSRealityUUID  string
	VLESSWSCDNUUID    string
	ShadowTLSPassword string
	SnellUserKey      string
	MieruPassword     string

	// Tier B. TUIC is the one protocol here needing both halves: the UUID
	// identifies the user and the password authenticates them.
	Hysteria2Password string
	TUICUUID          string
	TUICPassword      string
	AnyTLSPassword    string
	NaivePassword     string
	VLESSXHTTPUUID    string

	// MTProtoSecret is the user's own fake-TLS (ee) secret. The core matches a
	// connection to its user by it, so Telegram traffic is accounted per user.
	MTProtoSecret string

	// Peers is the client side of each WireGuard endpoint, keyed by protocol.
	Peers map[Protocol]PeerSecrets
}

// PeerSecrets is one client's keypair and tunnel address on one endpoint.
type PeerSecrets struct {
	PrivateKey string // base64 standard
	PublicKey  string // base64 standard, the half that goes in the server config
	Address    netip.Prefix
}

// SpecFromSecrets rebuilds what the client side needs from the deployment
// record written at generation time.
//
// It reads facts rather than reconstructing them. An earlier version filled the
// gaps from Defaults, which meant a deployment generated with -ports or
// a different Reality SNI produced share URLs pointing at the default port with
// the default SNI — wrong, and silently so. Anything missing is now an error.
func SpecFromSecrets(secrets Secrets) (Spec, error) {
	if len(secrets.Users) == 0 {
		return Spec{}, fmt.Errorf("the secrets file records no users")
	}
	if len(secrets.Deployment.Ports) == 0 {
		return Spec{}, fmt.Errorf("this secrets file predates the deployment record and does not say which ports were used; re-run `init` or pass the client flags by hand")
	}

	names := make([]string, 0, len(secrets.Users))
	for _, u := range secrets.Users {
		names = append(names, u.Name)
	}
	spec := Defaults(names)

	// Exactly the protocols that were deployed: a run with -disable must not
	// produce client entries for what it left out.
	spec.Enabled = map[Protocol]bool{}
	for p, port := range secrets.Deployment.Ports {
		spec.Enabled[p] = true
		spec.Ports[p] = port
	}
	for p, ep := range secrets.Endpoints {
		if ep.Address.IsValid() {
			spec.Subnets[p] = ep.Address.Masked()
		}
	}

	// Tier B is restored from its own record, never inferred. A secrets file
	// that names a domain was generated as Tier B, and the tier has to come
	// back with it: left at Tier A, EnabledProtocols would filter every Tier B
	// protocol out and the client bundle would quietly omit half the
	// deployment while reporting success. An xhttp path alone no longer says
	// Tier B: vless-xhttp is Tier A, and its facts are kept here only because
	// that is where secrets files hold them.
	if tb := secrets.TierB.Facts; tb.Domain != "" {
		spec.Tier = TierB
		spec.Domain = tb.Domain
		spec.Certs.Source = tb.CertSource
		if tb.TUICCongestionControl != "" {
			spec.TUICCongestionControl = tb.TUICCongestionControl
		}
		// XHTTPSNI and XHTTPPath are deliberately not copied onto the spec.
		// The xhttp client reads them from the facts directly, so there is one
		// place holding what was deployed instead of a spec field that has to
		// be kept in step with it.
	}

	d := secrets.Deployment
	spec.RealityHandshakeServer = d.RealitySNI
	spec.ShadowTLSHandshakeServer = d.ShadowTLSSNI
	spec.ShadowTLSVersion = d.ShadowTLSVersion
	spec.SnellVersion = d.SnellVersion
	spec.ShadowsocksMethod = d.ShadowsocksMethod
	spec.MTProtoFrontDomain = d.MTProtoFrontDomain

	if len(spec.EnabledProtocols()) == 0 {
		return Spec{}, fmt.Errorf("the secrets file records no protocol")
	}
	return spec, nil
}
