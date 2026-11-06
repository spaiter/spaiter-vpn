package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type MASQUEOutboundOptions struct {
	UseHTTP2             bool               `json:"use_http2,omitempty"`
	UseIPv6              bool               `json:"use_ipv6,omitempty"`
	Port                 uint16             `json:"port,omitempty"` // endpoint port, default 443
	Config               *MASQUEAccount     `json:"config,omitempty"`
	Profile              CloudflareProfile  `json:"profile,omitempty"`
	UDPTimeout           badoption.Duration `json:"udp_timeout,omitempty"`
	UDPKeepalivePeriod   badoption.Duration `json:"udp_keepalive_period,omitempty"`
	UDPInitialPacketSize uint16             `json:"udp_initial_packet_size,omitempty"`
	ReconnectDelay       badoption.Duration `json:"reconnect_delay,omitempty"`
	MASQUEOutboundTLSOptions
	DialerOptions
}

// MASQUEAccount is a Cloudflare MASQUE account (the output of registration).
// Baking one into the config lets a client that cannot reach the registration
// API -- e.g. anything behind white lists -- still bring up the tunnel: register
// once on an unrestricted host, then ship the result. When set, no registration
// is attempted and the config cache is left alone.
type MASQUEAccount struct {
	PrivateKey     string `json:"private_key"`      // Base64-encoded ECDSA private key
	EndpointV4     string `json:"endpoint_v4"`      // IPv4 address of the endpoint
	EndpointV6     string `json:"endpoint_v6"`      // IPv6 address of the endpoint
	EndpointH2V4   string `json:"endpoint_h2_v4"`   // IPv4 address used in HTTP/2 mode
	EndpointH2V6   string `json:"endpoint_h2_v6"`   // IPv6 address used in HTTP/2 mode
	EndpointPubKey string `json:"endpoint_pub_key"` // PEM-encoded ECDSA public key of the endpoint to verify against
	License        string `json:"license"`          // Application license key
	ID             string `json:"id"`               // Device unique identifier
	AccessToken    string `json:"access_token"`     // Authentication token for API access
	IPv4           string `json:"ipv4"`             // Assigned IPv4 address
	IPv6           string `json:"ipv6"`             // Assigned IPv6 address
}

type MASQUEOutboundTLSOptions struct {
	// ServerName overrides the TLS SNI (default cloudflare.ConnectSNI). The endpoint
	// is pinned by its ECDSA public key, not by name, so any value Cloudflare still
	// routes will do.
	ServerName            string                              `json:"server_name,omitempty"`
	Insecure              bool                                `json:"insecure,omitempty"`
	CipherSuites          badoption.Listable[string]          `json:"cipher_suites,omitempty"`
	CurvePreferences      badoption.Listable[CurvePreference] `json:"curve_preferences,omitempty"`
	Fragment              bool                                `json:"fragment,omitempty"`
	FragmentFallbackDelay badoption.Duration                  `json:"fragment_fallback_delay,omitempty"`
	RecordFragment        bool                                `json:"record_fragment,omitempty"`
	KernelTx              bool                                `json:"kernel_tx,omitempty"`
	KernelRx              bool                                `json:"kernel_rx,omitempty"`
}

type MASQUEOutboundTLSOptionsContainer struct {
	TLS *OutboundTLSOptions `json:"tls,omitempty"`
}

// --- self-hosted MASQUE (CONNECT-UDP) + WireGuard pair (masque-wg) //H ---

// MASQUEWGInboundOptions configures the server side: an HTTP/3 CONNECT-UDP proxy
// (RFC 9298, via quic-go/masque-go) that forwards all associations to a single
// locked UDP target (our WireGuard/AmneziaWG listener). Not an open proxy.
type MASQUEWGInboundOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	// Target is the fixed UDP host:port every CONNECT-UDP association is forwarded
	// to (the local WG listener), e.g. "127.0.0.1:10863". Client-requested targets
	// are ignored (anti-abuse).
	Target string `json:"target,omitempty"`
	// Path is the HTTP path of the CONNECT-UDP URI template, default "/m".
	Path string `json:"path,omitempty"`
}

// MASQUEWGOutboundOptions configures the client side: it dials the masque-wg
// server over HTTP/3, opens a CONNECT-UDP association, and runs an embedded
// WireGuard device whose UDP socket rides that association (self-contained; does
// not touch the awg endpoint). Exposes a normal proxy outbound.
type MASQUEWGOutboundOptions struct {
	DialerOptions
	ServerOptions
	OutboundTLSOptionsContainer
	Path string `json:"path,omitempty"` // must match server, default "/m"
	// Embedded WireGuard/AmneziaWG parameters. Awg must match the server's awg
	// endpoint (awg-in) so its handshake is accepted through the tunnel.
	PrivateKey                  string                           `json:"private_key"`
	PeerPublicKey               string                           `json:"peer_public_key"`
	PreSharedKey                string                           `json:"pre_shared_key,omitempty"`
	LocalAddress                badoption.Listable[netip.Prefix] `json:"local_address"` // client tunnel IPs, e.g. ["10.10.0.5/32"]
	MTU                         uint32                           `json:"mtu,omitempty"` // default 1280 (room under MASQUE/QUIC)
	PersistentKeepaliveInterval uint16                           `json:"persistent_keepalive_interval,omitempty"`
	Awg                         AwgOptions                       `json:"awg,omitempty"`
}
