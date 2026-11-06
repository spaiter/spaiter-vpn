package option

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

type _AwgEndpointOptions struct {
	UseIntegratedTun bool                             `json:"useIntegratedTun"`
	PrivateKey       string                           `json:"private_key"`
	Address          badoption.Listable[netip.Prefix] `json:"address"`
	MTU              uint32                           `json:"mtu,omitempty"`
	ListenPort       uint16                           `json:"listen_port,omitempty"`
	Awg              AwgOptions                       `json:"awg,omitempty"`
	Peers            []AwgPeerOptions                 `json:"peers,omitempty"`
	DialerOptions
}

type AwgEndpointOptions _AwgEndpointOptions

// UnmarshalJSONContext accepts the nested `awg` object and, for backward
// compatibility with configs written before the schema was nested, also folds
// legacy top-level AmneziaWG obfuscation params (jc/jmin/jmax/s1..s4/h1..h4/i1..i5)
// into the `awg` object. //H flat->nested migration
func (o *AwgEndpointOptions) UnmarshalJSONContext(ctx context.Context, content []byte) error {
	err := json.UnmarshalContext(ctx, content, (*_AwgEndpointOptions)(o))
	if err != nil {
		return err
	}
	if !o.Awg.IsAvailble() {
		var legacy AwgOptions
		if json.UnmarshalContext(ctx, content, &legacy) == nil && legacy.IsAvailble() {
			o.Awg = legacy
		}
	}
	return nil
}

type AwgOptions struct {
	Jc   int    `json:"jc,omitempty"`
	Jmin int    `json:"jmin,omitempty"`
	Jmax int    `json:"jmax,omitempty"`
	S1   int    `json:"s1,omitempty"`
	S2   int    `json:"s2,omitempty"`
	S3   int    `json:"s3,omitempty"`
	S4   int    `json:"s4,omitempty"`
	H1   string `json:"h1,omitempty"`
	H2   string `json:"h2,omitempty"`
	H3   string `json:"h3,omitempty"`
	H4   string `json:"h4,omitempty"`
	I1   string `json:"i1,omitempty"`
	I2   string `json:"i2,omitempty"`
	I3   string `json:"i3,omitempty"`
	I4   string `json:"i4,omitempty"`
	I5   string `json:"i5,omitempty"`

	// AWG 3.x. Ranges are "a-b" or a single "a"; HeaderProtectionKey is base64
	// (like private_key) and gets hex-encoded on the way into the UAPI. //H awg3
	HeaderProtectionKey    string `json:"header_protection_key,omitempty"`
	ContentPaddingAddition string `json:"content_padding_addition,omitempty"`
	RekeyAfterTime         string `json:"rekey_after_time,omitempty"`
	RekeyTimeout           string `json:"rekey_timeout,omitempty"`
	RejectAfterTime        string `json:"reject_after_time,omitempty"`
	KeepaliveTimeout       string `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   string `json:"max_handshake_attempts,omitempty"`
	RandomTrailers         bool   `json:"random_trailers,omitempty"`
	DisableCookies         bool   `json:"disable_cookies,omitempty"`
}

func (o *AwgOptions) IsAvailble() bool {
	if o == nil {
		return false
	}
	return o.Jc != 0 || o.Jmin != 0 || o.Jmax != 0 || o.S1 != 0 || o.S2 != 0 || o.S3 != 0 || o.S4 != 0 || o.H1 != "" || o.H2 != "" || o.H3 != "" || o.H4 != "" || o.I1 != "" || o.I2 != "" || o.I3 != "" || o.I4 != "" || o.I5 != "" ||
		o.HeaderProtectionKey != "" || o.ContentPaddingAddition != "" || o.RekeyAfterTime != "" || o.RekeyTimeout != "" || o.RejectAfterTime != "" || o.KeepaliveTimeout != "" || o.MaxHandshakeAttempts != "" || o.RandomTrailers || o.DisableCookies
}

type AwgPeerOptions struct {
	Address string `json:"address,omitempty"`
	Port    uint16 `json:"port,omitempty"`
	// Name attributes the peer's traffic to a user, the way the `users` list
	// does for proxy inbounds: it populates metadata.User, which drives the
	// per-user SQLite stats and the XDP blocker's per-user IP tracking.
	// Optional — an unnamed peer simply stays unattributed, as before. //H
	Name                        string                           `json:"name,omitempty"`
	PublicKey                   string                           `json:"public_key,omitempty"`
	PresharedKey                string                           `json:"preshared_key,omitempty"`
	AllowedIPs                  badoption.Listable[netip.Prefix] `json:"allowed_ips,omitempty"`
	PersistentKeepaliveInterval uint16                           `json:"persistent_keepalive_interval,omitempty"`
}
