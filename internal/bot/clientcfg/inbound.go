// Package clientcfg renders everything a client receives: share links,
// sing-box configs, bundle nodes and WireGuard files.
//
// These are the shapes the CLIENT core reads, which is not the same as the
// server's. Two of them diverge and both have already broken users:
//
//   - MASQUE takes a nested tls{sni} plus a baked config object; the server
//     core takes flat server_name/port and no config at all.
//   - Mieru takes server_port plus transport; the server inbound describes the
//     same thing as portBindings.
//
// Every generator here is a pure function of an inbound, a user and the
// configuration. Provisioning happens elsewhere and is passed in, which is
// what lets these be tested in process against a real core binary.
package clientcfg

import (
	"encoding/json"
	"fmt"
)

// Inbound is the slice of an inbound's config the generators read.
//
// Deliberately partial: the core's own option structs are the authority on the
// rest, and restating them here would create a second definition to keep in
// step. Unknown fields are ignored rather than rejected -- an inbound gaining
// an option must not stop the bot from handing out configs for it.
type Inbound struct {
	Type       string     `json:"type"`
	Tag        string     `json:"tag"`
	ListenPort uint16     `json:"listen_port"`
	TLS        *TLS       `json:"tls,omitempty"`
	Transport  *Transport `json:"transport,omitempty"`
	Obfs       *Obfs      `json:"obfs,omitempty"`
	Multiplex  *Multiplex `json:"multiplex,omitempty"`

	// tuic
	CongestionControl string `json:"congestion_control,omitempty"`
	// mtproto
	Secret string `json:"secret,omitempty"`
	// snell: the PSK is server-wide and the per-user part is a userkey, and
	// the v6 mode has to be mirrored by the client rather than defaulted.
	Version int    `json:"version,omitempty"`
	PSK     string `json:"psk,omitempty"`
	Mode    string `json:"mode,omitempty"`
	// shadowsocks, used as the ShadowTLS detour backend
	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`
	// shadowtls
	Handshake *Handshake `json:"handshake,omitempty"`
	// Detour names the inbound this one fronts. ShadowTLS is a TLS front over
	// a shadowsocks inbound, and the client needs both halves: without the
	// backend it has the outer credential and nothing to speak inside.
	Detour string `json:"detour,omitempty"`
	// mieru states its transport as port bindings; clients want `transport`
	PortBindings []PortBinding `json:"portBindings,omitempty"`
	// anytls
	PaddingScheme []string `json:"padding_scheme,omitempty"`
}

// TLS is the inbound's TLS block.
type TLS struct {
	Enabled    bool         `json:"enabled"`
	ServerName string       `json:"server_name,omitempty"`
	ALPN       StringOrList `json:"alpn,omitempty"`
	Reality    *Reality     `json:"reality,omitempty"`
}

// Reality carries the server's private key; a client is told the public one.
type Reality struct {
	Enabled    bool         `json:"enabled"`
	PrivateKey string       `json:"private_key,omitempty"`
	ShortID    StringOrList `json:"short_id,omitempty"`
}

// Transport is the inbound's transport block.
type Transport struct {
	Type string       `json:"type,omitempty"`
	Path string       `json:"path,omitempty"`
	Host StringOrList `json:"host,omitempty"`

	// XHTTP obfs mode. With it on the server stops reading the padding from a
	// fixed place and reads it where these say; a client missing any of them
	// gets 400 on every request.
	XPaddingObfsMode  bool   `json:"x_padding_obfs_mode,omitempty"`
	XPaddingBytes     string `json:"x_padding_bytes,omitempty"`
	XPaddingKey       string `json:"x_padding_key,omitempty"`
	XPaddingHeader    string `json:"x_padding_header,omitempty"`
	XPaddingPlacement string `json:"x_padding_placement,omitempty"`
	XPaddingMethod    string `json:"x_padding_method,omitempty"`
}

// Obfs is hysteria2's salamander obfuscation.
type Obfs struct {
	Type     string `json:"type,omitempty"`
	Password string `json:"password,omitempty"`
}

// Multiplex is carried through to clients that support it.
type Multiplex struct {
	Enabled bool `json:"enabled,omitempty"`
}

// Handshake is where ShadowTLS sends a real TLS handshake.
type Handshake struct {
	Server     string `json:"server,omitempty"`
	ServerPort uint16 `json:"server_port,omitempty"`
}

// PortBinding is one of mieru's listen bindings.
type PortBinding struct {
	Protocol  string `json:"protocol,omitempty"`
	Port      uint16 `json:"port,omitempty"`
	PortRange string `json:"portRange,omitempty"`
}

// ParseInbound reads an inbound as the core's API returned it.
func ParseInbound(raw json.RawMessage) (Inbound, error) {
	var in Inbound
	if err := json.Unmarshal(raw, &in); err != nil {
		return Inbound{}, fmt.Errorf("clientcfg: parse inbound: %w", err)
	}
	return in, nil
}

// ServerName is the SNI a client should present, empty when there is no TLS.
func (in Inbound) ServerName() string {
	if in.TLS == nil {
		return ""
	}
	return in.TLS.ServerName
}

// RealityEnabled reports whether this inbound expects a Reality handshake.
func (in Inbound) RealityEnabled() bool {
	return in.TLS != nil && in.TLS.Reality != nil && in.TLS.Reality.Enabled
}

// TransportType is the transport name, "" when the inbound is plain TCP.
func (in Inbound) TransportType() string {
	if in.Transport == nil {
		return ""
	}
	return in.Transport.Type
}

// TransportPath is the path the server routes on, if any.
func (in Inbound) TransportPath() string {
	if in.Transport == nil {
		return ""
	}
	return in.Transport.Path
}

// MieruTransport is mieru's client-side option: TCP or UDP, taken from the
// inbound's own port binding rather than assumed.
//
// The two schemas are not interchangeable. Our client core and upstream
// sing-box both take server_port plus transport and reject portBindings as an
// unknown field; the client core additionally requires transport, so leaving
// it out is no help either.
func (in Inbound) MieruTransport() string {
	for _, binding := range in.PortBindings {
		if binding.Protocol != "" {
			return upper(binding.Protocol)
		}
	}
	return "TCP"
}

// XHTTPObfsFields are the padding fields an obfs-mode XHTTP client must match.
// Empty for a plain XHTTP inbound, so configs for it stay byte-identical and
// nobody has to re-import for nothing.
func (in Inbound) XHTTPObfsFields() map[string]any {
	if in.Transport == nil || !in.Transport.XPaddingObfsMode {
		return nil
	}
	fields := map[string]any{"x_padding_obfs_mode": true}
	for key, value := range map[string]string{
		"x_padding_key":       in.Transport.XPaddingKey,
		"x_padding_header":    in.Transport.XPaddingHeader,
		"x_padding_placement": in.Transport.XPaddingPlacement,
		"x_padding_method":    in.Transport.XPaddingMethod,
	} {
		if value != "" {
			fields[key] = value
		}
	}
	return fields
}

// StringOrList decodes a field the core writes either way: short_id and host
// are a single string in some configs and a list in others.
type StringOrList []string

func (s *StringOrList) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		if one == "" {
			*s = nil
		} else {
			*s = StringOrList{one}
		}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("clientcfg: value is neither a string nor a list: %s", data)
	}
	*s = many
	return nil
}

// First is the value a share link carries when the field may hold several.
func (s StringOrList) First() string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// User is the per-user credential an inbound issued.
type User struct {
	Name     string `json:"name,omitempty"`
	Username string `json:"username,omitempty"`
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	UserKey  string `json:"userkey,omitempty"`
	Flow     string `json:"flow,omitempty"`
	// Secret is an MTProto user's own fake-TLS secret.
	Secret string `json:"secret,omitempty"`
}

// ParseUser reads a user object as the core's API returned it.
//
// naive-in's users are keyed Username/Password with capitals on disk, so both
// spellings are accepted: a user that decodes to an empty key would be
// provisioned again under the same name.
func ParseUser(raw json.RawMessage) (User, error) {
	var u User
	if err := json.Unmarshal(raw, &u); err != nil {
		return User{}, fmt.Errorf("clientcfg: parse user: %w", err)
	}
	if u.Name == "" && u.Username == "" {
		var capitalised struct {
			Username string `json:"Username"`
			Password string `json:"Password"`
		}
		if err := json.Unmarshal(raw, &capitalised); err == nil {
			u.Username = capitalised.Username
			if u.Password == "" {
				u.Password = capitalised.Password
			}
		}
	}
	return u, nil
}

// Key is how a user is identified across inbound types, and the name its
// traffic is accounted under.
func (u User) Key() string {
	if u.Name != "" {
		return u.Name
	}
	return u.Username
}

func upper(s string) string {
	out := []rune(s)
	for i, r := range out {
		if r >= 'a' && r <= 'z' {
			out[i] = r - 32
		}
	}
	return string(out)
}
