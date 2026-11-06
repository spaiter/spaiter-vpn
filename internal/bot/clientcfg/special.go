package clientcfg

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/keys"
)

// Endpoint is the slice of a WireGuard endpoint's config the generators read.
type Endpoint struct {
	Tag string `json:"tag"`
	// Type distinguishes an AmneziaWG endpoint from a plain WireGuard one,
	// which decides whether the obfuscation parameters are there to carry.
	Type       string         `json:"type"`
	PrivateKey string         `json:"private_key"`
	ListenPort uint16         `json:"listen_port"`
	MTU        uint32         `json:"mtu"`
	Address    StringOrList   `json:"address"`
	AWG        map[string]any `json:"awg"`
}

// ParseEndpoint reads an endpoint as the core's API returned it.
func ParseEndpoint(raw json.RawMessage) (Endpoint, error) {
	var ep Endpoint
	if err := json.Unmarshal(raw, &ep); err != nil {
		return Endpoint{}, fmt.Errorf("clientcfg: parse endpoint: %w", err)
	}
	return ep, nil
}

// ServerPublicKey is the public half of the endpoint's key, which is what a
// peer has to be told.
func (ep Endpoint) ServerPublicKey() (string, error) {
	pair, err := keys.X25519FromPrivate(ep.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("clientcfg: endpoint %s public key: %w", ep.Tag, err)
	}
	return pair.PublicStd(), nil
}

// awgOutboundKeys are AmneziaWG's obfuscation parameters.
//
// The client fork parses these FLAT on the outbound, where the server endpoint
// nests them under "awg". Same values, two shapes, and the client rejects the
// nested form outright.
//
// Ordered, and the order is the server's own: Jc..Jmax shape the junk packets,
// S1..S4 the handshake sizes, H1..H4 the header types, I1..I5 the injected
// packet templates, and the rest are AWG 3.1's header protection and timings.
var awgOutboundKeys = []string{
	"jc", "jmin", "jmax",
	"s1", "s2", "s3", "s4",
	"h1", "h2", "h3", "h4",
	"i1", "i2", "i3", "i4", "i5",
	"header_protection_key",
	"content_padding_addition",
	"rekey_after_time",
	"rekey_timeout",
	"reject_after_time",
	"keepalive_timeout",
	"max_handshake_attempts",
	"random_trailers",
	"disable_cookies",
}

// awgConfNames maps each parameter to its spelling in a wg-quick style file.
var awgConfNames = map[string]string{
	"jc": "Jc", "jmin": "Jmin", "jmax": "Jmax",
	"s1": "S1", "s2": "S2", "s3": "S3", "s4": "S4",
	"h1": "H1", "h2": "H2", "h3": "H3", "h4": "H4",
	"i1": "I1", "i2": "I2", "i3": "I3", "i4": "I4", "i5": "I5",
	"header_protection_key":    "HeaderProtectionKey",
	"content_padding_addition": "ContentPaddingAddition",
	"rekey_after_time":         "RekeyAfterTime",
	"rekey_timeout":            "RekeyTimeout",
	"reject_after_time":        "RejectAfterTime",
	"keepalive_timeout":        "KeepaliveTimeout",
	"max_handshake_attempts":   "MaxHandshakeAttempts",
	"random_trailers":          "RandomTrailers",
	"disable_cookies":          "DisableCookies",
}

// AWGNode is the AmneziaWG bundle node. The fork registers awg as an outbound,
// so it rides in outbounds[] like any other node.
//
// peerAddress is a name, not an address, and deliberately: the public IPv4 of a
// DS-Lite line rotates, so a baked literal goes stale and produces both a
// broken tunnel and a config-changed notification on every rotation. The name
// follows the address, which keeps the bundle stable.
func AWGNode(ep Endpoint, peer state.Peer, label, peerAddress string) (Node, error) {
	serverPub, err := ep.ServerPublicKey()
	if err != nil {
		return nil, err
	}
	mtu := ep.MTU
	if mtu == 0 {
		mtu = 1200
	}
	node := Node{
		"type": "awg", "tag": label,
		"private_key": peer.Priv,
		"address":     []string{peer.IP + "/32"},
		"mtu":         mtu,
		"peers": []any{map[string]any{
			"address": peerAddress, "port": ep.ListenPort, "public_key": serverPub,
			"allowed_ips":                   []string{"0.0.0.0/0", "::/0"},
			"persistent_keepalive_interval": 25,
		}},
	}
	for _, key := range awgOutboundKeys {
		if value, ok := ep.AWG[key]; ok && !isZero(value) {
			node[key] = value
		}
	}
	return node, nil
}

// MASQUEWGNode carries plain WireGuard inside a CONNECT-UDP tunnel.
//
// Its own endpoint, without AmneziaWG's junk: oversized and randomised packets
// do not fit the small QUIC datagrams a mobile MTU allows.
func MASQUEWGNode(cfg bot.Config, ep Endpoint, peer state.Peer, port uint16, path string) (Node, error) {
	serverPub, err := ep.ServerPublicKey()
	if err != nil {
		return nil, err
	}
	mtu := ep.MTU
	if mtu == 0 {
		mtu = 1200
	}
	if path == "" {
		path = "/m"
	}
	return Node{
		"type": "masque-wg", "tag": cfg.NodeTags.MASQUEWG,
		"server": cfg.Public.Host, "server_port": port, "path": path,
		"tls":             map[string]any{"enabled": true, "server_name": cfg.Public.Host},
		"private_key":     peer.Priv,
		"peer_public_key": serverPub,
		"local_address":   []string{peer.IP + "/32"},
		"mtu":             mtu,
	}, nil
}

// WDTTNode is WireGuard inside VK call relays.
func WDTTNode(cfg bot.Config, password string, hashes []string) Node {
	return Node{
		"type": "wdtt", "tag": cfg.NodeTags.WDTT,
		"server": wdttHost(cfg), "server_port": cfg.WDTT.DTLSPort,
		"password": password,
		// An empty list rather than a nil one: the field has to be present,
		// and nil renders as null where the client expects an array.
		"vk_hashes": append([]string{}, hashes...),
		"vk_dns":    "yandex",
		"obfs":      cfg.WDTT.Obfs,
		"mtu":       cfg.WDTT.MTU,
		"workers":   WDTTWorkers(cfg, len(hashes)),
	}
}

// WDTTWorkers is how many relay legs to open: one set per live hash, floored at
// one set and capped so a large pool cannot open an unbounded number.
func WDTTWorkers(cfg bot.Config, liveHashes int) int {
	per, max := cfg.WDTT.WorkersPerHash, cfg.WDTT.MaxWorkers
	if fixed := cfg.WDTT.Workers; fixed > 0 {
		return clamp(fixed, per, max)
	}
	if liveHashes < 1 {
		liveHashes = 1
	}
	return clamp(liveHashes*per, per, max)
}

func clamp(v, low, high int) int {
	if high > 0 && v > high {
		v = high
	}
	if v < low {
		v = low
	}
	return v
}

// wdttHost is the A-only name VK's TURN is reached through. VK is IPv4-only
// there, and a dual-stack name resolves to AAAA first and fails.
func wdttHost(cfg bot.Config) string {
	if cfg.WDTT.ServerHost != "" {
		return cfg.WDTT.ServerHost
	}
	// The A-only name before the proxy host: a dual-stack name resolves to
	// AAAA first and VK's TURN has no v6, so the client dials an address
	// nothing answers on.
	if cfg.Public.IPv4Host != "" {
		return cfg.Public.IPv4Host
	}
	return cfg.Public.Host
}

// Chain is a bundle node made of several legs. The client expands _chain into
// an outbound per leg and wires the detour between them.
type Chain struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
	Legs []Node `json:"_chain"`
}

// ShadowTLSChain is shadowsocks hidden behind a real TLS handshake. The
// shadowsocks credential is shared; the ShadowTLS password is per user, which
// is what attributes traffic at the TLS layer.
func ShadowTLSChain(cfg bot.Config, in, backend Inbound, user User, label string) Chain {
	handshake := "www.microsoft.com"
	if in.Handshake != nil && in.Handshake.Server != "" {
		handshake = in.Handshake.Server
	}
	return Chain{
		Type: "chain", Tag: label,
		Legs: []Node{
			{
				"type": "shadowsocks", "tag": "proxy",
				"server": cfg.Public.Host, "server_port": in.ListenPort,
				"method": backend.Method, "password": backend.Password,
				"detour":    "stls",
				"multiplex": map[string]any{"enabled": true},
			},
			{
				"type": "shadowtls", "tag": "stls",
				"server": cfg.Public.Host, "server_port": in.ListenPort, "version": 3,
				"password": user.Password,
				"tls": map[string]any{
					"enabled": true, "server_name": handshake,
					"utls": map[string]any{"enabled": true, "fingerprint": "chrome"},
				},
			},
		},
	}
}

// WARPChain enters through Cloudflare's anycast and leaves through our own
// server, so a user behind a national whitelist keeps our egress address.
func WARPChain(cfg bot.Config, inner Inbound, user User, account state.WARPAccount, label string) (Chain, error) {
	tls := map[string]any{
		"enabled": true, "server_name": inner.ServerName(),
		"utls": map[string]any{"enabled": true, "fingerprint": "chrome"},
	}
	if inner.RealityEnabled() {
		pair, err := keys.X25519FromPrivate(inner.TLS.Reality.PrivateKey)
		if err != nil {
			return Chain{}, fmt.Errorf("clientcfg: warp chain inner key: %w", err)
		}
		tls["reality"] = map[string]any{
			"enabled": true, "public_key": pair.PublicURL(),
			"short_id": inner.TLS.Reality.ShortID.First(),
		}
	}

	proxy := Node{
		"type": "vless", "tag": "proxy",
		"server": cfg.Public.Host, "server_port": inner.ListenPort,
		"uuid": user.UUID, "detour": "warp", "tls": tls,
	}
	if t := inner.TransportType(); t != "" {
		path := inner.TransportPath()
		if path == "" {
			path = "/"
		}
		proxy["transport"] = map[string]any{"type": t, "path": path}
	}

	// Nested tls{sni}, not the flat server_name/port the server core takes:
	// the client core is a different tree where the MASQUE options embed a TLS
	// container and know no top-level server_name, port or fragment. Emitting
	// those makes the whole config fail to decode on every shipped client.
	warp := Node{
		"type": "masque", "tag": "warp", "use_http2": true,
		"tls":    map[string]any{"sni": cfg.WARP.SNI, "fragment": true},
		"config": json.RawMessage(account),
	}
	return Chain{Type: "chain", Tag: label, Legs: []Node{proxy, warp}}, nil
}

// WireGuardConf renders the file an Amnezia client imports.
//
// Booleans are written as on/off: awg-tools' parser takes only those, and a
// literal "true" makes the official client reject the whole file. The Go UAPI
// on the server side is the opposite, which is why this conversion lives here
// and not in the core.
func WireGuardConf(ep Endpoint, peer state.Peer, endpointAddress string, dns string) (string, error) {
	serverPub, err := ep.ServerPublicKey()
	if err != nil {
		return "", err
	}
	if dns == "" {
		dns = "1.1.1.1"
	}
	mtu := ep.MTU
	if mtu == 0 {
		mtu = 1200
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", peer.Priv)
	fmt.Fprintf(&b, "Address = %s/32\n", peer.IP)
	fmt.Fprintf(&b, "DNS = %s\n", dns)
	for _, key := range awgOutboundKeys {
		value, ok := ep.AWG[key]
		if !ok || isZero(value) {
			continue
		}
		fmt.Fprintf(&b, "%s = %s\n", awgConfNames[key], confValue(value))
	}
	fmt.Fprintf(&b, "MTU = %d\n", mtu)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", serverPub)
	b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	fmt.Fprintf(&b, "Endpoint = %s:%d\n", endpointAddress, ep.ListenPort)
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String(), nil
}

// confValue renders one parameter for a .conf file.
func confValue(v any) string {
	switch val := v.(type) {
	case bool:
		if val {
			return "on"
		}
		return "off"
	case string:
		return val
	case float64:
		// JSON numbers decode as float64; these are all integers.
		return fmt.Sprintf("%d", int64(val))
	default:
		return fmt.Sprint(val)
	}
}

func isZero(v any) bool {
	switch val := v.(type) {
	case nil:
		return true
	case bool:
		return !val
	case string:
		return val == ""
	case float64:
		return val == 0
	case []any:
		return len(val) == 0
	default:
		return false
	}
}

// WARPRegistrationConfig is the throwaway config that mints one Cloudflare
// account, and the only generator here whose output never leaves this host.
//
// It is therefore written to the SERVER core's schema -- flat server_name and
// port on the outbound -- which is the opposite of the account-bearing config a
// client receives, where both are nested under tls. The two are not
// interchangeable and mixing them up is what broke the WARP path for every user
// on 2026-11-01.
//
// store_masque_config is the field that makes any of this work. Without it the
// core registers successfully and writes nothing to the cache, so there is
// nothing to scrape and registration fails with "no account produced" -- and
// since the config is schema-valid either way, no amount of checking catches
// its absence. Hence the explicit test.
func WARPRegistrationConfig(cfg bot.Config, cacheDB string) map[string]any {
	return map[string]any{
		"log": map[string]any{"level": "error"},
		"experimental": map[string]any{
			"cache_file": map[string]any{
				"enabled": true, "path": cacheDB, "store_masque_config": true,
			},
		},
		"outbounds": []any{map[string]any{
			"type": "masque", "tag": "warp", "use_http2": true,
			// recreate discards any cached account, which is what makes this a
			// registration rather than a reuse of somebody else's.
			"profile":     map[string]any{"recreate": true},
			"server_name": cfg.WARP.SNI,
			"port":        cfg.WARP.Port,
		}},
	}
}
