// Package client turns a generated deployment into something a person can
// actually connect with.
//
// Without this the installer stops one step short of the point: `init` mints
// every key, `up` starts the server, `selftest` proves it defends itself — and
// the operator is left holding a list of UUIDs and passwords with no way to
// turn them into a working client short of hand-writing a config for each of
// eleven protocols.
//
// Three artifact shapes, because no single one covers everything:
//
//   - a sing-box client config, which covers every protocol the core speaks,
//     including the two that have no share-URL form at all;
//   - share URLs, for the protocols that have a standard one and can therefore
//     be pasted into any client;
//   - WireGuard/AmneziaWG `.conf` files, which is what the Amnezia clients and
//     wg-quick read.
//
// What cannot be emitted is reported rather than skipped silently. A bundle
// that is quietly missing a protocol is worse than one that says why.
package client

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// Endpoint describes how a client reaches this deployment. The generated
// server config binds wildcards, so none of this can be derived from it.
type Endpoint struct {
	// Host is the public hostname or address clients dial.
	Host string

	// CDNHost is where the websocket inbound is reachable from outside. That
	// inbound deliberately binds loopback and expects a CDN or reverse proxy
	// to terminate TLS in front of it, so its public endpoint is a different
	// host and port entirely — and nothing in the deployment knows them.
	// Empty means the protocol is omitted with that reason recorded.
	CDNHost string
	CDNPort uint16

	// TLSFingerprint is the browser fingerprint uTLS should imitate.
	TLSFingerprint string
}

// DefaultTLSFingerprint is what share URLs advertise when nothing else is set.
const DefaultTLSFingerprint = "chrome"

// Omission is a protocol that could not be put into a bundle, and why.
type Omission struct {
	Protocol profile.Protocol
	Artifact string
	Reason   string
}

// Bundle is everything one user needs.
type Bundle struct {
	User string

	// SingBox is a complete client configuration covering every reachable
	// protocol, with a urltest group in front of them.
	SingBox []byte

	// URLs are the share links, in a stable order.
	URLs []string

	// WireGuard holds one wg-quick/Amnezia style config per endpoint.
	WireGuard map[profile.Protocol]string

	// Subscription is the conventional format: the URL list, newline
	// separated, base64 encoded.
	Subscription []byte

	// Omitted records what is deliberately absent.
	Omitted []Omission
}

// Generate builds a bundle per user.
func Generate(spec profile.Spec, secrets profile.Secrets, endpoint Endpoint) ([]Bundle, error) {
	if endpoint.Host == "" {
		return nil, fmt.Errorf("no public host: the server config binds wildcard addresses, so the address a client dials cannot be derived from it")
	}
	if endpoint.TLSFingerprint == "" {
		endpoint.TLSFingerprint = DefaultTLSFingerprint
	}

	enabled := spec.EnabledProtocols()
	bundles := make([]Bundle, 0, len(secrets.Users))
	for _, user := range secrets.Users {
		bundle := Bundle{User: user.Name, WireGuard: map[profile.Protocol]string{}}

		config, omitted, err := singBoxConfig(spec, secrets, user, endpoint, enabled)
		if err != nil {
			return nil, fmt.Errorf("%s: build client config: %w", user.Name, err)
		}
		bundle.SingBox = config
		bundle.Omitted = append(bundle.Omitted, omitted...)

		urls, urlOmitted := shareURLs(spec, secrets, user, endpoint, enabled)
		bundle.URLs = urls
		bundle.Omitted = append(bundle.Omitted, urlOmitted...)

		for _, p := range enabled {
			if !p.IsWireGuard() {
				continue
			}
			conf, err := wireGuardConfig(spec, secrets, user, endpoint, p)
			if err != nil {
				bundle.Omitted = append(bundle.Omitted, Omission{p, "wireguard .conf", err.Error()})
				continue
			}
			bundle.WireGuard[p] = conf
		}

		if len(urls) > 0 {
			// The conventional subscription format: the links, one per line,
			// base64 of the whole thing. Standard base64 rather than raw-url,
			// because that is what clients decode.
			bundle.Subscription = []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(urls, "\n") + "\n")))
		}

		sort.Slice(bundle.Omitted, func(i, j int) bool {
			if bundle.Omitted[i].Protocol != bundle.Omitted[j].Protocol {
				return bundle.Omitted[i].Protocol < bundle.Omitted[j].Protocol
			}
			return bundle.Omitted[i].Artifact < bundle.Omitted[j].Artifact
		})
		bundles = append(bundles, bundle)
	}
	return bundles, nil
}

// shareURLs renders the links for the protocols that have a standard form.
//
// Most do not. shadowtls-over-shadowsocks is a two-layer chain with no URL
// representation at all; snell's client format is Surge's ini, not a URI; and
// mieru carries its own config format. Those reach the user through the
// sing-box config instead, and are recorded here as omissions so that the
// absence is visible rather than mysterious.
func shareURLs(spec profile.Spec, secrets profile.Secrets, user profile.UserSecrets, endpoint Endpoint, enabled []profile.Protocol) ([]string, []Omission) {
	var urls []string
	var omitted []Omission

	for _, p := range enabled {
		switch p {
		case profile.VLESSReality:
			query := url.Values{}
			query.Set("encryption", "none")
			query.Set("security", "reality")
			query.Set("sni", spec.RealityHandshakeServer)
			query.Set("fp", endpoint.TLSFingerprint)
			query.Set("pbk", secrets.Reality.PublicKey)
			query.Set("sid", secrets.Reality.ShortID)
			query.Set("type", "http")
			query.Set("path", realityPath(secrets))
			urls = append(urls, fmt.Sprintf("vless://%s@%s:%d?%s#%s",
				user.VLESSRealityUUID, hostForURL(endpoint.Host), spec.Ports[p],
				query.Encode(), url.PathEscape(label(user.Name, p))))

		case profile.VLESSWSCDN:
			if endpoint.CDNHost == "" {
				omitted = append(omitted, Omission{p, "share URL",
					"needs the CDN hostname: this inbound binds loopback and a CDN terminates TLS in front of it, so its public endpoint is not in the server config"})
				continue
			}
			port := endpoint.CDNPort
			if port == 0 {
				port = 443
			}
			query := url.Values{}
			query.Set("encryption", "none")
			query.Set("security", "tls")
			query.Set("sni", endpoint.CDNHost)
			query.Set("fp", endpoint.TLSFingerprint)
			query.Set("type", "ws")
			query.Set("path", "/cdnws")
			query.Set("host", endpoint.CDNHost)
			urls = append(urls, fmt.Sprintf("vless://%s@%s:%d?%s#%s",
				user.VLESSWSCDNUUID, hostForURL(endpoint.CDNHost), port,
				query.Encode(), url.PathEscape(label(user.Name, p))))

		case profile.MTProto:
			// Telegram's own scheme, and the only artifact possible here: the
			// core registers mtproto as an inbound only, so there is no
			// sing-box outbound to put it in a client config.
			// The user's own secret, which attributes their traffic; the
			// shared legacy one only for a user who has none.
			secret := user.MTProtoSecret
			if secret == "" {
				secret = secrets.MTProto.Secret
			}
			if secret == "" {
				continue
			}
			urls = append(urls, fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s",
				url.QueryEscape(endpoint.Host), spec.Ports[p], secret))

		case profile.Shadowsocks:
			omitted = append(omitted, Omission{p, "share URL",
				"reachable only through the shadowtls chain, which has no URL form; it is in the sing-box config"})
		case profile.ShadowTLS:
			omitted = append(omitted, Omission{p, "share URL",
				"shadowtls is a transport for the shadowsocks inbound, not a destination; the pair is in the sing-box config"})
		case profile.Snell:
			omitted = append(omitted, Omission{p, "share URL",
				"snell's client format is Surge's ini, not a URI; it is in the sing-box config"})
		case profile.Mieru:
			omitted = append(omitted, Omission{p, "share URL",
				"mieru carries its own config format and has no URI form; it is in the sing-box config"})

		// Tier B. The three with a URI form all address the domain, because
		// that is the name on the certificate they present.
		case profile.Hysteria2:
			query := url.Values{}
			query.Set("sni", spec.Domain)
			query.Set("obfs", secrets.TierB.Hysteria2ObfsType)
			query.Set("obfs-password", secrets.TierB.Hysteria2ObfsPassword)
			urls = append(urls, fmt.Sprintf("hysteria2://%s@%s:%d?%s#%s",
				url.QueryEscape(user.Hysteria2Password), hostForURL(spec.Domain), spec.Ports[p],
				query.Encode(), url.PathEscape(label(user.Name, p))))

		case profile.TUIC:
			query := url.Values{}
			query.Set("sni", spec.Domain)
			query.Set("alpn", "h3")
			query.Set("congestion_control", spec.TUICCongestionControl)
			urls = append(urls, fmt.Sprintf("tuic://%s:%s@%s:%d?%s#%s",
				user.TUICUUID, url.QueryEscape(user.TUICPassword),
				hostForURL(spec.Domain), spec.Ports[p],
				query.Encode(), url.PathEscape(label(user.Name, p))))

		case profile.AnyTLS:
			query := url.Values{}
			query.Set("sni", spec.Domain)
			urls = append(urls, fmt.Sprintf("anytls://%s@%s:%d?%s#%s",
				url.QueryEscape(user.AnyTLSPassword), hostForURL(spec.Domain), spec.Ports[p],
				query.Encode(), url.PathEscape(label(user.Name, p))))

		case profile.VLESSXHTTP:
			query := url.Values{}
			query.Set("encryption", "none")
			query.Set("security", "reality")
			// The borrowed host, not the domain: this inbound has no
			// certificate of its own.
			query.Set("sni", secrets.TierB.Facts.XHTTPSNI)
			query.Set("fp", endpoint.TLSFingerprint)
			query.Set("pbk", secrets.TierB.XHTTPReality.PublicKey)
			query.Set("sid", secrets.TierB.XHTTPReality.ShortID)
			query.Set("type", "xhttp")
			query.Set("mode", "auto")
			query.Set("path", secrets.TierB.Facts.XHTTPPath)
			urls = append(urls, fmt.Sprintf("vless://%s@%s:%d?%s#%s",
				user.VLESSXHTTPUUID, hostForURL(endpoint.Host), spec.Ports[p],
				query.Encode(), url.PathEscape(label(user.Name, p))))

		case profile.Naive:
			// naive's own client takes a URL of this shape. It is not a
			// sing-box outbound — the core registers naive as an inbound only.
			urls = append(urls, fmt.Sprintf("https://%s:%s@%s:%d#%s",
				url.QueryEscape(user.Name), url.QueryEscape(user.NaivePassword),
				hostForURL(spec.Domain), spec.Ports[p], url.PathEscape(label(user.Name, p))))

		case profile.MASQUEWG:
			omitted = append(omitted, Omission{p, "share URL",
				"it is the public front for " + string(profile.WGMasque) + " rather than a proxy; what a client needs is that endpoint's WireGuard .conf plus this host and port"})
		}
	}
	return urls, omitted
}

// wireGuardConfig renders a wg-quick style config, with the AmneziaWG
// parameters appended when the endpoint carries them.
func wireGuardConfig(spec profile.Spec, secrets profile.Secrets, user profile.UserSecrets, endpoint Endpoint, p profile.Protocol) (string, error) {
	peer, ok := user.Peers[p]
	if !ok {
		return "", fmt.Errorf("no peer for this user")
	}
	server, ok := secrets.Endpoints[p]
	if !ok {
		return "", fmt.Errorf("no server keypair recorded")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# %s — %s\n", label(user.Name, p), p)
	switch p {
	case profile.WGMasque:
		b.WriteString("# Plain WireGuard on purpose: this endpoint sits behind MASQUE.\n")
		b.WriteString("# It is NOT reachable directly — the client must carry the MASQUE\n")
		b.WriteString("# transport and dial it through that.\n")
	case profile.WGWDTT:
		b.WriteString("# Plain WireGuard on purpose: this endpoint sits behind the\n")
		b.WriteString("# WG-over-VK relay. It is NOT reachable directly — the client must\n")
		b.WriteString("# speak that transport.\n")
	}
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", peer.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", peer.Address)
	if server.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", server.MTU)
	}
	b.WriteString("DNS = 1.1.1.1\n")

	if server.HasAWGParams {
		o := server.Obfuscation
		b.WriteString("\n# AmneziaWG obfuscation. These MUST match the server exactly;\n")
		b.WriteString("# a mismatch fails the handshake with no diagnostic.\n")
		fmt.Fprintf(&b, "Jc = %d\nJmin = %d\nJmax = %d\n", o.Jc, o.Jmin, o.Jmax)
		fmt.Fprintf(&b, "S1 = %d\nS2 = %d\n", o.S1, o.S2)
		if o.S3 != 0 || o.S4 != 0 {
			fmt.Fprintf(&b, "S3 = %d\nS4 = %d\n", o.S3, o.S4)
		}
		fmt.Fprintf(&b, "H1 = %s\nH2 = %s\nH3 = %s\nH4 = %s\n", o.H1, o.H2, o.H3, o.H4)
		for _, kv := range []struct{ k, v string }{
			{"I1", o.I1}, {"I2", o.I2},
			{"HeaderProtectionKey", o.HeaderProtectionKey},
			{"ContentPaddingAddition", o.ContentPaddingAddition},
			{"RekeyAfterTime", o.RekeyAfterTime},
			{"RekeyTimeout", o.RekeyTimeout},
			{"RejectAfterTime", o.RejectAfterTime},
			{"KeepaliveTimeout", o.KeepaliveTimeout},
			{"MaxHandshakeAttempts", o.MaxHandshakeAttempts},
		} {
			if kv.v != "" {
				fmt.Fprintf(&b, "%s = %s\n", kv.k, kv.v)
			}
		}
		if o.RandomTrailers {
			b.WriteString("RandomTrailers = true\n")
		}
	}

	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", server.PublicKey)
	fmt.Fprintf(&b, "AllowedIPs = 0.0.0.0/0, ::/0\n")
	fmt.Fprintf(&b, "Endpoint = %s:%d\n", endpoint.Host, server.ListenPort)
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String(), nil
}

// realityPath returns the HTTP transport path the server was generated with.
//
// Read from the deployment record rather than re-derived from the short_id:
// two derivations that must agree are two chances to disagree, and the symptom
// of disagreement is a client that connects and is then dropped.
func realityPath(secrets profile.Secrets) string {
	return secrets.Deployment.RealityTransportPath
}

func label(user string, p profile.Protocol) string {
	return user + "@" + string(p)
}

// hostForURL brackets an IPv6 literal, which is otherwise ambiguous against
// the port separator.
func hostForURL(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}
