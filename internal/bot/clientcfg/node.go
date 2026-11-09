package clientcfg

import (
	"fmt"

	"github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/keys"
)

// Node is one sing-box outbound, as a client reads it.
//
// A map rather than a struct per protocol: the fields are flattened per type
// and the client core is the authority on them. What matters is that only the
// keys the protocol defines are present -- an extra one is rejected outright,
// which is how a whole subscription stopped decoding on 2026-10-31.
type Node map[string]any

// BundleNode renders one node of the all-methods bundle, or nil when the
// inbound's type has no client outbound to offer.
//
// tagName is what the user sees in their client's node list, so it comes from
// the configured labels rather than the inbound tag.
func BundleNode(cfg bot.Config, in Inbound, user User, tagName string) (Node, error) {
	host := cfg.Public.Host

	// A CDN-fronted inbound is dialled at the edge with the edge's SNI, and
	// the origin host travels in a Host header rather than in the address.
	if front, ok := cfg.Public.CDN[in.Tag]; ok {
		transportType := in.TransportType()
		if transportType == "" {
			transportType = "ws"
		}
		path := in.TransportPath()
		if path == "" {
			path = "/"
		}
		return Node{
			"type": "vless", "tag": tagName,
			"server": front.Host, "server_port": front.Port,
			"uuid": user.UUID,
			"tls": map[string]any{
				"enabled": true, "server_name": front.SNI,
				"utls": map[string]any{"enabled": true, "fingerprint": "chrome"},
			},
			"transport": map[string]any{
				"type": transportType, "path": path,
				"headers": map[string]any{"Host": front.Host},
			},
		}, nil
	}

	switch in.Type {
	case "vless":
		return vlessNode(host, in, user, tagName)
	case "tuic":
		alpn := []string{"h3"}
		if in.TLS != nil && len(in.TLS.ALPN) > 0 {
			alpn = in.TLS.ALPN
		}
		congestion := in.CongestionControl
		if congestion == "" {
			congestion = "bbr"
		}
		return Node{
			"type": "tuic", "tag": tagName, "server": host, "server_port": in.ListenPort,
			"uuid": user.UUID, "password": user.Password,
			"congestion_control": congestion,
			"tls": map[string]any{
				"enabled": true, "server_name": in.ServerName(), "alpn": alpn,
			},
		}, nil
	case "hysteria2":
		node := Node{
			"type": "hysteria2", "tag": tagName, "server": host, "server_port": in.ListenPort,
			"password": user.Password,
			"tls":      map[string]any{"enabled": true, "server_name": in.ServerName()},
		}
		if in.Obfs != nil && in.Obfs.Type != "" {
			node["obfs"] = map[string]any{"type": in.Obfs.Type, "password": in.Obfs.Password}
		}
		return node, nil
	case "anytls":
		return Node{
			"type": "anytls", "tag": tagName, "server": host, "server_port": in.ListenPort,
			"password": user.Password,
			"tls":      map[string]any{"enabled": true, "server_name": in.ServerName()},
		}, nil
	case "mieru":
		// server_port plus transport, not portBindings: see MieruTransport.
		return Node{
			"type": "mieru", "tag": tagName, "server": host, "server_port": in.ListenPort,
			"username": user.Username, "password": user.Password,
			"transport": in.MieruTransport(),
		}, nil
	case "snell":
		node := Node{
			"type": "snell", "tag": tagName, "server": host, "server_port": in.ListenPort,
			"version": snellVersion(in), "psk": in.PSK, "userkey": user.UserKey,
		}
		if in.Mode != "" {
			// v6's mode has to match the server. The inbound runs unshaped
			// because default shaping corrupts downstream in this fork, so the
			// client has to mirror it rather than take its own default.
			node["mode"] = in.Mode
		}
		return node, nil
	case "naive":
		return Node{
			"type": "naive", "tag": tagName, "server": host, "server_port": in.ListenPort,
			"username": user.Username, "password": user.Password,
			"tls": map[string]any{"enabled": true, "server_name": in.ServerName()},
		}, nil
	}
	// trojan, vmess, hysteria v1, shadowtls and the rest are not offered as
	// bundle nodes. shadowtls arrives as a chain instead, since it needs its
	// shadowsocks backend beside it.
	return nil, nil
}

func vlessNode(host string, in Inbound, user User, tagName string) (Node, error) {
	tls := map[string]any{
		"enabled": true, "server_name": in.ServerName(),
		"utls": map[string]any{"enabled": true, "fingerprint": "chrome"},
	}
	if in.RealityEnabled() && in.TLS.Reality.PrivateKey != "" {
		pair, err := keys.X25519FromPrivate(in.TLS.Reality.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("clientcfg: reality public key for %s: %w", in.Tag, err)
		}
		tls["reality"] = map[string]any{
			"enabled":    true,
			"public_key": pair.PublicURL(),
			"short_id":   in.TLS.Reality.ShortID.First(),
		}
	}

	node := Node{
		"type": "vless", "tag": tagName, "server": host, "server_port": in.ListenPort,
		"uuid": user.UUID, "tls": tls,
	}
	if user.Flow != "" {
		node["flow"] = user.Flow
	}
	// Plain TCP needs no transport block at all; anything else needs its own.
	if t := in.TransportType(); t != "" && t != "tcp" {
		transport := map[string]any{"type": t}
		if path := in.TransportPath(); path != "" {
			transport["path"] = path
		}
		if t == "xhttp" {
			if in.Transport.XPaddingBytes != "" {
				transport["x_padding_bytes"] = in.Transport.XPaddingBytes
			}
			for key, value := range in.XHTTPObfsFields() {
				transport[key] = value
			}
		}
		if h := in.Transport.Host.First(); h != "" {
			transport["host"] = h
		}
		node["transport"] = transport
	}
	return node, nil
}

func snellVersion(in Inbound) int {
	if in.Version != 0 {
		return in.Version
	}
	return 6
}
