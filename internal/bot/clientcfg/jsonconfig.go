package clientcfg

import (
	"encoding/json"
	"fmt"

	"github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/keys"
)

// JSONConfigInput is what a config-file protocol needs beyond its own inbound.
//
// ShadowTLS is the reason this exists: it is a pair, and the credentials of
// its shadowsocks backend live in a different inbound. Passing that in keeps
// the generator a pure function instead of hiding an API call inside it.
type JSONConfigInput struct {
	Inbound Inbound
	User    User
	// Backend is the shadowsocks inbound ShadowTLS detours through. Required
	// for shadowtls, ignored otherwise.
	Backend *Inbound
}

// JSONConfig renders a whole client config for the protocols that have no
// clean share URI.
//
// naive is the odd one: what comes back is a naiveproxy client config, not
// sing-box, because that is what the naiveproxy binary reads. Callers must not
// feed it to a sing-box validator.
func JSONConfig(cfg bot.Config, in JSONConfigInput) ([]byte, error) {
	host := cfg.Public.Host
	inbound, user := in.Inbound, in.User

	if inbound.Type == "naive" {
		return marshal(map[string]any{
			"listen": "socks://127.0.0.1:1080",
			"proxy": fmt.Sprintf("https://%s:%s@%s:%d",
				user.Username, user.Password, host, inbound.ListenPort),
		})
	}

	var outbounds []any
	switch inbound.Type {
	case "mieru":
		outbounds = []any{
			map[string]any{
				"type": "mieru", "tag": "proxy", "server": host, "server_port": inbound.ListenPort,
				"username": user.Username, "password": user.Password,
				"transport": inbound.MieruTransport(),
			},
		}
	case "snell":
		snell := map[string]any{
			"type": "snell", "tag": "proxy", "server": host, "server_port": inbound.ListenPort,
			"version": snellVersion(inbound), "psk": inbound.PSK, "userkey": user.UserKey,
		}
		if inbound.Mode != "" {
			snell["mode"] = inbound.Mode
		}
		outbounds = []any{snell}
	case "shadowtls":
		if in.Backend == nil {
			return nil, fmt.Errorf("clientcfg: shadowtls needs its shadowsocks backend")
		}
		handshake := "www.microsoft.com"
		if inbound.Handshake != nil && inbound.Handshake.Server != "" {
			handshake = inbound.Handshake.Server
		}
		outbounds = []any{
			// The visible leg is shadowsocks, detoured through the ShadowTLS
			// one: the handshake is real TLS to a legitimate domain and the
			// proxy traffic rides inside it.
			map[string]any{
				"type": "shadowsocks", "tag": "proxy", "server": host,
				"server_port": inbound.ListenPort,
				"method":      in.Backend.Method, "password": in.Backend.Password,
				"detour":    "stls",
				"multiplex": map[string]any{"enabled": true},
			},
			map[string]any{
				"type": "shadowtls", "tag": "stls", "server": host,
				"server_port": inbound.ListenPort, "version": 3,
				"password": user.Password,
				"tls": map[string]any{
					"enabled": true, "server_name": handshake,
					"utls": map[string]any{"enabled": true, "fingerprint": "chrome"},
				},
			},
		}
	case "vless":
		node, err := vlessJSONOutbound(host, inbound, user)
		if err != nil {
			return nil, err
		}
		outbounds = []any{node}
	default:
		return nil, fmt.Errorf("clientcfg: %s has no config-file form", inbound.Type)
	}

	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})
	return marshal(map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{
			map[string]any{"type": "mixed", "listen": "127.0.0.1", "listen_port": 2080},
		},
		"outbounds": outbounds,
		"route":     map[string]any{"final": "proxy"},
	})
}

// vlessJSONOutbound is the XHTTP form: this path exists because obfs mode
// cannot be expressed as a share URI at all, so the padding fields have
// nowhere else to go.
func vlessJSONOutbound(host string, in Inbound, user User) (map[string]any, error) {
	tls := map[string]any{
		"enabled": true, "server_name": in.ServerName(),
		"utls": map[string]any{"enabled": true, "fingerprint": "chrome"},
	}
	if in.RealityEnabled() {
		if in.TLS.Reality.PrivateKey == "" {
			return nil, fmt.Errorf("clientcfg: %s enables reality with no private key", in.Tag)
		}
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

	path := in.TransportPath()
	if path == "" {
		path = "/"
	}
	padding := "100-1000"
	if in.Transport != nil && in.Transport.XPaddingBytes != "" {
		padding = in.Transport.XPaddingBytes
	}
	transport := map[string]any{
		"type": "xhttp", "path": path, "x_padding_bytes": padding,
	}
	for key, value := range in.XHTTPObfsFields() {
		transport[key] = value
	}

	return map[string]any{
		"type": "vless", "tag": "proxy", "server": host, "server_port": in.ListenPort,
		"uuid": user.UUID, "tls": tls, "transport": transport,
	}, nil
}

func marshal(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("clientcfg: render config: %w", err)
	}
	return data, nil
}
