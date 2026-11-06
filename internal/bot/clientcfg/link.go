package clientcfg

import (
	"fmt"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/keys"
)

// Link renders the share URI for an inbound, or "" when the protocol has no
// clean one and is handed out as a config file instead.
//
// Parameter order is fixed rather than sorted: these links are compared against
// what the bot handed out before, and a reordered query is a different string
// even when it is the same configuration.
func Link(cfg bot.Config, in Inbound, user User) (string, error) {
	name := user.Name

	// A CDN-fronted inbound is reached at the edge, not at the host, and with
	// the edge's own SNI. Checked before the protocol switch because the
	// address changes, not just a parameter.
	if front, ok := cfg.Public.CDN[in.Tag]; ok {
		transportType := in.TransportType()
		if transportType == "" {
			transportType = "ws"
		}
		path := in.TransportPath()
		if path == "" {
			path = "/"
		}
		q := query{}
		q.add("encryption", "none")
		q.add("type", transportType)
		q.add("security", "tls")
		q.add("sni", front.SNI)
		q.add("host", front.Host)
		q.add("path", path)
		q.add("fp", "chrome")
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
			user.UUID, front.Host, front.Port, q.encode(), escape(name)), nil
	}

	host := cfg.Public.Host
	switch in.Type {
	case "vless":
		return vlessLink(host, in, user, name)
	case "hysteria2":
		q := query{}
		q.add("sni", in.ServerName())
		if in.Obfs != nil && in.Obfs.Type != "" {
			q.add("obfs", in.Obfs.Type)
			q.add("obfs-password", in.Obfs.Password)
		}
		return fmt.Sprintf("hysteria2://%s@%s:%d?%s#%s",
			escape(user.Password), host, in.ListenPort, q.encode(), escape(name)), nil
	case "tuic":
		congestion := in.CongestionControl
		if congestion == "" {
			congestion = "bbr"
		}
		alpn := "h3"
		if in.TLS != nil {
			if first := in.TLS.ALPN.First(); first != "" {
				alpn = first
			}
		}
		q := query{}
		q.add("congestion_control", congestion)
		q.add("alpn", alpn)
		q.add("sni", in.ServerName())
		return fmt.Sprintf("tuic://%s:%s@%s:%d?%s#%s",
			user.UUID, escape(user.Password), host, in.ListenPort, q.encode(), escape(name)), nil
	case "anytls":
		q := query{}
		q.add("sni", in.ServerName())
		return fmt.Sprintf("anytls://%s@%s:%d?%s#%s",
			escape(user.Password), host, in.ListenPort, q.encode(), escape(name)), nil
	case "mtproto":
		// The user's own secret, which attributes their Telegram traffic to
		// them; the inbound's shared one only for an account that predates it.
		secret := user.Secret
		if secret == "" {
			secret = in.Secret
		}
		return fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s", host, in.ListenPort, secret), nil
	}
	return "", nil
}

func vlessLink(host string, in Inbound, user User, name string) (string, error) {
	transportType := in.TransportType()
	if transportType == "" {
		transportType = "tcp"
	}
	security := "none"
	switch {
	case in.RealityEnabled():
		security = "reality"
	case in.TLS != nil && in.TLS.Enabled:
		security = "tls"
	}

	q := query{}
	q.add("encryption", "none")
	q.add("type", transportType)
	q.add("security", security)
	q.add("sni", in.ServerName())
	q.add("fp", "chrome")

	if in.RealityEnabled() && in.TLS.Reality.PrivateKey != "" {
		pair, err := keys.X25519FromPrivate(in.TLS.Reality.PrivateKey)
		if err != nil {
			return "", fmt.Errorf("clientcfg: reality public key for %s: %w", in.Tag, err)
		}
		q.add("pbk", pair.PublicURL())
		q.add("sid", in.TLS.Reality.ShortID.First())
	}
	if user.Flow != "" {
		q.add("flow", user.Flow)
	}
	if transportType == "http" && in.Transport != nil {
		q.add("host", in.Transport.Host.First())
	}
	// Any transport that defines a path needs it in the URI, not only http: the
	// server routes on it and a client defaulting to "/" reaches nothing.
	// Nesting this under the http case is what once dropped /xh from the xhttp
	// link, leaving an inbound nobody could use.
	q.add("path", in.TransportPath())

	return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		user.UUID, host, in.ListenPort, q.encode(), escape(name)), nil
}

// query builds a query string in insertion order, skipping empty values.
type query struct {
	parts []string
}

func (q *query) add(key, value string) {
	if value == "" {
		return
	}
	q.parts = append(q.parts, escape(key)+"="+escape(value))
}

func (q *query) encode() string { return strings.Join(q.parts, "&") }

// escape percent-encodes everything outside the unreserved set.
//
// Written out rather than taken from net/url: QueryEscape renders a space as
// "+", PathEscape leaves several reserved characters alone, and the strings
// here are compared against links handed out earlier, where a space is %20.
func escape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}
