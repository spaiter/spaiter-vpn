package client

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
	xbadoption "github.com/spaiter/spaiter-vpn/core/common/xray/json/badoption"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/option"

	"github.com/spaiter/spaiter-vpn/internal/config"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// LocalProxyPort is where the generated client listens.
//
// A mixed (HTTP + SOCKS) inbound on loopback rather than a tun: tun needs root
// and a working route table, and the first thing anyone does with a fresh
// server is point one application at it to see whether it works at all.
const LocalProxyPort = 2080

// proxyTag is the urltest group every route ends at.
const proxyTag = "proxy"

// singBoxConfig builds the client configuration.
//
// It is generated from the same option structs as the server's, which is the
// whole reason this is worth doing in Go: the two sides cannot drift into
// disagreeing about a field name, and the result can be handed to
// `sing-box check` exactly like the server config.
func singBoxConfig(
	spec profile.Spec,
	secrets profile.Secrets,
	user profile.UserSecrets,
	endpoint Endpoint,
	enabled []profile.Protocol,
) ([]byte, []Omission, error) {
	var outbounds []option.Outbound
	var proxyTags []string
	var omitted []Omission

	add := func(o option.Outbound, selectable bool) {
		outbounds = append(outbounds, o)
		if selectable {
			proxyTags = append(proxyTags, o.Tag)
		}
	}

	for _, p := range enabled {
		switch p {
		case profile.VLESSReality:
			add(option.Outbound{
				Type: C.TypeVLESS,
				Tag:  string(p),
				Options: &option.VLESSOutboundOptions{
					ServerOptions: option.ServerOptions{Server: endpoint.Host, ServerPort: spec.Ports[p]},
					UUID:          user.VLESSRealityUUID,
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{
							Enabled:    true,
							ServerName: spec.RealityHandshakeServer,
							UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: endpoint.TLSFingerprint},
							Reality: &option.OutboundRealityOptions{
								Enabled:   true,
								PublicKey: secrets.Reality.PublicKey,
								ShortID:   secrets.Reality.ShortID,
							},
						},
					},
					Transport: &option.V2RayTransportOptions{
						Type:        C.V2RayTransportTypeHTTP,
						HTTPOptions: option.V2RayHTTPOptions{Path: realityPath(secrets)},
					},
				},
			}, true)

		case profile.ShadowTLS:
			// The chain: a shadowsocks outbound whose dialer detours through a
			// shadowtls outbound. Only the shadowsocks end is selectable —
			// shadowtls on its own is a transport, not a destination, and
			// putting it in the urltest group would have it dialled as if it
			// were one.
			add(option.Outbound{
				Type: C.TypeShadowTLS,
				Tag:  string(p),
				Options: &option.ShadowTLSOutboundOptions{
					ServerOptions: option.ServerOptions{Server: endpoint.Host, ServerPort: spec.Ports[p]},
					Version:       spec.ShadowTLSVersion,
					Password:      user.ShadowTLSPassword,
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{
							Enabled:    true,
							ServerName: spec.ShadowTLSHandshakeServer,
							UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: endpoint.TLSFingerprint},
						},
					},
				},
			}, false)

		case profile.Shadowsocks:
			add(option.Outbound{
				Type: C.TypeShadowsocks,
				Tag:  string(p),
				Options: &option.ShadowsocksOutboundOptions{
					// No server of its own: it rides the shadowtls chain, and
					// the detour is what carries it. The server fields still
					// have to be set because the protocol greets a host.
					DialerOptions: option.DialerOptions{Detour: string(profile.ShadowTLS)},
					ServerOptions: option.ServerOptions{Server: endpoint.Host, ServerPort: spec.Ports[profile.ShadowTLS]},
					Method:        secrets.Shadowsocks.Method,
					Password:      secrets.Shadowsocks.Password,
					Multiplex:     &option.OutboundMultiplexOptions{Enabled: true},
				},
			}, true)

		case profile.Snell:
			add(option.Outbound{
				Type: C.TypeSnell,
				Tag:  string(p),
				Options: &option.SnellOutboundOptions{
					ServerOptions: option.ServerOptions{Server: endpoint.Host, ServerPort: spec.Ports[p]},
					Version:       secrets.Snell.Version,
					PSK:           secrets.Snell.PSK,
					UserKey:       user.SnellUserKey,
				},
			}, true)

		case profile.Mieru:
			add(option.Outbound{
				Type: C.TypeMieru,
				Tag:  string(p),
				Options: &option.MieruOutboundOptions{
					ServerOptions: option.ServerOptions{Server: endpoint.Host, ServerPort: spec.Ports[p]},
					UserName:      user.Name,
					Password:      user.MieruPassword,
					PortBindings:  []option.MieruPortBinding{{Protocol: "TCP", Port: spec.Ports[p]}},
				},
			}, true)

		case profile.VLESSWSCDN:
			if endpoint.CDNHost == "" {
				omitted = append(omitted, Omission{p, "sing-box outbound",
					"needs the CDN hostname: the inbound binds loopback and a CDN terminates TLS in front of it"})
				continue
			}
			port := endpoint.CDNPort
			if port == 0 {
				port = 443
			}
			add(option.Outbound{
				Type: C.TypeVLESS,
				Tag:  string(p),
				Options: &option.VLESSOutboundOptions{
					ServerOptions: option.ServerOptions{Server: endpoint.CDNHost, ServerPort: port},
					UUID:          user.VLESSWSCDNUUID,
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{
							Enabled:    true,
							ServerName: endpoint.CDNHost,
							UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: endpoint.TLSFingerprint},
						},
					},
					Transport: &option.V2RayTransportOptions{
						Type: C.V2RayTransportTypeWebsocket,
						WebsocketOptions: option.V2RayWebsocketOptions{
							Path:                "/cdnws",
							EarlyDataHeaderName: "Sec-WebSocket-Protocol",
						},
					},
				},
			}, true)

		case profile.MTProto:
			omitted = append(omitted, Omission{p, "sing-box outbound",
				"the core registers mtproto as an inbound only, so there is no outbound to put here; use the tg:// link"})

		case profile.AWG2, profile.AWG3, profile.WGMasque, profile.WGWDTT:
			omitted = append(omitted, Omission{p, "sing-box outbound",
				"delivered as a WireGuard .conf instead, which is what the Amnezia clients and wg-quick read"})

		// Tier B. Every one of these dials the domain rather than the endpoint
		// host, and that is not interchangeable: the server presents a
		// certificate for the domain, so a client connecting by address gets a
		// name mismatch and refuses the handshake.
		case profile.Hysteria2:
			add(option.Outbound{
				Type: C.TypeHysteria2,
				Tag:  string(p),
				Options: &option.Hysteria2OutboundOptions{
					ServerOptions: option.ServerOptions{Server: tierBHost(spec, endpoint), ServerPort: spec.Ports[p]},
					Password:      user.Hysteria2Password,
					Obfs: &option.Hysteria2Obfs{
						Type:     secrets.TierB.Hysteria2ObfsType,
						Password: secrets.TierB.Hysteria2ObfsPassword,
					},
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: spec.Domain},
					},
				},
			}, true)

		case profile.TUIC:
			add(option.Outbound{
				Type: C.TypeTUIC,
				Tag:  string(p),
				Options: &option.TUICOutboundOptions{
					ServerOptions:     option.ServerOptions{Server: tierBHost(spec, endpoint), ServerPort: spec.Ports[p]},
					UUID:              user.TUICUUID,
					Password:          user.TUICPassword,
					CongestionControl: spec.TUICCongestionControl,
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{
							Enabled:    true,
							ServerName: spec.Domain,
							ALPN:       badoption.Listable[string]{"h3"},
						},
					},
				},
			}, true)

		case profile.AnyTLS:
			add(option.Outbound{
				Type: C.TypeAnyTLS,
				Tag:  string(p),
				Options: &option.AnyTLSOutboundOptions{
					ServerOptions: option.ServerOptions{Server: tierBHost(spec, endpoint), ServerPort: spec.Ports[p]},
					Password:      user.AnyTLSPassword,
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: spec.Domain},
					},
				},
			}, true)

		case profile.VLESSXHTTP:
			// Reality again, so the SNI is the borrowed host and not the
			// domain — this is the one Tier B protocol with no certificate.
			add(option.Outbound{
				Type: C.TypeVLESS,
				Tag:  string(p),
				Options: &option.VLESSOutboundOptions{
					ServerOptions: option.ServerOptions{Server: endpoint.Host, ServerPort: spec.Ports[p]},
					UUID:          user.VLESSXHTTPUUID,
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{
							Enabled:    true,
							ServerName: secrets.TierB.Facts.XHTTPSNI,
							UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: endpoint.TLSFingerprint},
							Reality: &option.OutboundRealityOptions{
								Enabled:   true,
								PublicKey: secrets.TierB.XHTTPReality.PublicKey,
								ShortID:   secrets.TierB.XHTTPReality.ShortID,
							},
						},
					},
					Transport: &option.V2RayTransportOptions{
						Type: C.V2RayTransportTypeXHTTP,
						XHTTPOptions: option.V2RayXHTTPOptions{
							Mode: "auto",
							V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{
								Path: secrets.TierB.Facts.XHTTPPath,
								// Mandatory here for the same reason as on the
								// server: a zero range reads as "disabled" and
								// is rejected.
								XPaddingBytes: xbadoption.Range{From: 100, To: 1000},
							},
						},
					},
				},
			}, true)

		case profile.Naive:
			omitted = append(omitted, Omission{p, "sing-box outbound",
				"the core registers naive as an inbound only; use the naive client with the printed credentials"})

		case profile.MASQUEWG:
			omitted = append(omitted, Omission{p, "sing-box outbound",
				"it is the public front for " + string(profile.WGMasque) + ", not a proxy of its own; the WireGuard .conf for that endpoint is what a client uses"})
		}
	}

	if len(proxyTags) == 0 {
		return nil, omitted, fmt.Errorf("no protocol in this deployment can be reached by a sing-box client")
	}

	// urltest rather than a selector: it picks whatever currently answers,
	// which is the behaviour someone with eleven transports actually wants.
	outbounds = append(outbounds, option.Outbound{
		Type: C.TypeURLTest,
		Tag:  proxyTag,
		Options: &option.URLTestOutboundOptions{
			Outbounds: proxyTags,
			URL:       "https://www.gstatic.com/generate_204",
			Interval:  badoption.Duration(3 * 60 * 1000 * 1000 * 1000),
			Tolerance: 50,
		},
	})
	outbounds = append(outbounds, option.Outbound{
		Type:    C.TypeDirect,
		Tag:     "direct",
		Options: &option.DirectOutboundOptions{},
	})

	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	options := option.Options{
		Log: &option.LogOptions{Level: "warn", Timestamp: true},
		Inbounds: []option.Inbound{{
			Type: C.TypeMixed,
			Tag:  "local",
			Options: &option.HTTPMixedInboundOptions{
				ListenOptions: option.ListenOptions{Listen: &listen, ListenPort: LocalProxyPort},
			},
		}},
		Outbounds: outbounds,
		Route:     &option.RouteOptions{Final: proxyTag},
	}

	data, err := config.Marshal(context.Background(), options)
	if err != nil {
		return nil, omitted, err
	}
	return data, omitted, nil
}

// tierBHost is what a Tier B client dials.
//
// The domain, not the endpoint address, and the distinction is load-bearing:
// these inbounds present a certificate issued for the domain, so a client
// connecting by IP gets a name mismatch and refuses the handshake before any
// authentication happens. The endpoint host is only a fallback for a
// certificate-free deployment.
func tierBHost(spec profile.Spec, endpoint Endpoint) string {
	if spec.Domain != "" {
		return spec.Domain
	}
	return endpoint.Host
}
