package profile

import (
	"fmt"

	"github.com/sagernet/sing/common/auth"
	xbadoption "github.com/spaiter/spaiter-vpn/core/common/xray/json/badoption"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/option"

	"github.com/spaiter/spaiter-vpn/internal/keys"
)

// The Tier B protocols. Tags and ports match the live deployment, for the same
// reason the Tier A ones do: an operator reading either config recognises the
// other, and existing port forwards carry over.
const (
	Hysteria2  Protocol = "hysteria-in"
	TUIC       Protocol = "tuic-in"
	AnyTLS     Protocol = "anytls-in"
	Naive      Protocol = "naive-in"
	VLESSXHTTP Protocol = "vless-xhttp-in"
	MASQUEWG   Protocol = "masque-wg-in"
)

// TierBProtocols is the set that a domain unlocks.
//
// VLESSXHTTP is declared beside these and keeps its secrets in TierBSecrets,
// where existing secrets files hold them, but it is a Tier A protocol: it runs
// Reality and needs no name. It was listed here once, which left every server
// without a domain without the transport that survives Russian mobile networks.
var TierBProtocols = []Protocol{
	Hysteria2,
	TUIC,
	AnyTLS,
	Naive,
	MASQUEWG,
}

// NeedsCertificate reports whether this protocol presents a certificate of its
// own, and therefore whether a certificate source has to be configured for it.
//
// The distinction is worth drawing rather than treating Tier B as monolithic:
// vless-xhttp runs on a bare IP with no name and no certificate, so an operator
// with no domain can still have it.
func (p Protocol) NeedsCertificate() bool {
	switch p {
	case Hysteria2, TUIC, AnyTLS, Naive, MASQUEWG:
		return true
	}
	return false
}

// DefaultTierBPorts is Tier B's share of the reference set; see DefaultPorts.
func DefaultTierBPorts() map[Protocol]uint16 {
	return map[Protocol]uint16{
		Hysteria2: 10862,
		TUIC:      10869,
		AnyTLS:    10874,
		Naive:     10872,
		MASQUEWG:  10876,
	}
}

// isTierB reports membership in the Tier B set.
func isTierB(p Protocol) bool {
	return contains(TierBProtocols, p)
}

// builtWithTierB reports whether buildTierBInbound builds p: the Tier B set,
// and vless-xhttp, whose secrets live beside theirs.
func builtWithTierB(p Protocol) bool {
	return p == VLESSXHTTP || isTierB(p)
}

// TierBSecrets is the shared, non-per-user half of Tier B.
type TierBSecrets struct {
	// Hysteria2ObfsPassword salts the QUIC packet obfuscation. Without obfs a
	// hysteria2 inbound is identifiable as QUIC with an unusual handshake; with
	// it the packets look like noise. It is shared by every client because it is
	// a transport-layer wrapper, not an identity — which also means rotating it
	// locks out every client at once.
	Hysteria2ObfsPassword string
	Hysteria2ObfsType     string

	// XHTTPReality is a *separate* keypair from the one VLESSReality uses.
	// Sharing one would mean a single leaked private key deanonymises both
	// inbounds, and there is no cost to minting two.
	XHTTPReality RealitySecrets

	// Facts is the non-secret half of the handover.
	Facts TierBFacts
}

// TierBFacts is the non-secret record of what Tier B deployed, the same
// handover DeploymentFacts performs for Tier A.
type TierBFacts struct {
	// Domain is the name the certificates are for and the name clients dial.
	Domain string
	// CertSource is how it was obtained, which is what an operator needs to
	// know before debugging an expired chain.
	CertSource CertSource

	// XHTTPSNI is the host whose handshake the xhttp inbound's Reality borrows,
	// and XHTTPPath its transport path. Both must match on the client exactly.
	XHTTPSNI  string
	XHTTPPath string

	// TUICCongestionControl has to match on the client side.
	TUICCongestionControl string
}

// buildTierBInbound builds one Tier B inbound.
func buildTierBInbound(spec Spec, p Protocol, secrets *Secrets, prev *Secrets) (*option.Inbound, error) {
	port := spec.Ports[p]
	domain := spec.Domain

	switch p {
	case Hysteria2:
		if prev != nil {
			secrets.TierB.Hysteria2ObfsPassword = prev.TierB.Hysteria2ObfsPassword
		}
		obfs, err := reuseOrMint(&secrets.TierB.Hysteria2ObfsPassword, "hysteria2 obfs password", func() (string, error) { return keys.Password(16) })
		if err != nil {
			return nil, err
		}
		secrets.TierB.Hysteria2ObfsType = C.Hysteria2ObfsTypeSalamander

		users := make([]option.Hysteria2User, 0, len(spec.Users))
		for i := range secrets.Users {
			if secrets.Users[i].Hysteria2Password == "" && !spec.mayMint(secrets.Users[i].Name, SlotHysteria2) {
				continue
			}
			password, err := reuseOrMint(&secrets.Users[i].Hysteria2Password, "hysteria2 password", func() (string, error) { return keys.Password(16) })
			if err != nil {
				return nil, err
			}
			users = append(users, option.Hysteria2User{Name: secrets.Users[i].Name, Password: password})
		}

		return &option.Inbound{
			Type: C.TypeHysteria2,
			Tag:  string(p),
			Options: &option.Hysteria2InboundOptions{
				ListenOptions: listenOn(spec.PublicListen, port),
				Users:         users,
				Obfs: &option.Hysteria2Obfs{
					Type:     C.Hysteria2ObfsTypeSalamander,
					Password: obfs,
				},
				// No up/down_mbps and IgnoreClientBandwidth left false: the
				// congestion control is then Brutal driven by the client's own
				// declared rate. Pinning a server-side ceiling here would cap
				// every client at whatever this host was provisioned for on the
				// day it was installed.
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: spec.Certs.inboundTLS(domain, nil),
				},
			},
		}, nil

	case TUIC:
		users := make([]option.TUICUser, 0, len(spec.Users))
		for i := range secrets.Users {
			if secrets.Users[i].TUICUUID == "" && secrets.Users[i].TUICPassword == "" && !spec.mayMint(secrets.Users[i].Name, SlotTUIC) {
				continue
			}
			uuid, err := reuseOrMint(&secrets.Users[i].TUICUUID, "tuic UUID", keys.UUID)
			if err != nil {
				return nil, err
			}
			password, err := reuseOrMint(&secrets.Users[i].TUICPassword, "tuic password", func() (string, error) { return keys.Password(16) })
			if err != nil {
				return nil, err
			}
			users = append(users, option.TUICUser{Name: secrets.Users[i].Name, UUID: uuid, Password: password})
		}

		return &option.Inbound{
			Type: C.TypeTUIC,
			Tag:  string(p),
			Options: &option.TUICInboundOptions{
				ListenOptions:     listenOn(spec.PublicListen, port),
				Users:             users,
				CongestionControl: spec.TUICCongestionControl,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					// h3 is not decorative: TUIC is QUIC, and a client that
					// offers h3 against a server that advertises nothing fails
					// ALPN negotiation outright.
					TLS: spec.Certs.inboundTLS(domain, []string{"h3"}),
				},
			},
		}, nil

	case AnyTLS:
		users := make([]option.AnyTLSUser, 0, len(spec.Users))
		for i := range secrets.Users {
			if secrets.Users[i].AnyTLSPassword == "" && !spec.mayMint(secrets.Users[i].Name, SlotAnyTLS) {
				continue
			}
			password, err := reuseOrMint(&secrets.Users[i].AnyTLSPassword, "anytls password", func() (string, error) { return keys.Password(16) })
			if err != nil {
				return nil, err
			}
			users = append(users, option.AnyTLSUser{Name: secrets.Users[i].Name, Password: password})
		}

		return &option.Inbound{
			Type: C.TypeAnyTLS,
			Tag:  string(p),
			Options: &option.AnyTLSInboundOptions{
				ListenOptions: listenOn(spec.PublicListen, port),
				Users:         users,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: spec.Certs.inboundTLS(domain, nil),
				},
			},
		}, nil

	case Naive:
		users := make([]auth.User, 0, len(spec.Users))
		for i := range secrets.Users {
			if secrets.Users[i].NaivePassword == "" && !spec.mayMint(secrets.Users[i].Name, SlotNaive) {
				continue
			}
			password, err := reuseOrMint(&secrets.Users[i].NaivePassword, "naive password", func() (string, error) { return keys.Password(16) })
			if err != nil {
				return nil, err
			}
			users = append(users, auth.User{Username: secrets.Users[i].Name, Password: password})
		}

		return &option.Inbound{
			Type: C.TypeNaive,
			Tag:  string(p),
			Options: &option.NaiveInboundOptions{
				ListenOptions: listenOn(spec.PublicListen, port),
				Users:         users,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					// h2 only. naive is HTTP/2 CONNECT, and offering http/1.1
					// alongside it lets a client negotiate a version the
					// inbound does not speak.
					TLS: spec.Certs.inboundTLS(domain, []string{"h2"}),
				},
			},
		}, nil

	case VLESSXHTTP:
		// One unit, for the same reason as the Reality inbound: the public
		// key, the short_id and the path derived from it are all in every
		// client's config.
		if prev != nil && prev.TierB.XHTTPReality.PrivateKey != "" {
			secrets.TierB.XHTTPReality = prev.TierB.XHTTPReality
			secrets.TierB.Facts.XHTTPPath = prev.TierB.Facts.XHTTPPath
		} else {
			reality, err := keys.NewX25519()
			if err != nil {
				return nil, fmt.Errorf("generate xhttp reality keypair: %w", err)
			}
			newShortID, err := keys.ShortID()
			if err != nil {
				return nil, fmt.Errorf("generate xhttp reality short_id: %w", err)
			}
			secrets.TierB.XHTTPReality = RealitySecrets{
				PrivateKey: reality.PrivateURL(),
				PublicKey:  reality.PublicURL(),
				ShortID:    newShortID,
			}
			secrets.TierB.Facts.XHTTPPath = "/" + pathSuffix(newShortID)
		}
		shortID := secrets.TierB.XHTTPReality.ShortID
		path := secrets.TierB.Facts.XHTTPPath
		secrets.TierB.Facts.XHTTPSNI = spec.RealityHandshakeServer

		users := make([]option.VLESSUser, 0, len(spec.Users))
		for i := range secrets.Users {
			if secrets.Users[i].VLESSXHTTPUUID == "" && !spec.mayMint(secrets.Users[i].Name, SlotVLESSXHTTP) {
				continue
			}
			uuid, err := reuseOrMint(&secrets.Users[i].VLESSXHTTPUUID, "vless UUID", keys.UUID)
			if err != nil {
				return nil, err
			}
			users = append(users, option.VLESSUser{Name: secrets.Users[i].Name, UUID: uuid})
		}

		return &option.Inbound{
			Type: C.TypeVLESS,
			Tag:  string(p),
			Options: &option.VLESSInboundOptions{
				ListenOptions: listenOn(spec.PublicListen, port),
				Users:         users,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					// Reality, not spec.Certs: this inbound borrows a foreign
					// handshake and has no certificate of its own, which is why
					// it needs no domain either.
					TLS: &option.InboundTLSOptions{
						Enabled:    true,
						ServerName: spec.RealityHandshakeServer,
						Reality: &option.InboundRealityOptions{
							Enabled: true,
							Handshake: option.InboundRealityHandshakeOptions{
								ServerOptions: option.ServerOptions{
									Server:     spec.RealityHandshakeServer,
									ServerPort: spec.RealityHandshakePort,
								},
							},
							PrivateKey: secrets.TierB.XHTTPReality.PrivateKey,
							ShortID:    []string{shortID},
						},
					},
				},
				Transport: &option.V2RayTransportOptions{
					Type: C.V2RayTransportTypeXHTTP,
					XHTTPOptions: option.V2RayXHTTPOptions{
						// "auto" lets the client choose stream-up or packet-up.
						Mode: "auto",
						V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{
							Path: path,
							// Explicit because the core refuses to default it:
							// a zero range reads as "padding disabled" and is
							// rejected outright with "xPaddingBytes cannot be
							// disabled". Everything else here — the padding
							// key and header, the session and seq placements,
							// the xmux ranges — the core does fill in, so it
							// is left alone to track the fork rather than
							// drift from it. 100-1000 matches the live
							// deployment.
							XPaddingBytes: xbadoption.Range{From: 100, To: 1000},
						},
					},
				},
			},
		}, nil

	case MASQUEWG:
		// The public door for the wg-masque endpoint. This is the one Tier B
		// protocol that Tier A depends on rather than merely complements:
		// wg-masque-in binds a wildcard but is not internet-facing, because
		// plain WireGuard arrives here from this inbound on loopback. Generate
		// Tier A alone and that endpoint has no front at all.
		target, err := spec.masqueTarget()
		if err != nil {
			return nil, err
		}

		return &option.Inbound{
			Type: C.TypeMASQUEWG,
			Tag:  string(p),
			Options: &option.MASQUEWGInboundOptions{
				ListenOptions: listenOn(spec.PublicListen, port),
				Target:        target,
				Path:          spec.MASQUEPath,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					// The inbound is an HTTP/3 server, so h3 is mandatory
					// rather than advisory.
					TLS: spec.Certs.inboundTLS(domain, []string{"h3"}),
				},
			},
		}, nil
	}

	return nil, fmt.Errorf("no inbound builder for tier B protocol %q", p)
}

// masqueTarget is the loopback address of the WireGuard endpoint this inbound
// forwards every association to.
//
// Derived from the WGMasque port rather than configured separately. Those two
// numbers must agree or the tunnel terminates into nothing — the MASQUE
// handshake succeeds, the client believes it is connected, and not one packet
// is ever answered.
func (s Spec) masqueTarget() (string, error) {
	port, ok := s.Ports[WGMasque]
	if !ok || port == 0 {
		return "", fmt.Errorf("%s forwards into %s, which has no port assigned", MASQUEWG, WGMasque)
	}
	return fmt.Sprintf("127.0.0.1:%d", port), nil
}
