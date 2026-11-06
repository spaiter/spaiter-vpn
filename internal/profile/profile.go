// Package profile turns a small set of operator choices into a complete
// sing-box configuration, expressed as the fork's own option.Options rather
// than a template. There is then one schema instead of two, so a config that
// drifts from the fork fails to compile instead of failing at runtime.
package profile

import (
	"fmt"
	"net/netip"
	"sort"
	"time"
)

// Tier names the external prerequisites a protocol has, which is the axis the
// whole product is organised around: Tier A needs nothing but an IP address,
// Tier B needs a domain and a certificate.
type Tier string

const (
	// TierA is the honest "one click": generate keys and it works on a bare VPS.
	TierA Tier = "a"
	// TierB additionally brings up the protocols that require TLS certificates.
	TierB Tier = "ab"
)

// Protocol identifies a generated inbound or endpoint by the tag it carries in
// the config. The tags match the live deployment so that an operator reading
// either one recognises the other.
type Protocol string

const (
	VLESSReality Protocol = "vless-reality-in"
	Shadowsocks  Protocol = "ss-stls-in"
	ShadowTLS    Protocol = "shadowtls-in"
	Snell        Protocol = "snell-in"
	Mieru        Protocol = "mieru-in"
	MTProto      Protocol = "mtproto-in"
	VLESSWSCDN   Protocol = "vless-ws-cdn-in"
	AWG2         Protocol = "awg-in"
	AWG3         Protocol = "awg3-in"
	WGMasque     Protocol = "wg-masque-in"
	WGWDTT       Protocol = "wg-wdtt-in"
)

// TierAProtocols is every protocol that needs no domain, no certificate and no
// third-party account — only generated keys. Reality is in here because it
// borrows a foreign SNI and so has no certificate of its own, and so is
// vless-xhttp, which runs Reality too.
//
// The order is the order clients list them in, so it leads with what survives
// best: Russian mobile networks cut a long stream over Reality's h2 after its
// first request while XHTTP's many short ones pass (docs/FIELD-NOTES.md).
var TierAProtocols = []Protocol{
	VLESSXHTTP,
	VLESSReality,
	Shadowsocks,
	ShadowTLS,
	Snell,
	Mieru,
	MTProto,
	VLESSWSCDN,
	AWG2,
	AWG3,
	WGMasque,
	WGWDTT,
}

// AllProtocols is every protocol in both tiers, in generation order.
var AllProtocols = append(append([]Protocol{}, TierAProtocols...), TierBProtocols...)

// wireGuardProtocols are the ones configured as endpoints rather than inbounds:
// each is a WireGuard-family listener with its own subnet and per-user peers.
var wireGuardProtocols = []Protocol{AWG2, AWG3, WGMasque, WGWDTT}

// IsWireGuard reports whether the protocol is generated as an endpoint.
func (p Protocol) IsWireGuard() bool {
	for _, w := range wireGuardProtocols {
		if w == p {
			return true
		}
	}
	return false
}

// ListenAddress returns where this protocol's listener binds in the given
// spec.
func (p Protocol) ListenAddress(s Spec) netip.Addr {
	switch p {
	case Shadowsocks:
		return s.ShadowsocksListen
	case VLESSWSCDN:
		return s.CDNListen
	default:
		return s.PublicListen
	}
}

// IsInternetFacing reports whether a firewall needs to let this protocol
// through.
//
// Binding a wildcard address is not the same as being a public door, and the
// difference matters because the answer here becomes `ufw allow` lines.
// Opening a port that was never meant to be reachable is a hole, not a
// convenience.
//
// Two bind loopback outright: the shadowsocks inbound is only reachable as the
// shadowtls detour target, and the websocket one expects a CDN to terminate
// TLS in front of it. Exposed directly, the first speaks shadowsocks to anyone
// who asks and the second speaks vless in clear text.
//
// Two more bind a wildcard yet are still internal: wg-masque-in and
// wg-wdtt-in receive plain WireGuard from their own fronts — the MASQUE
// inbound and the WG-over-VK relay — both running on the same host. The public
// door for those is the front's port, not theirs. Confirmed against the
// hand-built deployment this was modelled on, where ufw allows neither.
func (p Protocol) IsInternetFacing(s Spec) bool {
	switch p {
	case WGMasque, WGWDTT:
		return false
	}
	addr := p.ListenAddress(s)
	return addr.IsValid() && !addr.IsLoopback()
}

// Networks returns the transport protocols the listener binds, which is what a
// port-conflict check has to know: UDP 10863 and TCP 10863 are different
// ports, and treating them as one reports conflicts that do not exist.
//
// shadowsocks is the one that carries both — its inbound serves UDP relay
// alongside TCP unless `network` narrows it, and the generator does not.
func (p Protocol) Networks() []string {
	switch p {
	case AWG2, AWG3, WGMasque, WGWDTT:
		return []string{"udp"}
	// All three are QUIC: hysteria2 and tuic natively, masque-wg because its
	// MASQUE server speaks HTTP/3. A TCP check on these ports would report a
	// free port that is in fact occupied.
	case Hysteria2, TUIC, MASQUEWG:
		return []string{"udp"}
	case Shadowsocks:
		return []string{"tcp", "udp"}
	default:
		return []string{"tcp"}
	}
}

// Spec is the operator-facing input. Zero values are filled in by Defaults, so
// callers set only what they want to override.
type Spec struct {
	// Tier selects how much of the stack to generate.
	Tier Tier

	// Domain is the name Tier B's certificates are issued for and the name its
	// clients dial. It must already resolve to this host: ACME validates it,
	// and even with external certificates a client that cannot resolve it
	// cannot connect. Unused by Tier A, which needs only an address.
	Domain string

	// Certs says where Tier B's certificates come from. Unused by Tier A.
	Certs TLSCerts

	// Users are the per-client identities. Every enabled protocol gets one
	// credential per user, and every WireGuard endpoint one peer per user, so
	// a user's name is the join key across the whole config.
	Users []string

	// Mint restricts which credentials generation may issue to the users it
	// names: a named user keeps every credential it already holds and is
	// issued only the empty slots listed for it (see Slot* and PeerSlot). A
	// user absent from the map, and every user when it is nil, is issued
	// whatever it lacks.
	//
	// Migrations name every bot-provisioned user with an empty set. The bot
	// provisions those users on demand and keeps the private halves itself,
	// so a peer minted for one here would hold a key nobody stores and an
	// address the bot later works around with a second peer of the same name.
	Mint map[string]map[string]bool

	// Enabled restricts generation to a subset of the selected tier's
	// protocols. Nil means all of them.
	Enabled map[Protocol]bool

	Ports   map[Protocol]uint16
	Subnets map[Protocol]netip.Prefix
	MTU     map[Protocol]uint32

	// Reality borrows this server's TLS handshake. It must be a real host that
	// speaks TLS 1.3 with X25519, because clients actually complete a
	// handshake against it.
	RealityHandshakeServer string
	RealityHandshakePort   uint16

	// ShadowTLS fronts an unrelated host in the same way.
	ShadowTLSHandshakeServer string
	ShadowTLSHandshakePort   uint16
	ShadowTLSVersion         int

	// MTProtoFrontDomain is the domain the fake-TLS (`ee`) secret encodes.
	MTProtoFrontDomain string
	// MTProtoPerUser gives every user an MTProto secret of their own, which
	// the core matches to them so their Telegram traffic is accounted and
	// limited per user. It needs a core built with MTProto users; without it
	// there is one shared secret.
	MTProtoPerUser bool
	// RetireSharedMTProto drops a legacy shared MTProto secret, which stops
	// every link made from it. Per-user secrets are unaffected.
	RetireSharedMTProto bool

	ShadowsocksMethod string
	SnellVersion      int

	// TUICCongestionControl is the algorithm both ends must agree on.
	TUICCongestionControl string

	// MASQUEPath is the HTTP path of the CONNECT-UDP URI template.
	MASQUEPath string

	// PublicListen is where the internet-facing inbounds bind. ShadowsocksListen
	// and CDNListen are deliberately separate: the shadowsocks inbound exists
	// only as the detour target of shadowtls, and the websocket inbound expects
	// TLS to be terminated by a CDN or reverse proxy in front of it. Exposing
	// either directly would hand out an unauthenticated or unencrypted port.
	PublicListen      netip.Addr
	ShadowsocksListen netip.Addr
	CDNListen         netip.Addr

	LogLevel  string
	LogOutput string

	// ConfigOutputPath is where sing-box rewrites the config after a live
	// change. It must point at the same file that was loaded, or provisioning
	// a user silently writes its state somewhere nobody reads.
	ConfigOutputPath string

	ClashAPIListen string
	ClashAPISecret string

	// XDPInterfaces are the host interfaces the XDP blocker attaches to. Empty
	// disables the service, which also disables enforcement of the ban.
	XDPInterfaces []string

	BanDuration  time.Duration
	SniffTimeout time.Duration
}

// DefaultPorts is the reference port set: the one the original deployment
// listens on, kept so that deployment's documents, fixtures and migrations keep
// their numbers. A new install does not use it: `bootstrap state` and `init`
// draw random ports (RandomPorts), because a public project whose installs all
// listen on one set of ports is found by scanning for that set.
func DefaultPorts() map[Protocol]uint16 {
	ports := defaultTierAPorts()
	for p, port := range DefaultTierBPorts() {
		ports[p] = port
	}
	return ports
}

func defaultTierAPorts() map[Protocol]uint16 {
	return map[Protocol]uint16{
		VLESSXHTTP:   10871,
		VLESSReality: 10861,
		Shadowsocks:  10041,
		ShadowTLS:    10870,
		Snell:        10875,
		Mieru:        10878,
		MTProto:      10868,
		VLESSWSCDN:   10042,
		AWG2:         10863,
		AWG3:         10860,
		WGMasque:     10877,
		WGWDTT:       10879,
	}
}

// DefaultSubnets gives each WireGuard endpoint its own /24. They must not
// overlap: the endpoints share one routing table, so an overlap would send a
// peer's traffic into the wrong tunnel.
func DefaultSubnets() map[Protocol]netip.Prefix {
	return map[Protocol]netip.Prefix{
		AWG2:     netip.MustParsePrefix("10.10.0.0/24"),
		AWG3:     netip.MustParsePrefix("10.40.0.0/24"),
		WGMasque: netip.MustParsePrefix("10.20.0.0/24"),
		WGWDTT:   netip.MustParsePrefix("10.30.0.0/24"),
	}
}

// DefaultMTU follows the live values. These are not cosmetic: each tunnel is
// sized for what wraps it, and the plain-WG backends sit under another
// encapsulation. The MASQUE one is the smallest because a QUIC datagram plus
// WireGuard headers has to fit the 1280-byte floor that DS-Lite mobile paths
// impose — the measured wall that made masque-wg the mobile transport and
// kept TUIC on the desktop.
func DefaultMTU() map[Protocol]uint32 {
	return map[Protocol]uint32{
		AWG2:     1200,
		AWG3:     1180,
		WGMasque: 1100,
		WGWDTT:   1000,
	}
}

// Defaults returns a Spec that generates the full Tier A set for the given
// users.
func Defaults(users []string) Spec {
	return Spec{
		Tier:    TierA,
		Users:   users,
		Ports:   DefaultPorts(),
		Subnets: DefaultSubnets(),
		MTU:     DefaultMTU(),

		RealityHandshakeServer: "ae-pic-a1.aliexpress-media.com",
		RealityHandshakePort:   443,

		ShadowTLSHandshakeServer: "www.microsoft.com",
		ShadowTLSHandshakePort:   443,
		ShadowTLSVersion:         3,

		MTProtoFrontDomain: "www.google.com",

		ShadowsocksMethod: "2022-blake3-aes-128-gcm",
		SnellVersion:      6,

		TUICCongestionControl: "bbr",
		MASQUEPath:            "/m",

		PublicListen:      netip.MustParseAddr("::"),
		ShadowsocksListen: netip.MustParseAddr("127.0.0.1"),
		CDNListen:         netip.MustParseAddr("127.0.0.1"),

		// debug, not info, and this is load-bearing rather than verbose.
		//
		// The fork logs a BitTorrent detection at info, but the routing
		// decision that follows it — the reject — is logged by the router at
		// debug. At info the traffic is still dropped; there is simply no
		// record of the drop. That makes the product's own end-to-end proof
		// impossible to obtain: `selftest` sees the detection, finds no
		// rejection, and `bootstrap apply` refuses to record a deployment it
		// could not verify. A default that cannot pass the gate the same
		// binary enforces is not a default.
		//
		// The cost is volume and detail: debug logs every connection, and an
		// append-only log at this level fills a disk. That is why `init` and
		// `bootstrap` generate a logrotate configuration and why preflight
		// fails when nothing rotates the log.
		LogLevel:  "debug",
		LogOutput: "/etc/sing-box/sing-box.log",

		ConfigOutputPath: "/etc/sing-box/config.json",
		ClashAPIListen:   "127.0.0.1:9090",

		BanDuration:  10 * time.Minute,
		SniffTimeout: 100 * time.Millisecond,
	}
}

// TierProtocols is the candidate set for the spec's tier.
func (s Spec) TierProtocols() []Protocol {
	if s.Tier == TierB {
		return AllProtocols
	}
	return TierAProtocols
}

// EnabledProtocols returns the protocols to generate, in a stable order.
func (s Spec) EnabledProtocols() []Protocol {
	var out []Protocol
	for _, p := range s.TierProtocols() {
		if s.Enabled == nil || s.Enabled[p] {
			out = append(out, p)
		}
	}
	return out
}

// needsCertificateSource reports whether any enabled protocol presents a
// certificate, which is what makes a domain and a certificate source
// mandatory.
func (s Spec) needsCertificateSource() bool {
	for _, p := range s.EnabledProtocols() {
		if p.NeedsCertificate() {
			return true
		}
	}
	return false
}

// Validate rejects a spec that would produce a config sing-box refuses, or —
// worse — accepts while doing something other than intended.
func (s Spec) Validate() error {
	switch s.Tier {
	case TierA, TierB:
	default:
		return fmt.Errorf("unknown tier %q", s.Tier)
	}

	if len(s.Users) == 0 {
		return fmt.Errorf("no users: every protocol here is authenticated, so a config with no users accepts nobody")
	}
	seenUser := map[string]struct{}{}
	for _, u := range s.Users {
		if u == "" {
			return fmt.Errorf("empty user name")
		}
		if _, dup := seenUser[u]; dup {
			return fmt.Errorf("duplicate user name %q: names attribute traffic in the per-user stats and the XDP blocker, so they must be unique", u)
		}
		seenUser[u] = struct{}{}
	}

	// Membership is checked before emptiness. The other order reports "every
	// protocol is disabled" for a spec that in fact asked for a Tier B
	// protocol under Tier A — true, but it names the symptom instead of the
	// mistake, because EnabledProtocols filters that request out silently.
	for p := range s.Enabled {
		if !s.Enabled[p] {
			continue
		}
		if !isTierA(p) && !isTierB(p) {
			return fmt.Errorf("unknown protocol %q", p)
		}
		if s.Tier == TierA && isTierB(p) {
			return fmt.Errorf("protocol %q belongs to tier %q; select that tier to enable it", p, TierB)
		}
	}

	enabled := s.EnabledProtocols()
	if len(enabled) == 0 {
		return fmt.Errorf("every protocol is disabled, so there is nothing to generate")
	}

	// The certificate source is validated only when something actually needs
	// one. Selecting Tier B for vless-xhttp alone is legitimate — it runs
	// Reality and needs no name — and demanding a domain for it would be a
	// prerequisite invented by this code rather than by the protocol.
	if s.needsCertificateSource() {
		if err := s.Certs.validate(s.Domain); err != nil {
			return err
		}
	}

	// masque-wg is a front, not a destination. Enabling it without the
	// endpoint it forwards into yields an inbound whose every association
	// terminates into a closed port: the TLS and MASQUE handshakes both
	// succeed, so the client reports a working connection and simply carries
	// no traffic.
	if contains(enabled, MASQUEWG) && !contains(enabled, WGMasque) {
		return fmt.Errorf("%s forwards into %s, so %s cannot be disabled while %s is enabled", MASQUEWG, WGMasque, WGMasque, MASQUEWG)
	}

	// shadowtls has no transport of its own; it hands the connection to its
	// detour target. Generating it without that target yields a config that
	// starts and then fails every connection.
	if contains(enabled, ShadowTLS) && !contains(enabled, Shadowsocks) {
		return fmt.Errorf("%s detours into %s, so %s cannot be disabled while %s is enabled", ShadowTLS, Shadowsocks, Shadowsocks, ShadowTLS)
	}

	usedPort := map[uint16]Protocol{}
	for _, p := range enabled {
		port, ok := s.Ports[p]
		if !ok || port == 0 {
			return fmt.Errorf("no port assigned to %s", p)
		}
		if other, dup := usedPort[port]; dup {
			return fmt.Errorf("port %d is assigned to both %s and %s", port, other, p)
		}
		usedPort[port] = p
	}

	var subnets []netip.Prefix
	for _, p := range enabled {
		if !p.IsWireGuard() {
			continue
		}
		prefix, ok := s.Subnets[p]
		if !ok || !prefix.IsValid() {
			return fmt.Errorf("no subnet assigned to %s", p)
		}
		if !prefix.Addr().Is4() {
			return fmt.Errorf("%s: subnet %s is not IPv4; the generator allocates peer addresses in IPv4 only", p, prefix)
		}
		// Addresses .1 is the endpoint and the rest go to peers, so capacity is
		// the host count minus the endpoint itself.
		capacity := 1<<(32-prefix.Bits()) - 3
		if len(s.Users) > capacity {
			return fmt.Errorf("%s: subnet %s holds %d peers but there are %d users", p, prefix, capacity, len(s.Users))
		}
		for _, other := range subnets {
			if other.Overlaps(prefix) {
				return fmt.Errorf("subnets %s and %s overlap; peers would be routed into the wrong tunnel", other, prefix)
			}
		}
		subnets = append(subnets, prefix)
	}

	if contains(enabled, VLESSReality) && s.RealityHandshakeServer == "" {
		return fmt.Errorf("%s needs a handshake server: Reality has no certificate of its own and borrows one", VLESSReality)
	}
	if contains(enabled, ShadowTLS) && s.ShadowTLSHandshakeServer == "" {
		return fmt.Errorf("%s needs a handshake server", ShadowTLS)
	}
	if contains(enabled, MTProto) && s.MTProtoFrontDomain == "" {
		return fmt.Errorf("%s needs a fronting domain for its fake-TLS secret", MTProto)
	}
	if contains(enabled, Snell) && s.SnellVersion != 5 && s.SnellVersion != 6 {
		return fmt.Errorf("snell version %d is not supported by the fork (5 or 6)", s.SnellVersion)
	}
	if !s.PublicListen.IsValid() {
		return fmt.Errorf("no public listen address")
	}
	if s.ConfigOutputPath == "" {
		return fmt.Errorf("config_output_path is empty: live user provisioning would write its state nowhere")
	}
	if s.LogOutput == "" {
		return fmt.Errorf("log output is empty: sing-box would log to stdout, and the self-test reads the log file")
	}
	return nil
}

func isTierA(p Protocol) bool {
	return contains(TierAProtocols, p)
}

func contains(list []Protocol, p Protocol) bool {
	for _, item := range list {
		if item == p {
			return true
		}
	}
	return false
}

// sortedProtocols gives map iteration a stable order, so two runs of the
// generator over the same spec differ only in their random secrets.
func sortedProtocols(in []Protocol) []Protocol {
	out := append([]Protocol(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
