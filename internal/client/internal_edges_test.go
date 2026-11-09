package client

import (
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func generated(t *testing.T, endpoint Endpoint) (profile.Spec, profile.Secrets, []Bundle) {
	t.Helper()
	spec := profile.Defaults([]string{"alice"})
	spec.XDPInterfaces = []string{"eth0"}
	built, err := profile.Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := Generate(spec, built.Secrets, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	return spec, built.Secrets, bundles
}

func TestACDNFrontedWebsocketIsOfferedOnlyWhereTheCDNIsKnown(t *testing.T) {
	_, _, without := generated(t, Endpoint{Host: "203.0.113.1"})
	_, _, with := generated(t, Endpoint{Host: "2001:db8::1", CDNHost: "cdn.example.com"})

	hasCDN := func(b Bundle) bool {
		for _, url := range b.URLs {
			if strings.Contains(url, "path=%2Fcdnws") {
				return true
			}
		}
		return false
	}
	if hasCDN(without[0]) {
		t.Error("a CDN URL appeared with no CDN configured")
	}
	if !hasCDN(with[0]) {
		t.Errorf("no CDN URL with a CDN host: %v", with[0].URLs)
	}
	// The default port is 443 and the sing-box config carries the node.
	var found bool
	for _, url := range with[0].URLs {
		if strings.Contains(url, "@cdn.example.com:443?") {
			found = true
		}
	}
	if !found {
		t.Errorf("CDN URL lacks the default port: %v", with[0].URLs)
	}
	if !strings.Contains(string(with[0].SingBox), "cdn.example.com") || !strings.Contains(string(with[0].SingBox), "/cdnws") {
		t.Error("the sing-box config does not carry the CDN node")
	}

	// An explicit port is kept.
	_, _, custom := generated(t, Endpoint{Host: "203.0.113.1", CDNHost: "cdn.example.com", CDNPort: 8443})
	if !strings.Contains(strings.Join(custom[0].URLs, "\n"), "cdn.example.com:8443") {
		t.Error("the CDN port was dropped")
	}
}

func TestIPv6LiteralsAreBracketedInURLs(t *testing.T) {
	for in, want := range map[string]string{"2001:db8::1": "[2001:db8::1]", "[::1]": "[::1]", "example.com": "example.com", "203.0.113.1": "203.0.113.1"} {
		if got := hostForURL(in); got != want {
			t.Errorf("hostForURL(%q) = %q, want %q", in, got, want)
		}
	}
	spec := profile.Spec{Domain: "vpn.example.org"}
	if tierBHost(spec, Endpoint{Host: "203.0.113.1"}) != "vpn.example.org" || tierBHost(profile.Spec{}, Endpoint{Host: "203.0.113.1"}) != "203.0.113.1" {
		t.Error("tierBHost")
	}
}

func TestWireGuardConfigNamesWhatTheSecretsLack(t *testing.T) {
	spec, secrets, _ := generated(t, Endpoint{Host: "203.0.113.1"})
	user := secrets.Users[0]
	endpoint := Endpoint{Host: "203.0.113.1"}

	var wg profile.Protocol
	for _, p := range spec.EnabledProtocols() {
		if p.IsWireGuard() {
			wg = p
			break
		}
	}
	if wg == "" {
		t.Skip("no WireGuard protocol enabled")
	}
	if _, err := wireGuardConfig(spec, secrets, user, endpoint, wg); err != nil {
		t.Fatalf("the intact secrets were refused: %v", err)
	}

	noPeer := user
	noPeer.Peers = nil
	if _, err := wireGuardConfig(spec, secrets, noPeer, endpoint, wg); err == nil || !strings.Contains(err.Error(), "no peer") {
		t.Errorf("no peer: %v", err)
	}
	noKeys := secrets
	noKeys.Endpoints = nil
	if _, err := wireGuardConfig(spec, noKeys, user, endpoint, wg); err == nil || !strings.Contains(err.Error(), "no server keypair") {
		t.Errorf("no server keypair: %v", err)
	}
}

func TestAGeneratedBundleOmitsAWireGuardWhoseSecretsAreMissing(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	spec.XDPInterfaces = []string{"eth0"}
	built, err := profile.Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	secrets := built.Secrets
	secrets.Endpoints = nil
	bundles, err := Generate(spec, secrets, Endpoint{Host: "203.0.113.1"})
	if err != nil {
		t.Fatal(err)
	}
	var omitted bool
	for _, o := range bundles[0].Omitted {
		if o.Artifact == "wireguard .conf" {
			omitted = true
		}
	}
	if !omitted {
		t.Errorf("no omission recorded: %+v", bundles[0].Omitted)
	}
}
