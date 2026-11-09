package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/client"
	"github.com/spaiter/spaiter-vpn/internal/profile"
	"github.com/spaiter/spaiter-vpn/internal/singbox"
)

const tierBDomain = "tls.example.com"

// generateTierB builds both halves of a Tier B deployment.
//
// Non-default ports and a different borrowed SNI on purpose: with defaults
// everywhere, a client that ignored the deployment record and filled the gaps
// from profile.Defaults would pass. That exact bug happened once, and the
// agreement test that was supposed to catch it never exercised the path.
func generateTierB(t *testing.T) (profile.Spec, profile.Secrets, []client.Bundle) {
	t.Helper()
	spec := profile.Defaults([]string{"alice", "bob"})
	spec.Tier = profile.TierB
	spec.XDPInterfaces = []string{"eth0"}
	spec.Domain = tierBDomain
	spec.Certs = profile.TLSCerts{
		Source:        profile.CertSourceACMEDNS,
		Email:         "ops@example.com",
		DNSProvider:   "cloudflare",
		DataDirectory: "/var/lib/acme",
	}
	spec.Certs.CloudflareAPIToken = "not-a-real-token"
	spec.RealityHandshakeServer = "www.lovelive-anime.jp"
	spec.TUICCongestionControl = "cubic"
	spec.Ports[profile.Hysteria2] = 21862
	spec.Ports[profile.TUIC] = 21869
	spec.Ports[profile.AnyTLS] = 21874
	spec.Ports[profile.VLESSXHTTP] = 21871

	bundle, err := profile.Generate(spec)
	if err != nil {
		t.Fatalf("generate server: %v", err)
	}
	clients, err := client.Generate(spec, bundle.Secrets, client.Endpoint{Host: publicHost})
	if err != nil {
		t.Fatalf("generate clients: %v", err)
	}
	return spec, bundle.Secrets, clients
}

// TestTierBClientConfigPassesSingBoxCheck validates the client half with the
// real binary, exactly as the server half is validated.
func TestTierBClientConfigPassesSingBoxCheck(t *testing.T) {
	ctx := context.Background()
	checker, err := singbox.Detect(ctx, "", "")
	if err != nil {
		if errors.Is(err, singbox.ErrUnavailable) {
			t.Skipf("no sing-box checker available (%v)", err)
		}
		t.Fatalf("detect checker: %v", err)
	}

	_, _, clients := generateTierB(t)
	for _, b := range clients {
		if err := checker.Check(ctx, b.SingBox); err != nil {
			t.Fatalf("sing-box check rejected the Tier B client config for %s: %v\n\n%s", b.User, err, b.SingBox)
		}
	}
}

// TestTierBClientsDialTheDomain is the agreement that matters most here, and
// the one with the least debuggable symptom.
//
// These inbounds present a certificate issued for the domain. A client that
// dialled the endpoint address instead would fail name verification before any
// authentication happened — a handshake that dies with nothing in the server
// log. Reality is the exception and is checked as one.
func TestTierBClientsDialTheDomain(t *testing.T) {
	spec, secrets, clients := generateTierB(t)

	var doc struct {
		Outbounds []struct {
			Tag    string `json:"tag"`
			Server string `json:"server"`
			TLS    *struct {
				ServerName string `json:"server_name"`
			} `json:"tls"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(clients[0].SingBox, &doc); err != nil {
		t.Fatalf("unmarshal client config: %v", err)
	}

	seen := map[string]bool{}
	for _, o := range doc.Outbounds {
		p := profile.Protocol(o.Tag)
		if !p.NeedsCertificate() {
			continue
		}
		seen[o.Tag] = true
		if o.Server != spec.Domain {
			t.Errorf("%s dials %q; it must dial %q, the name on the certificate", o.Tag, o.Server, spec.Domain)
		}
		if o.TLS == nil || o.TLS.ServerName != spec.Domain {
			t.Errorf("%s does not send %q as SNI", o.Tag, spec.Domain)
		}
	}
	// hysteria2, tuic and anytls have outbounds; naive and masque-wg do not,
	// and say so as omissions instead.
	for _, want := range []profile.Protocol{profile.Hysteria2, profile.TUIC, profile.AnyTLS} {
		if !seen[string(want)] {
			t.Errorf("no client outbound for %s", want)
		}
	}

	// And the exception: xhttp borrows a handshake, so it must address the
	// endpoint and present the borrowed host.
	for _, o := range doc.Outbounds {
		if o.Tag != string(profile.VLESSXHTTP) {
			continue
		}
		if o.Server != publicHost {
			t.Errorf("%s dials %q, want the endpoint host %q: it has no certificate for the domain", o.Tag, o.Server, publicHost)
		}
		if o.TLS == nil || o.TLS.ServerName != secrets.TierB.Facts.XHTTPSNI {
			t.Errorf("%s must present the borrowed host %q as SNI, or Reality forwards the handshake to the wrong place", o.Tag, secrets.TierB.Facts.XHTTPSNI)
		}
	}
}

// TestTierBShareURLsCarryTheRightFields parses what an operator would paste
// into a client.
func TestTierBShareURLsCarryTheRightFields(t *testing.T) {
	spec, secrets, clients := generateTierB(t)
	alice := clients[0]
	aliceSecrets := secrets.Users[0]
	if aliceSecrets.Name != alice.User {
		t.Fatalf("secrets[0] is %q but bundle[0] is %q", aliceSecrets.Name, alice.User)
	}

	byScheme := map[string]*url.URL{}
	for _, raw := range alice.URLs {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("unparseable share URL %q: %v", raw, err)
		}
		byScheme[u.Scheme] = u
	}

	t.Run("hysteria2", func(t *testing.T) {
		u := byScheme["hysteria2"]
		if u == nil {
			t.Fatal("no hysteria2:// URL")
		}
		if u.Hostname() != spec.Domain {
			t.Errorf("host is %q, want %q", u.Hostname(), spec.Domain)
		}
		if u.Port() != "21862" {
			t.Errorf("port is %q, want the overridden 21862", u.Port())
		}
		q := u.Query()
		// Without the obfs password the client's packets are rejected by the
		// obfuscation layer before the protocol is reached, and the server
		// logs nothing at all — it cannot, since it never decoded them.
		if got := q.Get("obfs-password"); got != secrets.TierB.Hysteria2ObfsPassword {
			t.Errorf("obfs-password is %q, want the generated one", got)
		}
		if got := q.Get("obfs"); got != secrets.TierB.Hysteria2ObfsType {
			t.Errorf("obfs type is %q, want %q", got, secrets.TierB.Hysteria2ObfsType)
		}
		if q.Get("sni") != spec.Domain {
			t.Errorf("sni is %q, want %q", q.Get("sni"), spec.Domain)
		}
	})

	t.Run("tuic", func(t *testing.T) {
		u := byScheme["tuic"]
		if u == nil {
			t.Fatal("no tuic:// URL")
		}
		user := u.User.Username()
		pass, _ := u.User.Password()
		if user != aliceSecrets.TUICUUID {
			t.Errorf("uuid is %q, want %q", user, aliceSecrets.TUICUUID)
		}
		if pass != aliceSecrets.TUICPassword {
			t.Errorf("password does not match the generated one")
		}
		// Both ends must agree on congestion control, and the deployment
		// overrode the default.
		if got := u.Query().Get("congestion_control"); got != "cubic" {
			t.Errorf("congestion_control is %q, want the deployed cubic", got)
		}
	})

	t.Run("anytls", func(t *testing.T) {
		u := byScheme["anytls"]
		if u == nil {
			t.Fatal("no anytls:// URL")
		}
		if u.User.Username() != aliceSecrets.AnyTLSPassword {
			t.Error("password does not match the generated one")
		}
	})

	t.Run("xhttp reality", func(t *testing.T) {
		var found bool
		for _, raw := range alice.URLs {
			if !strings.Contains(raw, "type=xhttp") {
				continue
			}
			found = true
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			if q.Get("pbk") != secrets.TierB.XHTTPReality.PublicKey {
				t.Error("the xhttp URL carries the wrong Reality public key")
			}
			if q.Get("pbk") == secrets.Reality.PublicKey {
				t.Error("the xhttp URL carries the other inbound's Reality key")
			}
			if q.Get("path") != secrets.TierB.Facts.XHTTPPath {
				t.Errorf("path is %q, want %q", q.Get("path"), secrets.TierB.Facts.XHTTPPath)
			}
			if q.Get("sni") != secrets.TierB.Facts.XHTTPSNI {
				t.Errorf("sni is %q, want the borrowed %q", q.Get("sni"), secrets.TierB.Facts.XHTTPSNI)
			}
		}
		if !found {
			t.Error("no xhttp share URL")
		}
	})
}

// TestTierBSecretsRoundTripPreservesTheDeployment goes through the serialised
// form, which is the path that actually runs: `clients` reads secrets.json off
// disk rather than holding a Secrets value from generation.
//
// This is where the earlier bug lived. An agreement test that passed the
// in-memory struct straight through never touched the code that rebuilt a spec
// from the file, so it proved nothing about it.
func TestTierBSecretsRoundTripPreservesTheDeployment(t *testing.T) {
	spec, secrets, _ := generateTierB(t)

	raw, err := json.Marshal(secrets)
	if err != nil {
		t.Fatalf("marshal secrets: %v", err)
	}
	var restored profile.Secrets
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatalf("unmarshal secrets: %v", err)
	}

	recovered, err := profile.SpecFromSecrets(restored)
	if err != nil {
		t.Fatalf("SpecFromSecrets: %v", err)
	}

	// The tier itself has to come back. Left at Tier A, EnabledProtocols would
	// filter every Tier B protocol out and the client bundle would omit half
	// the deployment while reporting success.
	if recovered.Tier != profile.TierB {
		t.Fatalf("tier came back as %q, want %q", recovered.Tier, profile.TierB)
	}
	if recovered.Domain != spec.Domain {
		t.Errorf("domain came back as %q, want %q", recovered.Domain, spec.Domain)
	}
	if recovered.Certs.Source != spec.Certs.Source {
		t.Errorf("certificate source came back as %q, want %q", recovered.Certs.Source, spec.Certs.Source)
	}
	if recovered.TUICCongestionControl != spec.TUICCongestionControl {
		t.Errorf("congestion control came back as %q, want %q", recovered.TUICCongestionControl, spec.TUICCongestionControl)
	}
	for _, p := range profile.TierBProtocols {
		if recovered.Ports[p] != spec.Ports[p] {
			t.Errorf("%s port came back as %d, want %d", p, recovered.Ports[p], spec.Ports[p])
		}
	}

	// And the clients built from the recovered spec must be the same clients.
	rebuilt, err := client.Generate(recovered, restored, client.Endpoint{Host: publicHost})
	if err != nil {
		t.Fatalf("generate clients from the recovered spec: %v", err)
	}
	original, err := client.Generate(spec, secrets, client.Endpoint{Host: publicHost})
	if err != nil {
		t.Fatalf("generate clients from the original spec: %v", err)
	}
	if len(rebuilt) != len(original) {
		t.Fatalf("got %d bundles from the file, %d from memory", len(rebuilt), len(original))
	}
	for i := range rebuilt {
		if string(rebuilt[i].SingBox) != string(original[i].SingBox) {
			t.Errorf("the client config for %s differs depending on whether the secrets went through JSON", rebuilt[i].User)
		}
		if strings.Join(rebuilt[i].URLs, "\n") != strings.Join(original[i].URLs, "\n") {
			t.Errorf("the share URLs for %s differ depending on whether the secrets went through JSON:\n file:   %v\n memory: %v",
				rebuilt[i].User, rebuilt[i].URLs, original[i].URLs)
		}
	}
}

// TestTierBOmissionsExplainThemselves. naive and masque-wg have no sing-box
// outbound; an empty omission would leave an operator wondering whether the
// protocol failed or was never generated.
func TestTierBOmissionsExplainThemselves(t *testing.T) {
	_, _, clients := generateTierB(t)
	want := map[profile.Protocol]bool{profile.Naive: false, profile.MASQUEWG: false}
	for _, o := range clients[0].Omitted {
		if _, tracked := want[o.Protocol]; tracked {
			want[o.Protocol] = true
		}
		if strings.TrimSpace(o.Reason) == "" {
			t.Errorf("%s was omitted from the %s with no reason", o.Protocol, o.Artifact)
		}
	}
	for p, explained := range want {
		if !explained {
			t.Errorf("%s has no sing-box outbound and no omission saying why", p)
		}
	}
}
