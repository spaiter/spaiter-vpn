package client_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/client"
	"github.com/spaiter/spaiter-vpn/internal/config"
	"github.com/spaiter/spaiter-vpn/internal/profile"
	"github.com/spaiter/spaiter-vpn/internal/singbox"
)

const publicHost = "vpn.example.com"

func generate(t *testing.T, mutate func(*profile.Spec)) (profile.Spec, profile.Secrets, []byte, []client.Bundle) {
	t.Helper()
	spec := profile.Defaults([]string{"alice", "bob"})
	spec.XDPInterfaces = []string{"eth0"}
	if mutate != nil {
		mutate(&spec)
	}
	bundle, err := profile.Generate(spec)
	if err != nil {
		t.Fatalf("generate server: %v", err)
	}
	serverJSON, err := config.Marshal(context.Background(), bundle.Options)
	if err != nil {
		t.Fatalf("marshal server: %v", err)
	}
	clients, err := client.Generate(spec, bundle.Secrets, client.Endpoint{Host: publicHost})
	if err != nil {
		t.Fatalf("generate clients: %v", err)
	}
	return spec, bundle.Secrets, serverJSON, clients
}

// TestClientAndServerAgree is the test this package exists for.
//
// Both sides are generated from one spec, so a mismatch is not a typo — it is
// the two halves having been built from different assumptions. That failure is
// invisible until a real client connects and is dropped, and the symptom
// (a handshake that fails with nothing in the log) is among the least
// debuggable this project has. Checking the agreement here is cheap; finding it
// later is not.
func TestClientAndServerAgree(t *testing.T) {
	// A deployment that overrides everything the client side could otherwise
	// be tempted to assume: non-default ports and a different borrowed SNI.
	// With defaults, a client that ignored the deployment record would pass.
	_, _, serverJSON, clients := generate(t, func(s *profile.Spec) {
		for p := range s.Ports {
			s.Ports[p] += 11000
		}
		s.RealityHandshakeServer = "www.cloudflare.com"
		s.ShadowTLSHandshakeServer = "www.apple.com"
	})

	var server struct {
		Inbounds []struct {
			Tag        string `json:"tag"`
			ListenPort uint16 `json:"listen_port"`
			TLS        *struct {
				ServerName string `json:"server_name"`
			} `json:"tls"`
			Transport *struct {
				Path string `json:"path"`
			} `json:"transport"`
			Handshake *struct {
				Server string `json:"server"`
			} `json:"handshake"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(serverJSON, &server); err != nil {
		t.Fatalf("parse server config: %v", err)
	}
	type serverFacts struct {
		port   uint16
		sni    string
		path   string
		detour string
	}
	byTag := map[string]serverFacts{}
	for _, in := range server.Inbounds {
		f := serverFacts{port: in.ListenPort}
		if in.TLS != nil {
			f.sni = in.TLS.ServerName
		}
		if in.Transport != nil {
			f.path = in.Transport.Path
		}
		if in.Handshake != nil {
			f.detour = in.Handshake.Server
		}
		byTag[in.Tag] = f
	}

	var clientDoc struct {
		Outbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			Server     string `json:"server"`
			ServerPort uint16 `json:"server_port"`
			Detour     string `json:"detour"`
			TLS        *struct {
				ServerName string `json:"server_name"`
			} `json:"tls"`
			Transport *struct {
				Path string `json:"path"`
			} `json:"transport"`
			Outbounds []string `json:"outbounds"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(clients[0].SingBox, &clientDoc); err != nil {
		t.Fatalf("parse client config: %v", err)
	}

	checked := 0
	for _, ob := range clientDoc.Outbounds {
		facts, ok := byTag[ob.Tag]
		if !ok {
			continue // urltest, direct
		}
		checked++

		// shadowsocks rides the shadowtls chain, so the port it dials is the
		// shadowtls one, not its own loopback port.
		wantPort := facts.port
		if ob.Tag == string(profile.Shadowsocks) {
			wantPort = byTag[string(profile.ShadowTLS)].port
			if ob.Detour != string(profile.ShadowTLS) {
				t.Errorf("%s does not detour through %s, so it would dial a loopback-only port directly", ob.Tag, profile.ShadowTLS)
			}
		}
		if ob.ServerPort != wantPort {
			t.Errorf("%s: client dials port %d, server listens on %d", ob.Tag, ob.ServerPort, wantPort)
		}
		if ob.Server != publicHost {
			t.Errorf("%s: client dials %q, want the public host", ob.Tag, ob.Server)
		}

		// The SNI a client sends must equal the host the server borrows, or
		// the server forwards the handshake somewhere else entirely.
		switch ob.Tag {
		case string(profile.VLESSReality):
			if ob.TLS == nil || ob.TLS.ServerName != facts.sni {
				t.Errorf("%s: client SNI %v, server %q", ob.Tag, ob.TLS, facts.sni)
			}
			if ob.Transport == nil || ob.Transport.Path != facts.path {
				t.Errorf("%s: client path %v, server %q", ob.Tag, ob.Transport, facts.path)
			}
		case string(profile.ShadowTLS):
			if ob.TLS == nil || ob.TLS.ServerName != facts.detour {
				t.Errorf("%s: client fronts %v, server fronts %q", ob.Tag, ob.TLS, facts.detour)
			}
		}
	}
	if checked < 4 {
		t.Fatalf("only %d outbounds were cross-checked; the test is not covering the deployment", checked)
	}

	// The urltest group must not contain shadowtls: it is a transport, and
	// dialling it as a destination makes the group measure a thing that
	// cannot answer.
	for _, ob := range clientDoc.Outbounds {
		if ob.Type != "urltest" {
			continue
		}
		for _, tag := range ob.Outbounds {
			if tag == string(profile.ShadowTLS) {
				t.Error("urltest includes the shadowtls transport as if it were a destination")
			}
		}
		if len(ob.Outbounds) == 0 {
			t.Error("urltest group is empty")
		}
	}
}

func TestClientCredentialsMatchTheUser(t *testing.T) {
	_, secrets, _, clients := generate(t, nil)
	if len(clients) != len(secrets.Users) {
		t.Fatalf("%d bundles for %d users", len(clients), len(secrets.Users))
	}
	for i, bundle := range clients {
		user := secrets.Users[i]
		if bundle.User != user.Name {
			t.Fatalf("bundle %d is for %q, want %q", i, bundle.User, user.Name)
		}
		body := string(bundle.SingBox)
		// Each user's own credentials, and nobody else's: a bundle carrying
		// another user's UUID would hand one person another's access.
		if !strings.Contains(body, user.VLESSRealityUUID) {
			t.Errorf("%s: own vless UUID missing from the config", user.Name)
		}
		for j, other := range secrets.Users {
			if i == j {
				continue
			}
			if strings.Contains(body, other.VLESSRealityUUID) {
				t.Errorf("%s: config contains %s's UUID", user.Name, other.Name)
			}
			if strings.Contains(body, other.ShadowTLSPassword) {
				t.Errorf("%s: config contains %s's shadowtls password", user.Name, other.Name)
			}
		}
	}
}

func TestShareURLsParseAndCarryTheRightFields(t *testing.T) {
	_, secrets, _, clients := generate(t, nil)
	bundle := clients[0]
	user := secrets.Users[0]

	var sawVless, sawTG bool
	for _, raw := range bundle.URLs {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("share URL does not parse: %q: %v", raw, err)
		}
		switch u.Scheme {
		case "vless":
			sawVless = true
			// Two inbounds speak vless, each with its own Reality keypair and
			// the user's own UUID for it; the transport says which this is.
			q := u.Query()
			uuid, reality, transport := user.VLESSRealityUUID, secrets.Reality, "http"
			if q.Get("type") == "xhttp" {
				uuid, reality, transport = user.VLESSXHTTPUUID, secrets.TierB.XHTTPReality, "xhttp"
				if q.Get("path") != secrets.TierB.Facts.XHTTPPath {
					t.Errorf("xhttp URL carries path %q, want %q", q.Get("path"), secrets.TierB.Facts.XHTTPPath)
				}
			}
			if u.User.Username() != uuid {
				t.Errorf("vless URL carries %q, want the user's UUID", u.User.Username())
			}
			if q.Get("pbk") != reality.PublicKey {
				t.Error("vless URL carries the wrong Reality public key")
			}
			if q.Get("sid") != reality.ShortID {
				t.Error("vless URL carries the wrong short_id")
			}
			if q.Get("security") != "reality" || q.Get("type") != transport {
				t.Errorf("vless URL misdescribes the transport: %v", q)
			}
			// The private key must never appear in something handed out.
			if strings.Contains(raw, reality.PrivateKey) {
				t.Fatal("the Reality PRIVATE key is in a share URL")
			}
		case "tg":
			sawTG = true
			// The user's own secret, never another user's: it is what
			// attributes their Telegram traffic to them.
			want := user.MTProtoSecret
			if want == "" {
				want = secrets.MTProto.Secret
			}
			if got := u.Query().Get("secret"); got != want || got == "" {
				t.Errorf("tg:// URL carries %q, want %q", got, want)
			}
		}
	}
	if !sawVless || !sawTG {
		t.Errorf("expected both a vless and a tg URL, got %v", bundle.URLs)
	}

	decoded, err := base64.StdEncoding.DecodeString(string(bundle.Subscription))
	if err != nil {
		t.Fatalf("subscription is not standard base64: %v", err)
	}
	for _, raw := range bundle.URLs {
		if !strings.Contains(string(decoded), raw) {
			t.Errorf("subscription is missing %q", raw)
		}
	}
}

func TestWireGuardConfigsPairWithTheServer(t *testing.T) {
	_, secrets, _, clients := generate(t, nil)
	bundle := clients[0]
	user := secrets.Users[0]

	for _, p := range []profile.Protocol{profile.AWG2, profile.AWG3, profile.WGMasque, profile.WGWDTT} {
		conf, ok := bundle.WireGuard[p]
		if !ok {
			t.Errorf("%s: no .conf emitted", p)
			continue
		}
		peer := user.Peers[p]
		server := secrets.Endpoints[p]

		if !strings.Contains(conf, "PrivateKey = "+peer.PrivateKey) {
			t.Errorf("%s: the client's own private key is not in its config", p)
		}
		if !strings.Contains(conf, "PublicKey = "+server.PublicKey) {
			t.Errorf("%s: the server's public key is not in the [Peer] section", p)
		}
		// The server's private key must never reach a client file.
		if strings.Contains(conf, server.PrivateKey) {
			t.Fatalf("%s: the SERVER's private key is in a client config", p)
		}
		if !strings.Contains(conf, "Address = "+peer.Address.String()) {
			t.Errorf("%s: wrong tunnel address", p)
		}

		// AmneziaWG parameters must appear exactly where the server has them;
		// a mismatch fails the handshake with no diagnostic at all.
		hasAWG := strings.Contains(conf, "Jc = ")
		if hasAWG != server.HasAWGParams {
			t.Errorf("%s: config has AWG params = %v, server = %v", p, hasAWG, server.HasAWGParams)
		}
		if server.HasAWGParams && !strings.Contains(conf, "H1 = "+server.Obfuscation.H1) {
			t.Errorf("%s: H1 disagrees with the server", p)
		}
	}
}

func TestOmissionsAlwaysExplainThemselves(t *testing.T) {
	_, _, _, clients := generate(t, nil)
	if len(clients[0].Omitted) == 0 {
		t.Fatal("no omissions recorded, yet several protocols have no share-URL form")
	}
	for _, o := range clients[0].Omitted {
		if o.Protocol == "" || o.Artifact == "" || o.Reason == "" {
			t.Errorf("incomplete omission: %+v", o)
		}
		if len(o.Reason) < 20 {
			t.Errorf("%s/%s: reason is too terse to act on: %q", o.Protocol, o.Artifact, o.Reason)
		}
	}
}

func TestNoPublicHostIsRefused(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	bundle, err := profile.Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	// Silently emitting URLs pointing at a wildcard would be worse than
	// refusing: they would look valid and connect to nothing.
	if _, err := client.Generate(spec, bundle.Secrets, client.Endpoint{}); err == nil {
		t.Fatal("client.Generate accepted an empty public host")
	}
}

// TestGeneratedClientConfigPassesSingBoxCheck mirrors the server-side test:
// generating from the core's option structs guarantees the shape, not that the
// values are usable, and only the real binary knows the difference.
func TestGeneratedClientConfigPassesSingBoxCheck(t *testing.T) {
	ctx := context.Background()
	checker, err := singbox.Detect(ctx, "", "")
	if err != nil {
		if errors.Is(err, singbox.ErrUnavailable) {
			t.Skipf("no sing-box checker available (%v)", err)
		}
		t.Fatalf("detect checker: %v", err)
	}

	_, _, _, clients := generate(t, nil)

	// The checker must be shown to refuse something first, or "it accepted our
	// config" is not evidence of anything.
	t.Run("the checker rejects a broken client config", func(t *testing.T) {
		var doc map[string]any
		if err := json.Unmarshal(clients[0].SingBox, &doc); err != nil {
			t.Fatal(err)
		}
		doc["outbounds"].([]any)[0].(map[string]any)["type"] = "telepathy"
		broken, _ := json.Marshal(doc)
		if err := checker.Check(ctx, broken); err == nil {
			t.Fatal("sing-box check accepted an unknown outbound type; the positive case below proves nothing")
		}
	})

	t.Run("the checker accepts every generated client config", func(t *testing.T) {
		for _, bundle := range clients {
			if err := checker.Check(ctx, bundle.SingBox); err != nil {
				t.Fatalf("%s: %v\n\n%s", bundle.User, err, bundle.SingBox)
			}
		}
	})
}

// TestSecretsRoundTripPreservesTheDeployment closes the hole that let the
// port bug through.
//
// The earlier agreement test built its spec in the test, so it never exercised
// the reconstruction path — which is exactly where the bug was: client
// generation filled missing ports from profile.Defaults and emitted share URLs
// pointing at port 10861 for a deployment listening on 21861, silently. This
// goes the whole way round: generate, serialise the secrets as `init` writes
// them, read them back, and check the clients built from that still agree with
// the server.
func TestSecretsRoundTripPreservesTheDeployment(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	for p := range spec.Ports {
		spec.Ports[p] += 11000
	}
	spec.RealityHandshakeServer = "www.cloudflare.com"
	spec.ShadowTLSHandshakeServer = "www.apple.com"
	spec.SnellVersion = 6

	bundle, err := profile.Generate(spec)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Through JSON, because that is how the two commands actually communicate.
	raw, err := json.Marshal(bundle.Secrets)
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

	for _, p := range spec.EnabledProtocols() {
		if recovered.Ports[p] != spec.Ports[p] {
			t.Errorf("%s: recovered port %d, deployed %d", p, recovered.Ports[p], spec.Ports[p])
		}
	}
	if recovered.RealityHandshakeServer != spec.RealityHandshakeServer {
		t.Errorf("Reality SNI recovered as %q, deployed %q", recovered.RealityHandshakeServer, spec.RealityHandshakeServer)
	}
	if recovered.ShadowTLSHandshakeServer != spec.ShadowTLSHandshakeServer {
		t.Errorf("shadowtls SNI recovered as %q, deployed %q", recovered.ShadowTLSHandshakeServer, spec.ShadowTLSHandshakeServer)
	}

	// And the artifacts built from the recovered spec must still point at the
	// real server.
	clients, err := client.Generate(recovered, restored, client.Endpoint{Host: publicHost})
	if err != nil {
		t.Fatalf("generate clients from recovered spec: %v", err)
	}
	var found bool
	for _, raw := range clients[0].URLs {
		if !strings.HasPrefix(raw, "vless://") {
			continue
		}
		found = true
		wantPort := spec.Ports[profile.VLESSReality]
		if strings.Contains(raw, "type=xhttp") {
			wantPort = spec.Ports[profile.VLESSXHTTP]
		}
		if !strings.Contains(raw, publicHost+":"+itoa(wantPort)) {
			t.Errorf("share URL does not carry the deployed port %d: %s", wantPort, raw)
		}
		if !strings.Contains(raw, "sni="+spec.RealityHandshakeServer) {
			t.Errorf("share URL does not carry the deployed SNI %q: %s", spec.RealityHandshakeServer, raw)
		}
	}
	if !found {
		t.Fatal("no vless share URL was produced")
	}
}

// TestSpecFromSecretsRefusesAnOlderFile keeps the failure loud. A secrets file
// without the deployment record cannot be used to build correct client
// artifacts, and guessing is what caused the bug.
func TestSpecFromSecretsRefusesAnOlderFile(t *testing.T) {
	bundle, err := profile.Generate(profile.Defaults([]string{"alice"}))
	if err != nil {
		t.Fatal(err)
	}
	secrets := bundle.Secrets
	secrets.Deployment.Ports = nil
	if _, err := profile.SpecFromSecrets(secrets); err == nil {
		t.Fatal("SpecFromSecrets accepted a file with no deployment record; it would have had to guess the ports")
	}
}

func itoa(v uint16) string { return strconv.Itoa(int(v)) }
