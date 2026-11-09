package profile_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/config"
	"github.com/spaiter/spaiter-vpn/internal/profile"
	"github.com/spaiter/spaiter-vpn/internal/singbox"
)

// TestGeneratedConfigPassesSingBoxCheck is the test the plan calls for: the
// defence against schema drift when the fork is rebased. Generating from the
// fork's option structs cannot emit unparseable JSON, but it can emit values
// the binary rejects at startup, and only the binary knows which.
//
// The test deliberately checks a known-bad config first. Without that, a
// checker that silently stopped working — a missing image, a docker socket
// without permission, an exit code read from the wrong process — would make
// this test pass by doing nothing, which is precisely the failure mode
// recorded in the handover document.
func TestGeneratedConfigPassesSingBoxCheck(t *testing.T) {
	ctx := context.Background()

	checker, err := singbox.Detect(ctx, "", "")
	if err != nil {
		if errors.Is(err, singbox.ErrUnavailable) {
			t.Skipf("no sing-box checker available (%v); this test is the only thing standing between a fork rebase and a broken config, so do not leave it skipped in CI", err)
		}
		t.Fatalf("detect checker: %v", err)
	}
	t.Logf("checking with: %s", checker.Describe())

	bundle, err := profile.Generate(tierASpec())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	data, err := config.Marshal(ctx, bundle.Options)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	t.Run("the checker rejects a config it should reject", func(t *testing.T) {
		broken := withDuplicateInboundTag(t, data)
		err := checker.Check(ctx, broken)
		if err == nil {
			t.Fatal("sing-box check accepted a config with a duplicate inbound tag; the checker is not actually checking, so the positive case below proves nothing")
		}
		var checkErr *singbox.CheckError
		if !errors.As(err, &checkErr) {
			t.Fatalf("expected the checker to run and refuse, got: %v", err)
		}
		if checkErr.ExitCode == 0 {
			t.Fatalf("checker reported failure with exit code 0: %v", checkErr)
		}
	})

	t.Run("the checker accepts the generated config", func(t *testing.T) {
		if err := checker.Check(ctx, data); err != nil {
			t.Fatalf("sing-box check rejected a freshly generated Tier A config: %v\n\nconfig:\n%s", err, data)
		}
	})
}

// TestGeneratedConfigShapeMatchesTheSpec guards the structure independently of
// the binary, so a machine without Docker still catches the mistakes that are
// cheap to make: a protocol silently missing, a port collision, a peer address
// outside its subnet.
func TestGeneratedConfigShapeMatchesTheSpec(t *testing.T) {
	spec := tierASpec()
	bundle, err := profile.Generate(spec)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var doc struct {
		Inbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			ListenPort uint16 `json:"listen_port"`
			Listen     string `json:"listen"`
		} `json:"inbounds"`
		Endpoints []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			ListenPort uint16 `json:"listen_port"`
			Address    string `json:"address"`
			Peers      []struct {
				Name       string `json:"name"`
				PublicKey  string `json:"public_key"`
				AllowedIPs string `json:"allowed_ips"`
			} `json:"peers"`
		} `json:"endpoints"`
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	data, err := config.Marshal(context.Background(), bundle.Options)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("generated config is not valid JSON: %v", err)
	}

	tags := map[string]bool{}
	ports := map[uint16]string{}
	for _, in := range doc.Inbounds {
		tags[in.Tag] = true
		if other, dup := ports[in.ListenPort]; dup {
			t.Errorf("port %d used by both %s and %s", in.ListenPort, other, in.Tag)
		}
		ports[in.ListenPort] = in.Tag
	}
	for _, ep := range doc.Endpoints {
		tags[ep.Tag] = true
		if other, dup := ports[ep.ListenPort]; dup {
			t.Errorf("port %d used by both %s and %s", ep.ListenPort, other, ep.Tag)
		}
		ports[ep.ListenPort] = ep.Tag
	}
	for _, p := range profile.TierAProtocols {
		if !tags[string(p)] {
			t.Errorf("protocol %s is missing from the generated config", p)
		}
	}

	// The loopback-only inbounds must stay loopback-only: the shadowsocks one
	// is the shadowtls detour target and the websocket one expects TLS to be
	// terminated upstream, so either exposed directly is a hole.
	for _, in := range doc.Inbounds {
		switch profile.Protocol(in.Tag) {
		case profile.Shadowsocks, profile.VLESSWSCDN:
			if in.Listen != "127.0.0.1" {
				t.Errorf("%s listens on %q; it must stay on loopback", in.Tag, in.Listen)
			}
		}
	}

	for _, ep := range doc.Endpoints {
		prefix, err := netip.ParsePrefix(ep.Address)
		if err != nil {
			t.Fatalf("%s: address %q does not parse: %v", ep.Tag, ep.Address, err)
		}
		if len(ep.Peers) != len(spec.Users) {
			t.Errorf("%s has %d peers, want %d", ep.Tag, len(ep.Peers), len(spec.Users))
		}
		seenPeer := map[string]bool{}
		for _, peer := range ep.Peers {
			addr, err := netip.ParsePrefix(peer.AllowedIPs)
			if err != nil {
				t.Fatalf("%s/%s: allowed_ips %q does not parse: %v", ep.Tag, peer.Name, peer.AllowedIPs, err)
			}
			if addr.Bits() != 32 {
				t.Errorf("%s/%s: allowed_ips %s is wider than /32, so one peer could impersonate another", ep.Tag, peer.Name, addr)
			}
			if !prefix.Contains(addr.Addr()) {
				t.Errorf("%s/%s: peer address %s is outside the endpoint subnet %s", ep.Tag, peer.Name, addr, prefix)
			}
			if addr.Addr() == prefix.Addr() {
				t.Errorf("%s/%s: peer took the endpoint's own address %s", ep.Tag, peer.Name, addr)
			}
			if seenPeer[peer.AllowedIPs] {
				t.Errorf("%s: two peers share address %s", ep.Tag, peer.AllowedIPs)
			}
			seenPeer[peer.AllowedIPs] = true
			if peer.PublicKey == "" {
				t.Errorf("%s/%s: peer has no public key", ep.Tag, peer.Name)
			}
		}
	}

	// The sniff rule has to come before the reject rule: rejecting on
	// `protocol` only works once something has identified the protocol.
	if len(doc.Route.Rules) != 2 {
		t.Fatalf("expected exactly 2 route rules, got %d", len(doc.Route.Rules))
	}
	if doc.Route.Rules[0]["action"] != "sniff" {
		t.Errorf("first route rule is %v, want the sniff rule", doc.Route.Rules[0]["action"])
	}
	if doc.Route.Rules[1]["action"] != "reject" {
		t.Errorf("second route rule is %v, want the reject rule", doc.Route.Rules[1]["action"])
	}
	if doc.Route.Rules[1]["xdp_block"] != true {
		t.Error("the reject rule does not set xdp_block, so an offender is dropped but never banned")
	}
}

// TestSecretsCoverEveryUser checks the half of the output the operator
// actually hands out. A config nobody can connect to is not a deployment.
func TestSecretsCoverEveryUser(t *testing.T) {
	spec := tierASpec()
	bundle, err := profile.Generate(spec)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(bundle.Secrets.Users) != len(spec.Users) {
		t.Fatalf("secrets cover %d users, want %d", len(bundle.Secrets.Users), len(spec.Users))
	}

	seen := map[string]bool{}
	for _, user := range bundle.Secrets.Users {
		if user.VLESSRealityUUID == "" || user.VLESSWSCDNUUID == "" ||
			user.ShadowTLSPassword == "" || user.SnellUserKey == "" || user.MieruPassword == "" {
			t.Errorf("user %s is missing credentials: %+v", user.Name, user)
		}
		if user.VLESSRealityUUID == user.VLESSWSCDNUUID {
			t.Errorf("user %s got the same UUID on two inbounds, which links the two identities together", user.Name)
		}
		for _, p := range []profile.Protocol{profile.AWG2, profile.AWG3, profile.WGMasque, profile.WGWDTT} {
			peer, ok := user.Peers[p]
			if !ok {
				t.Errorf("user %s has no peer on %s", user.Name, p)
				continue
			}
			if peer.PrivateKey == "" || peer.PublicKey == "" {
				t.Errorf("user %s has an incomplete keypair on %s", user.Name, p)
			}
			if seen[peer.PrivateKey] {
				t.Errorf("private key reused across users or endpoints (user %s, %s)", user.Name, p)
			}
			seen[peer.PrivateKey] = true
		}
	}

	for _, p := range []profile.Protocol{profile.AWG2, profile.AWG3, profile.WGMasque, profile.WGWDTT} {
		ep, ok := bundle.Secrets.Endpoints[p]
		if !ok {
			t.Errorf("no server keypair recorded for %s", p)
			continue
		}
		if ep.PrivateKey == "" || ep.PublicKey == "" {
			t.Errorf("%s: incomplete server keypair", p)
		}
		// The plain-WG backends must not carry AmneziaWG parameters: the
		// obfuscation is supplied by what wraps them, and junk here only
		// costs MTU on paths already at the 1280-byte floor.
		switch p {
		case profile.AWG2, profile.AWG3:
			if !ep.HasAWGParams {
				t.Errorf("%s has no AmneziaWG parameters", p)
			}
		default:
			if ep.HasAWGParams {
				t.Errorf("%s should be plain WireGuard but carries AmneziaWG parameters", p)
			}
		}
	}

	if len(bundle.Secrets.ClashAPISecret) != 43 {
		t.Errorf("clash API secret is %d characters, want 43", len(bundle.Secrets.ClashAPISecret))
	}
	if bundle.Secrets.Reality.PrivateKey == "" || bundle.Secrets.Reality.PublicKey == "" {
		t.Error("no Reality keypair recorded; clients cannot be configured without the public key")
	}
}

func TestValidateRejectsBrokenSpecs(t *testing.T) {
	cases := map[string]func(*profile.Spec){
		"no users": func(s *profile.Spec) { s.Users = nil },
		"duplicate users": func(s *profile.Spec) {
			s.Users = []string{"alice", "alice"}
		},
		"port collision": func(s *profile.Spec) {
			s.Ports[profile.Snell] = s.Ports[profile.Mieru]
		},
		"overlapping subnets": func(s *profile.Spec) {
			s.Subnets[profile.AWG3] = s.Subnets[profile.AWG2]
		},
		"shadowtls without its detour target": func(s *profile.Spec) {
			s.Enabled = map[profile.Protocol]bool{profile.ShadowTLS: true}
		},
		"more users than the subnet holds": func(s *profile.Spec) {
			s.Subnets[profile.AWG2] = netip.MustParsePrefix("10.10.0.0/30")
			s.Users = []string{"a", "b", "c", "d", "e"}
		},
		"tier b is not implemented": func(s *profile.Spec) { s.Tier = profile.TierB },
		"unknown protocol": func(s *profile.Spec) {
			s.Enabled = map[profile.Protocol]bool{"telepathy-in": true}
		},
		"empty config output path": func(s *profile.Spec) { s.ConfigOutputPath = "" },
		"empty log output":         func(s *profile.Spec) { s.LogOutput = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := tierASpec()
			mutate(&spec)
			if err := spec.Validate(); err == nil {
				t.Fatal("Validate accepted a spec it should have refused")
			}
			if _, err := profile.Generate(spec); err == nil {
				t.Fatal("Generate produced a config from a spec it should have refused")
			}
		})
	}

	// And the unmodified spec must pass, or every case above is vacuous.
	if err := tierASpec().Validate(); err != nil {
		t.Fatalf("the baseline spec does not validate, so the negative cases prove nothing: %v", err)
	}
}

func tierASpec() profile.Spec {
	spec := profile.Defaults([]string{"alice", "bob", "carol"})
	spec.XDPInterfaces = []string{"eth0"}
	return spec
}

func withDuplicateInboundTag(t *testing.T, data []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal generated config: %v", err)
	}
	inbounds, ok := doc["inbounds"].([]any)
	if !ok || len(inbounds) < 2 {
		t.Fatalf("expected at least two inbounds to collide, got %T", doc["inbounds"])
	}
	first := inbounds[0].(map[string]any)
	second := inbounds[1].(map[string]any)
	second["tag"] = first["tag"]

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		t.Fatalf("re-encode config: %v", err)
	}
	return buf.Bytes()
}
