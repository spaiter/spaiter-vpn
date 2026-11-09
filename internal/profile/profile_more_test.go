package profile

import (
	"net/netip"
	"strings"
	"testing"
)

func TestSubnetMoveNamesWhatCannotBeMoved(t *testing.T) {
	from := netip.MustParsePrefix("10.10.0.0/24")
	to := netip.MustParsePrefix("10.99.0.0/24")
	base := Secrets{
		Endpoints: map[Protocol]EndpointSecrets{AWG2: {Address: netip.MustParsePrefix("10.10.0.1/24")}},
		Users: []UserSecrets{
			{Name: "idle"}, // holds no AWG2 peer at all
			{Name: "alice", Peers: map[Protocol]PeerSecrets{AWG2: {Address: netip.MustParsePrefix("10.10.0.2/32")}}},
		},
	}
	if got, err := ReassignSubnetPreserveHost(base, AWG2, from, to); err != nil || len(got.Users[0].Peers) != 0 {
		t.Fatalf("a user without a peer: %v", err)
	}

	cases := map[string]struct {
		protocol Protocol
		mutate   func(*Secrets)
		to       netip.Prefix
		want     string
	}{
		"not wireguard":       {VLESSReality, func(*Secrets) {}, to, "is not WireGuard"},
		"no endpoint":         {AWG3, func(*Secrets) {}, to, "no endpoint for"},
		"an endpoint outside": {AWG2, func(s *Secrets) { s.Endpoints[AWG2] = EndpointSecrets{Address: netip.MustParsePrefix("172.16.0.1/24")} }, to, "endpoint"},
		"a peer outside": {AWG2, func(s *Secrets) {
			s.Users[1].Peers[AWG2] = PeerSecrets{Address: netip.MustParsePrefix("172.16.0.9/32")}
		}, to, "user \"alice\" peer"},
		"two peers on one host": {AWG2, func(s *Secrets) {
			s.Users = append(s.Users, UserSecrets{Name: "bob", Peers: map[Protocol]PeerSecrets{AWG2: {Address: netip.MustParsePrefix("10.10.0.2/32")}}})
		}, to, "already used by user alice"},
	}
	for name, tc := range cases {
		secrets := cloneSecretsForSubnetMove(base)
		tc.mutate(&secrets)
		_, err := ReassignSubnetPreserveHost(secrets, tc.protocol, from, tc.to)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPeerAddressAllocationRefusesAStrayAddressAndAFullSubnet(t *testing.T) {
	prefix := netip.MustParsePrefix("10.5.0.0/24")
	stray := PeerSecrets{Address: netip.MustParsePrefix("192.168.1.2/32")}
	if _, err := allocatePeerAddress(prefix, stray, map[netip.Addr]bool{}); err == nil || !strings.Contains(err.Error(), "outside the endpoint subnet") {
		t.Errorf("stray: %v", err)
	}

	small := netip.MustParsePrefix("10.5.0.0/30") // room for the endpoint and two more hosts
	taken := map[netip.Addr]bool{}
	first, err := allocatePeerAddress(small, PeerSecrets{}, taken)
	if err != nil {
		t.Fatalf("first peer: %v", err)
	}
	if first.Addr().String() != "10.5.0.2" {
		t.Errorf("first = %v", first)
	}
	if _, err := allocatePeerAddress(small, PeerSecrets{}, taken); err != nil {
		t.Fatalf("second peer: %v", err)
	}
	if _, err := allocatePeerAddress(small, PeerSecrets{}, taken); err == nil || !strings.Contains(err.Error(), "no free address left") {
		t.Errorf("a full subnet: %v", err)
	}
}

func TestSpecFromSecretsRefusesWhatItCannotReconstruct(t *testing.T) {
	deployed := Secrets{
		Users:      []UserSecrets{{Name: "alice"}},
		Deployment: DeploymentFacts{Ports: map[Protocol]uint16{VLESSReality: 443}},
	}
	if _, err := SpecFromSecrets(Secrets{}); err == nil || !strings.Contains(err.Error(), "no users") {
		t.Errorf("no users: %v", err)
	}
	if _, err := SpecFromSecrets(Secrets{Users: deployed.Users}); err == nil || !strings.Contains(err.Error(), "predates the deployment record") {
		t.Errorf("no ports: %v", err)
	}
	// Ports recorded only for a protocol the tier filters out leave nothing to render.
	none := deployed
	none.Deployment = DeploymentFacts{Ports: map[Protocol]uint16{Hysteria2: 8443}}
	if _, err := SpecFromSecrets(none); err == nil || !strings.Contains(err.Error(), "no protocol") {
		t.Errorf("no protocol: %v", err)
	}
}

func TestSpecFromSecretsRestoresTierBFromItsOwnRecord(t *testing.T) {
	secrets := Secrets{
		Users:      []UserSecrets{{Name: "alice"}},
		Deployment: DeploymentFacts{Ports: map[Protocol]uint16{Hysteria2: 8443}},
	}
	secrets.TierB.Facts.Domain = "vpn.example.net"
	secrets.TierB.Facts.CertSource = CertSourceFiles
	secrets.TierB.Facts.TUICCongestionControl = "bbr"
	spec, err := SpecFromSecrets(secrets)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Tier != TierB || spec.Domain != "vpn.example.net" || spec.TUICCongestionControl != "bbr" || spec.Certs.Source != CertSourceFiles {
		t.Errorf("spec = %+v", spec)
	}
}
