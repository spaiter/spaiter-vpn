package profile

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestReassignSubnetPreserveHostMovesOnlyAddresses(t *testing.T) {
	from := netip.MustParsePrefix("10.10.0.0/24")
	to := netip.MustParsePrefix("10.99.0.0/24")
	other := netip.MustParsePrefix("10.20.0.0/24")
	input := Secrets{
		ClashAPISecret: "clash-secret",
		Endpoints: map[Protocol]EndpointSecrets{
			AWG2: {PrivateKey: "server-private", PublicKey: "server-public", Address: netip.MustParsePrefix("10.10.0.1/24")},
			AWG3: {PrivateKey: "other-private", PublicKey: "other-public", Address: netip.MustParsePrefix("10.20.0.1/24")},
		},
		Users: []UserSecrets{
			{Name: "alice", Peers: map[Protocol]PeerSecrets{
				AWG2: {PrivateKey: "alice-private", PublicKey: "alice-public", Address: netip.MustParsePrefix("10.10.0.2/32")},
				AWG3: {PrivateKey: "other-user-private", PublicKey: "other-user-public", Address: netip.MustParsePrefix("10.20.0.2/32")},
			}},
			{Name: "bob", Peers: map[Protocol]PeerSecrets{
				AWG2: {PrivateKey: "bob-private", PublicKey: "bob-public", Address: netip.MustParsePrefix("10.10.0.17/32")},
			}},
		},
	}
	original := cloneSecretsForSubnetMove(input)

	got, err := ReassignSubnetPreserveHost(input, AWG2, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if got.Endpoints[AWG2].Address.String() != "10.99.0.1/24" || got.Users[0].Peers[AWG2].Address.String() != "10.99.0.2/32" || got.Users[1].Peers[AWG2].Address.String() != "10.99.0.17/32" {
		t.Fatalf("host numbers were not preserved: %#v", got)
	}
	if got.Endpoints[AWG3].Address.Masked() != other || !reflect.DeepEqual(got.Endpoints[AWG3], input.Endpoints[AWG3]) || !reflect.DeepEqual(got.Users[0].Peers[AWG3], input.Users[0].Peers[AWG3]) {
		t.Fatal("an unrelated protocol changed")
	}

	wantKeys := cloneSecretsForSubnetMove(input)
	wantKeys.Endpoints[AWG2] = EndpointSecrets{PrivateKey: "server-private", PublicKey: "server-public", Address: got.Endpoints[AWG2].Address}
	for index := range wantKeys.Users {
		peer := wantKeys.Users[index].Peers[AWG2]
		peer.Address = got.Users[index].Peers[AWG2].Address
		wantKeys.Users[index].Peers[AWG2] = peer
	}
	if !reflect.DeepEqual(got, wantKeys) {
		t.Fatal("subnet migration changed data other than selected addresses")
	}
	if !reflect.DeepEqual(input, original) {
		t.Fatal("input was mutated")
	}
}

func TestReassignSubnetPreserveHostRejectsUnsafeMovesAtomically(t *testing.T) {
	base := Secrets{
		Endpoints: map[Protocol]EndpointSecrets{AWG2: {Address: netip.MustParsePrefix("10.10.0.1/24")}},
		Users:     []UserSecrets{{Name: "alice", Peers: map[Protocol]PeerSecrets{AWG2: {Address: netip.MustParsePrefix("10.10.0.17/32")}}}},
	}
	tests := map[string]struct {
		secrets Secrets
		to      string
		want    string
	}{
		"peer outside source": {
			secrets: Secrets{Endpoints: base.Endpoints, Users: []UserSecrets{{Name: "alice", Peers: map[Protocol]PeerSecrets{AWG2: {Address: netip.MustParsePrefix("10.11.0.17/32")}}}}},
			to:      "10.99.0.0/24", want: "outside source subnet",
		},
		"shrink loses host": {secrets: base, to: "10.99.0.0/28", want: "does not fit"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			before := test.secrets.Endpoints[AWG2].Address
			_, err := ReassignSubnetPreserveHost(test.secrets, AWG2, netip.MustParsePrefix("10.10.0.0/24"), netip.MustParsePrefix(test.to))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
			if test.secrets.Endpoints[AWG2].Address != before {
				t.Fatal("failed migration mutated input")
			}
		})
	}
}
