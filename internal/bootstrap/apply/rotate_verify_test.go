package apply

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func peer(pub, priv, addr string) profile.PeerSecrets {
	return profile.PeerSecrets{PublicKey: pub, PrivateKey: priv, Address: netip.MustParsePrefix(addr)}
}

// rotationBefore has "a" selected and "b" left alone.
func rotationBefore() *pendingRotation {
	return &pendingRotation{
		users: map[string]bool{"a": true},
		before: profile.Secrets{Users: []profile.UserSecrets{
			{Name: "a", VLESSRealityUUID: "old-a", Peers: map[profile.Protocol]profile.PeerSecrets{profile.AWG2: peer("pa", "ka", "10.0.0.2/24")}},
			{Name: "b", VLESSRealityUUID: "old-b", Peers: map[profile.Protocol]profile.PeerSecrets{profile.AWG2: peer("pb", "kb", "10.0.0.3/24")}},
		}},
	}
}

// rotationAfter is a correct outcome: a reissued everywhere, b untouched.
func rotationAfter() profile.Secrets {
	return profile.Secrets{Users: []profile.UserSecrets{
		{Name: "a", VLESSRealityUUID: "new-a", Peers: map[profile.Protocol]profile.PeerSecrets{profile.AWG2: peer("pa2", "ka2", "10.0.0.2/24")}},
		{Name: "b", VLESSRealityUUID: "old-b", Peers: map[profile.Protocol]profile.PeerSecrets{profile.AWG2: peer("pb", "kb", "10.0.0.3/24")}},
	}}
}

func TestVerifyRotationNamesEachWayAnOutcomeCanBeWrong(t *testing.T) {
	if err := verifyRotation(rotationBefore(), rotationAfter()); err != nil {
		t.Fatalf("a correct outcome failed: %v", err)
	}
	cases := map[string]struct {
		mutate func(*profile.Secrets)
		want   string
	}{
		"a user vanished":          {func(s *profile.Secrets) { s.Users = s.Users[:1] }, "user count changed"},
		"users reordered":          {func(s *profile.Secrets) { s.Users[0].Name, s.Users[1].Name = "b", "a" }, "changed from"},
		"a peer set shrank":        {func(s *profile.Secrets) { s.Users[0].Peers = nil }, "peer set changed"},
		"an unselected peer moved": {func(s *profile.Secrets) { s.Users[1].Peers[profile.AWG2] = peer("pb", "kb", "10.0.0.9/24") }, "was not selected but its"},
		"a slot vanished":          {func(s *profile.Secrets) { s.Users[0].VLESSRealityUUID = "" }, "appeared or disappeared"},
		"a slot appeared":          {func(s *profile.Secrets) { s.Users[0].SnellUserKey = "x" }, "appeared or disappeared"},
		"a peer address moved":     {func(s *profile.Secrets) { s.Users[0].Peers[profile.AWG2] = peer("pa2", "ka2", "10.0.0.7/24") }, "address changed"},
		"a peer went missing": {func(s *profile.Secrets) {
			s.Users[0].Peers = map[profile.Protocol]profile.PeerSecrets{profile.WGMasque: peer("x", "y", "10.0.0.2/24")}
		}, "address changed"},
		"a keypair was kept":         {func(s *profile.Secrets) { s.Users[0].Peers[profile.AWG2] = peer("pa", "ka", "10.0.0.2/24") }, "keypair was not reissued"},
		"a private key went missing": {func(s *profile.Secrets) { s.Users[0].Peers[profile.AWG2] = peer("pa2", "", "10.0.0.2/24") }, "keypair was not reissued"},
	}
	for name, tc := range cases {
		after := rotationAfter()
		tc.mutate(&after)
		if err := verifyRotation(rotationBefore(), after); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
