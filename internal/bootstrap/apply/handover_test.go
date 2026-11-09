package apply

import (
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func TestTheHandoverGainsWhatAMigrationMintedAndKeepsWhatClientsHold(t *testing.T) {
	handover := profile.Secrets{
		Deployment: profile.DeploymentFacts{Ports: map[profile.Protocol]uint16{profile.AWG2: 1}},
		Users:      []profile.UserSecrets{{Name: "owner", VLESSRealityUUID: "u-1", Peers: map[profile.Protocol]profile.PeerSecrets{}}},
	}
	rendered := profile.Secrets{
		Deployment: profile.DeploymentFacts{Ports: map[profile.Protocol]uint16{profile.AWG2: 2}},
		MTProto:    profile.MTProtoSecrets{FrontDomain: "www.google.com"},
		Users: []profile.UserSecrets{{Name: "owner", VLESSRealityUUID: "u-1", MTProtoSecret: "ee-new", MieruPassword: "m-new",
			Peers: map[profile.Protocol]profile.PeerSecrets{profile.AWG3: {PrivateKey: "p", PublicKey: "P"}}}},
	}
	out, err := refreshHandover(handover, rendered)
	if err != nil {
		t.Fatal(err)
	}
	owner := out.Users[0]
	if out.Deployment.Ports[profile.AWG2] != 2 || owner.MTProtoSecret != "ee-new" || owner.MieruPassword != "m-new" || owner.Peers[profile.AWG3].PrivateKey != "p" {
		t.Fatalf("refreshed handover = %#v", out)
	}
	if owner.VLESSRealityUUID != "u-1" || handover.Users[0].MieruPassword != "" {
		t.Fatal("the refresh changed what the client held, or mutated its input")
	}
	rendered.Users[0].VLESSRealityUUID = "u-2"
	if _, err := refreshHandover(handover, rendered); err == nil || !strings.Contains(err.Error(), "disagrees") {
		t.Fatalf("a credential that disagrees with the live config was accepted: %v", err)
	}
}
