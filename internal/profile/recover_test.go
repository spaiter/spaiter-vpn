package profile

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/spaiter/spaiter-vpn/internal/config"
)

// TestSecretsFromConfigRebuildsTheSameServer proves the property migration
// needs: the live config is a complete store for every credential the server
// uses, including users the bot added after the initial secrets.json snapshot.
// Client-only private peer keys are intentionally absent, but re-rendering the
// server must still be byte-identical.
func TestSecretsFromConfigRebuildsTheSameServer(t *testing.T) {
	ctx := context.Background()
	spec := Defaults([]string{"alice", "bob"})
	generated, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	data, err := config.Marshal(ctx, generated.Options)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := config.Unmarshal(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := SecretsFromConfig(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(recovered.Names(), []string{"alice", "bob"}) {
		t.Fatalf("recovered users = %v", recovered.Names())
	}
	if recovered.ClashAPISecret != generated.Secrets.ClashAPISecret {
		t.Fatal("the management credential was not recovered")
	}
	for _, user := range recovered.Users {
		for protocol, peer := range user.Peers {
			if peer.PublicKey == "" || !peer.Address.IsValid() {
				t.Errorf("%s/%s: incomplete server-side peer", user.Name, protocol)
			}
			if peer.PrivateKey != "" {
				t.Errorf("%s/%s: recovered a client-only private key from the server", user.Name, protocol)
			}
		}
	}

	rebuiltSpec := Defaults(recovered.Names())
	rebuilt, err := Regenerate(rebuiltSpec, recovered)
	if err != nil {
		t.Fatal(err)
	}
	rebuiltData, err := config.Marshal(ctx, rebuilt.Options)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, rebuiltData) {
		t.Fatal("config -> credentials -> config changed the server configuration")
	}
}

func TestSecretsFromConfigRejectsAnUnreadableRealityKey(t *testing.T) {
	spec := Defaults([]string{"alice"})
	generated, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	for index := range generated.Options.Inbounds {
		inbound := &generated.Options.Inbounds[index]
		if inbound.Tag != string(VLESSReality) {
			continue
		}
		options := inbound.Options.(*option.VLESSInboundOptions)
		options.TLS.Reality.PrivateKey = "not-an-x25519-key"
	}
	if _, err := SecretsFromConfig(generated.Options); err == nil {
		t.Fatal("an unreadable Reality key was accepted as recoverable")
	}
}

func TestSecretsFromTierBConfigRebuildsTheSameServer(t *testing.T) {
	ctx := context.Background()
	spec := Defaults([]string{"alice", "bob"})
	spec.Tier = TierB
	spec.Domain = "vpn.example.com"
	spec.Certs.Source = CertSourceACMEHTTP
	spec.Certs.Email = "ops@example.com"

	generated, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	data, err := config.Marshal(ctx, generated.Options)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := config.Unmarshal(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := SecretsFromConfig(parsed)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := Regenerate(spec, recovered)
	if err != nil {
		t.Fatal(err)
	}
	rebuiltData, err := config.Marshal(ctx, rebuilt.Options)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, rebuiltData) {
		t.Fatal("Tier B config -> credentials -> config changed the server configuration")
	}
}
