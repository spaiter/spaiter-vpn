package apply

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// A backup restored onto a new host brings up the same deployment: every
// server key, every user's credential, and the users the bot added after
// install, which exist only in config.json.
func TestRestoreCarriesEveryKeyAndUser(t *testing.T) {
	ctx := context.Background()
	old := newHarness(t)
	if _, err := Run(ctx, old.options); err != nil {
		t.Fatal(err)
	}
	configJSON, err := os.ReadFile(old.layout.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	secretsJSON, err := os.ReadFile(old.layout.SecretsPath())
	if err != nil {
		t.Fatal(err)
	}

	// A user the bot provisioned: present in the live config only.
	var doc map[string]any
	if err := json.Unmarshal(configJSON, &doc); err != nil {
		t.Fatal(err)
	}
	const botUUID = "6f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	for _, raw := range doc["inbounds"].([]any) {
		inbound := raw.(map[string]any)
		if inbound["tag"] == string(profile.VLESSReality) {
			inbound["users"] = append(inbound["users"].([]any), map[string]any{"name": "100000001", "uuid": botUUID})
		}
	}
	if configJSON, err = json.Marshal(doc); err != nil {
		t.Fatal(err)
	}

	fresh := newHarness(t)
	fresh.options.Restore = &Restore{Config: configJSON, Secrets: secretsJSON}
	result, err := Run(ctx, fresh.options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != plan.ModeFresh {
		t.Fatalf("mode = %q", result.Mode)
	}

	restored, err := os.ReadFile(fresh.layout.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(restored), botUUID) {
		t.Error("the bot's user did not survive the restore")
	}
	var before, after profile.Secrets
	if err := json.Unmarshal(secretsJSON, &before); err != nil {
		t.Fatal(err)
	}
	restoredSecrets, _ := os.ReadFile(fresh.layout.SecretsPath())
	if err := json.Unmarshal(restoredSecrets, &after); err != nil {
		t.Fatal(err)
	}
	if after.Reality.PrivateKey != before.Reality.PrivateKey || after.Reality.PrivateKey == "" {
		t.Error("the Reality key changed: every client would stop working")
	}
	if len(after.Users) == 0 || after.Users[0].VLESSRealityUUID != before.Users[0].VLESSRealityUUID {
		t.Errorf("the owner's UUID changed: %+v vs %+v", after.Users, before.Users)
	}
	// And a fresh install without a backup mints its own.
	other := newHarness(t)
	if _, err := Run(ctx, other.options); err != nil {
		t.Fatal(err)
	}
	minted, _ := os.ReadFile(other.layout.SecretsPath())
	if strings.Contains(string(minted), before.Reality.PrivateKey) {
		t.Fatal("an ordinary install reused another deployment's key")
	}
}
