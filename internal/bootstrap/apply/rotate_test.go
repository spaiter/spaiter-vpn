package apply

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/plan"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/transaction"
	botstate "github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/config"
	"github.com/spaiter/spaiter-vpn/internal/deploy"
	"github.com/spaiter/spaiter-vpn/internal/keys"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// rotationFixture is a bot-backed deployment with two seed users and one bot
// user "42" whose every client-side copy exists: a peer file per endpoint, a
// WG-over-VK password and relay entry with a bound device, and a subscription
// token per user.
type rotationFixture struct {
	h          *harness
	previous   state.State
	relayPath  string
	subsPath   string
	cachePath  string
	botPeers   map[profile.Protocol]string
	liveBefore profile.Secrets
	seedBefore profile.Secrets
	tokens     map[string]string
}

func newRotationFixture(t *testing.T) *rotationFixture {
	t.Helper()
	h := newHarness(t)
	h.options.Desired = state.Default([]string{"owner", "guest"})
	h.enableBot(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	f := &rotationFixture{h: h, botPeers: map[profile.Protocol]string{}}

	live := liveSecrets(t, h)
	spec, err := h.options.Desired.DeploymentSpec([]string{"eth0"}, h.options.Secrets.Resolver())
	if err != nil {
		t.Fatal(err)
	}
	spec.Users = append(live.Names(), "42")
	expanded, err := profile.Regenerate(spec, live)
	if err != nil {
		t.Fatal(err)
	}
	configJSON, err := config.Marshal(context.Background(), expanded.Options)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.layout.ConfigPath(), configJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	var botUser profile.UserSecrets
	for _, user := range expanded.Secrets.Users {
		if user.Name == "42" {
			botUser = user
		}
	}
	if len(botUser.Peers) == 0 || botUser.Peers[profile.WGWDTT].PrivateKey == "" {
		t.Fatalf("fixture needs a bot user with a WG-over-VK peer, got %#v", botUser.Peers)
	}
	peerDir := filepath.Join(h.layout.BotDataDir(), "awg")
	if err := os.MkdirAll(peerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for protocol, peer := range botUser.Peers {
		name := "42.json"
		if protocol != profile.AWG2 {
			name = "42-" + string(protocol) + ".json"
		}
		path := filepath.Join(peerDir, name)
		data, _ := json.Marshal(botstate.Peer{Priv: peer.PrivateKey, Pub: peer.PublicKey, IP: peer.Address.Addr().String()})
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		f.botPeers[protocol] = path
	}

	wdttDir := filepath.Join(h.layout.BotDataDir(), "wdtt")
	if err := os.MkdirAll(filepath.Join(wdttDir, "subs-cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wdttDir, "42.json"), []byte(`{"password":"old-relay-secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f.tokens = map[string]string{"owner": "token-owner", "guest": "token-guest", "42": "token-42"}
	subs := map[string]any{}
	for uid, token := range f.tokens {
		subs[token] = map[string]any{"uid": uid, "created": "2026-01-01 00:00:00", "last_hash": "h-" + uid}
	}
	subsJSON, _ := json.Marshal(subs)
	f.subsPath = filepath.Join(wdttDir, "subs.json")
	if err := os.WriteFile(f.subsPath, subsJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	f.cachePath = filepath.Join(wdttDir, "subs-cache", "token-42.json")
	if err := os.WriteFile(f.cachePath, []byte(`{"outbounds":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	relayDir := filepath.Join(filepath.Dir(h.layout.DataRoot), "wdtt-relay")
	if err := os.MkdirAll(relayDir, 0o700); err != nil {
		t.Fatal(err)
	}
	wdttPeer := botUser.Peers[profile.WGWDTT]
	relay := map[string]any{
		"bot_token": "relay-owned-token",
		"devices": map[string]any{
			"dev-attacker": map[string]any{"ip": "10.66.0.2"},
			"dev-other":    map[string]any{"ip": "10.66.0.3"},
		},
		"passwords": map[string]any{
			"old-relay-secret": map[string]any{
				"max_devices": 2, "wg_priv": wdttPeer.PrivateKey, "wg_ip": wdttPeer.Address.Addr().String(),
				"down_bytes": 1234, "label": "forty-two", "device_id": "dev-attacker", "device_ids": []string{"dev-attacker"},
			},
			"someone-else": map[string]any{"max_devices": 1, "device_id": "dev-other", "device_ids": []string{"dev-other"}},
		},
	}
	relayJSON, _ := json.MarshalIndent(relay, "", "  ")
	f.relayPath = filepath.Join(relayDir, "passwords.json")
	if err := os.WriteFile(f.relayPath, append(relayJSON, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	h.options.Desired.Bot.WDTTConfigDirectory = relayDir
	f.previous = h.options.Desired
	f.liveBefore = liveSecrets(t, h)
	if err := json.Unmarshal(mustRead(t, h.layout.SecretsPath()), &f.seedBefore); err != nil {
		t.Fatal(err)
	}
	return f
}

// rotate installs the fixture's state as the previous generation and asks
// for a rotation of users.
func (f *rotationFixture) rotate(t *testing.T, id string, users ...string) {
	t.Helper()
	desired := f.previous
	desired.MigrationPolicy = &state.MigrationPolicy{RotateCredentials: &state.CredentialRotation{
		ID: id, Users: users, Strategy: state.CredentialRotationStrategyReissue,
	}}
	f.h.options.Desired = desired
	f.h.installed(t, f.previous)
	f.h.observeBotCredential()
	f.h.replan(t)
}

func liveSecrets(t *testing.T, h *harness) profile.Secrets {
	t.Helper()
	parsed, err := config.Unmarshal(context.Background(), mustRead(t, h.layout.ConfigPath()))
	if err != nil {
		t.Fatal(err)
	}
	live, err := profile.SecretsFromConfig(parsed)
	if err != nil {
		t.Fatal(err)
	}
	return live
}

func userByName(t *testing.T, s profile.Secrets, name string) profile.UserSecrets {
	t.Helper()
	for _, user := range s.Users {
		if user.Name == name {
			return user
		}
	}
	t.Fatalf("user %q not found in %v", name, s.Names())
	return profile.UserSecrets{}
}

func TestCredentialRotationReissuesEveryCopyOfSelectedUsersOnly(t *testing.T) {
	f := newRotationFixture(t)
	h := f.h
	f.rotate(t, "r1", "42", "owner")
	if h.options.Approved.Mode != plan.ModeMigrate || h.options.Approved.Blocked {
		t.Fatalf("plan = %s blocked=%v %#v", h.options.Approved.Mode, h.options.Approved.Blocked, h.options.Approved.Actions)
	}
	if !slices.ContainsFunc(h.options.Approved.Actions, func(a plan.Action) bool { return a.ID == "rotate-credentials" }) {
		t.Fatalf("plan does not name the rotation: %#v", h.options.Approved.Actions)
	}
	h.compose.calls = nil
	result, err := Run(context.Background(), h.options)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(h.compose.calls, ","), "stop:vpn-bot,pull,up"; got != want {
		t.Fatalf("compose calls = %s, want %s", got, want)
	}

	liveAfter := liveSecrets(t, h)
	if !slices.Equal(liveAfter.Names(), f.liveBefore.Names()) {
		t.Fatalf("live users = %v, want %v", liveAfter.Names(), f.liveBefore.Names())
	}
	for _, name := range []string{"owner", "42"} {
		before, after := userByName(t, f.liveBefore, name), userByName(t, liveAfter, name)
		for slot, old := range before.CredentialSlots() {
			if old != "" && after.CredentialSlots()[slot] == old {
				t.Errorf("%s %s was not reissued in config.json", name, slot)
			}
		}
		for protocol, peer := range before.Peers {
			got := after.Peers[protocol]
			if got.Address != peer.Address || got.PublicKey == peer.PublicKey {
				t.Errorf("%s %s peer = %#v, want new key at %s", name, protocol, got, peer.Address)
			}
		}
	}
	guestBefore, guestAfter := userByName(t, f.liveBefore, "guest"), userByName(t, liveAfter, "guest")
	if !maps.Equal(guestBefore.CredentialSlots(), guestAfter.CredentialSlots()) || !maps.Equal(guestBefore.Peers, guestAfter.Peers) {
		t.Fatal("guest was not selected but its live credentials changed")
	}

	var seedAfter profile.Secrets
	if err := json.Unmarshal(mustRead(t, h.layout.SecretsPath()), &seedAfter); err != nil {
		t.Fatal(err)
	}
	ownerLive, ownerSeed := userByName(t, liveAfter, "owner"), userByName(t, seedAfter, "owner")
	if ownerSeed.VLESSRealityUUID != ownerLive.VLESSRealityUUID {
		t.Fatal("secrets.json does not hand the owner the credentials the server now accepts")
	}
	for protocol, peer := range ownerLive.Peers {
		if ownerSeed.Peers[protocol].PublicKey != peer.PublicKey || ownerSeed.Peers[protocol].PrivateKey == "" {
			t.Fatalf("secrets.json owner %s peer does not match the live key", protocol)
		}
	}
	if userByName(t, seedAfter, "guest").VLESSRealityUUID != userByName(t, f.seedBefore, "guest").VLESSRealityUUID {
		t.Fatal("guest handover changed")
	}

	botLive := userByName(t, liveAfter, "42")
	for protocol, path := range f.botPeers {
		var peer botstate.Peer
		if err := json.Unmarshal(mustRead(t, path), &peer); err != nil {
			t.Fatal(err)
		}
		live := botLive.Peers[protocol]
		if peer.Pub != live.PublicKey || peer.IP != live.Address.Addr().String() || peer.Priv == "" {
			t.Fatalf("bot peer %s = %#v does not match live %#v", path, peer, live)
		}
		if !slices.Contains(result.Files, path) {
			t.Fatalf("%s absent from the rotation transaction", path)
		}
	}

	var password botstate.WDTTPassword
	if err := json.Unmarshal(mustRead(t, filepath.Join(h.layout.BotDataDir(), "wdtt", "42.json")), &password); err != nil {
		t.Fatal(err)
	}
	if password.Password == "" || password.Password == "old-relay-secret" {
		t.Fatalf("relay password was not reissued: %q", password.Password)
	}
	var relay map[string]json.RawMessage
	if err := json.Unmarshal(mustRead(t, f.relayPath), &relay); err != nil {
		t.Fatal(err)
	}
	var entries map[string]map[string]json.RawMessage
	var devices map[string]json.RawMessage
	if json.Unmarshal(relay["passwords"], &entries) != nil || json.Unmarshal(relay["devices"], &devices) != nil {
		t.Fatalf("relay file is malformed: %s", mustRead(t, f.relayPath))
	}
	if _, ok := entries["old-relay-secret"]; ok {
		t.Fatal("the old relay password still authenticates")
	}
	entry := entries[password.Password]
	var wdttPeer botstate.Peer
	if err := json.Unmarshal(mustRead(t, f.botPeers[profile.WGWDTT]), &wdttPeer); err != nil {
		t.Fatal(err)
	}
	wantPriv, _ := json.Marshal(wdttPeer.Priv)
	if string(entry["wg_priv"]) != string(wantPriv) || string(entry["down_bytes"]) != "1234" || string(entry["label"]) != `"forty-two"` || string(entry["max_devices"]) != "2" {
		t.Fatalf("new relay entry = %v", entry)
	}
	if _, bound := entry["device_ids"]; bound {
		t.Fatal("the new relay password inherited the old device bindings")
	}
	if _, ok := devices["dev-attacker"]; ok {
		t.Fatal("the device bound with the old password is still registered")
	}
	if _, ok := devices["dev-other"]; !ok || string(relay["bot_token"]) != `"relay-owned-token"` {
		t.Fatal("relay state that belongs to other users or to the relay was lost")
	}
	if _, ok := entries["someone-else"]; !ok {
		t.Fatal("another user's relay password was removed")
	}
	if _, err := os.Stat((deploy.Bot{DataDir: h.layout.BotDataDir()}).WDTTReloadMarkerPath()); err != nil {
		t.Fatalf("relay reload marker was not touched: %v", err)
	}

	var subs map[string]botstate.Subscription
	if err := json.Unmarshal(mustRead(t, f.subsPath), &subs); err != nil {
		t.Fatal(err)
	}
	if len(subs) != 3 {
		t.Fatalf("subscriptions = %#v", subs)
	}
	if subs[f.tokens["guest"]].UID != "guest" || subs[f.tokens["guest"]].LastHash != "h-guest" {
		t.Fatal("guest's subscription token changed")
	}
	for _, uid := range []string{"owner", "42"} {
		if _, ok := subs[f.tokens[uid]]; ok {
			t.Fatalf("%s's old subscription token still serves", uid)
		}
		found := false
		for _, sub := range subs {
			if sub.UID == uid && sub.LastHash == "" {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s has no fresh subscription token: %#v", uid, subs)
		}
	}
	if _, err := os.Stat(f.cachePath); !os.IsNotExist(err) {
		t.Fatalf("subscription cache survived the rotation: %v", err)
	}

	// A later process rebuilds its allowlist from the layout alone. It must
	// accept every path the rotation's receipt now owns, or nothing can ever
	// touch this deployment again: acceptance found exactly that.
	targets, err := h.layout.TransactionTargets()
	if err != nil {
		t.Fatal(err)
	}
	fresh := &transaction.Manager{StateDir: h.layout.BootstrapStateDir(), AllowedTargets: targets, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	if err := fresh.Recover(); err != nil {
		t.Fatalf("a fresh process cannot recover after the rotation: %v", err)
	}
	if _, _, err := fresh.Current(); err != nil {
		t.Fatalf("a fresh process cannot read the rotation's receipt: %v", err)
	}

	// Retained as an audit record, the same entry rotates nothing again.
	rotated := liveSecrets(t, h)
	h.installed(t, h.options.Desired)
	h.observeBotCredential()
	h.replan(t)
	if h.options.Approved.Mode != plan.ModeReconcile {
		t.Fatalf("retained rotation record planned %s", h.options.Approved.Mode)
	}
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatalf("convergence with a retained rotation record: %v", err)
	}
	if userByName(t, liveSecrets(t, h), "owner").VLESSRealityUUID != userByName(t, rotated, "owner").VLESSRealityUUID {
		t.Fatal("a retained rotation record rotated again")
	}
}

func TestCredentialRotationRefusesAnUnknownUserBeforeWriting(t *testing.T) {
	f := newRotationFixture(t)
	h := f.h
	configBefore, relayBefore, subsBefore := digestFile(t, h.layout.ConfigPath()), digestFile(t, f.relayPath), digestFile(t, f.subsPath)
	f.rotate(t, "r1", "nobody")
	h.compose.calls = nil
	_, err := Run(context.Background(), h.options)
	if err == nil || !strings.Contains(err.Error(), "not a user of the live configuration") {
		t.Fatalf("err = %v", err)
	}
	if got, want := strings.Join(h.compose.calls, ","), "stop:vpn-bot,up"; got != want {
		t.Fatalf("compose calls = %s, want the bot stopped and brought back (%s)", got, want)
	}
	if digestFile(t, h.layout.ConfigPath()) != configBefore || digestFile(t, f.relayPath) != relayBefore || digestFile(t, f.subsPath) != subsBefore {
		t.Fatal("a refused rotation wrote something")
	}
}

func TestCredentialRotationRefusesAPeerWithoutAPrivateCopy(t *testing.T) {
	f := newRotationFixture(t)
	if err := os.Remove(f.botPeers[profile.AWG2]); err != nil {
		t.Fatal(err)
	}
	f.rotate(t, "r1", "42")
	_, err := Run(context.Background(), f.h.options)
	if err == nil || !strings.Contains(err.Error(), "no private-key copy") {
		t.Fatalf("err = %v", err)
	}
}

func TestCredentialRotationMustNotRideAlongAnotherMigration(t *testing.T) {
	f := newRotationFixture(t)
	f.rotate(t, "r1", "owner")
	desired := f.h.options.Desired
	desired.Deployment.Ports = maps.Clone(desired.Deployment.Ports)
	desired.Deployment.Ports[profile.AWG2]++
	f.h.options.Desired = desired
	f.h.replan(t)
	if f.h.options.Approved.Mode != plan.ModeMigrationRequired || !f.h.options.Approved.Blocked {
		t.Fatalf("plan = %s blocked=%v", f.h.options.Approved.Mode, f.h.options.Approved.Blocked)
	}
}

func TestFailedCredentialRotationRestoresEveryCopy(t *testing.T) {
	f := newRotationFixture(t)
	h := f.h
	paths := []string{h.layout.ConfigPath(), h.layout.SecretsPath(), f.relayPath, f.subsPath, filepath.Join(h.layout.BotDataDir(), "wdtt", "42.json")}
	for _, path := range f.botPeers {
		paths = append(paths, path)
	}
	before := map[string]string{}
	for _, path := range paths {
		before[path] = digestFile(t, path)
	}
	f.rotate(t, "r1", "42", "owner")
	h.options.SelfTest = func(context.Context, io.Writer) error { return errors.New("selftest failed") }
	if _, err := Run(context.Background(), h.options); err == nil {
		t.Fatal("rotation succeeded despite a failed self-test")
	} else {
		t.Log(err)
	}
	for _, path := range paths {
		if digestFile(t, path) != before[path] {
			t.Errorf("%s was not restored after the failed rotation", path)
		}
	}
	if _, err := os.Stat(f.cachePath); err != nil {
		t.Errorf("subscription cache was not restored: %v", err)
	}
}

func TestVerifyRotationRejectsCollateralChanges(t *testing.T) {
	f := newRotationFixture(t)
	runtime, err := f.h.options.readRuntimeState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pending, err := f.h.options.prepareCredentialRotation(runtime, state.CredentialRotation{ID: "r", Users: []string{"owner"}, Strategy: state.CredentialRotationStrategyReissue})
	if err != nil {
		t.Fatal(err)
	}
	spec, err := f.previous.DeploymentSpec([]string{"eth0"}, f.h.options.Secrets.Resolver())
	if err != nil {
		t.Fatal(err)
	}
	spec.Users = runtime.credentials.Names()
	bundle, err := profile.Regenerate(spec, runtime.credentials)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRotation(pending, bundle.Secrets); err != nil {
		t.Fatalf("a correct rotation failed its proof: %v", err)
	}

	guest := cloneSecrets(bundle.Secrets)
	for i := range guest.Users {
		if guest.Users[i].Name == "guest" {
			guest.Users[i].VLESSRealityUUID = "00000000-0000-4000-8000-000000000000"
		}
	}
	if err := verifyRotation(pending, guest); err == nil {
		t.Fatal("a change to an unselected user passed the proof")
	}
	shared := cloneSecrets(bundle.Secrets)
	shared.Reality.PrivateKey = "changed"
	if err := verifyRotation(pending, shared); err == nil {
		t.Fatal("a change to a deployment-wide key passed the proof")
	}
	stale := cloneSecrets(bundle.Secrets)
	for i := range stale.Users {
		if stale.Users[i].Name == "owner" {
			stale.Users[i].VLESSRealityUUID = userByName(t, pending.before, "owner").VLESSRealityUUID
		}
	}
	if err := verifyRotation(pending, stale); err == nil {
		t.Fatal("a slot that was not reissued passed the proof")
	}
}

// TestMigrationIssuesNothingNewToABotUser is the defect acceptance found: a
// migration re-rendered a bot user onto every endpoint, minting peers whose
// private halves nobody stored. The bot then provisioned a second peer of the
// same name beside each orphan.
func TestMigrationIssuesNothingNewToABotUser(t *testing.T) {
	h := newHarness(t)
	h.enableBot(t)
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	pair, err := keys.NewX25519()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(mustRead(t, h.layout.ConfigPath()), &doc); err != nil {
		t.Fatal(err)
	}
	for _, raw := range doc["endpoints"].([]any) {
		endpoint := raw.(map[string]any)
		if endpoint["tag"] == string(profile.AWG2) {
			endpoint["peers"] = append(endpoint["peers"].([]any), map[string]any{
				"name": "42", "public_key": pair.PublicStd(), "allowed_ips": []string{"10.10.0.9/32"},
			})
		}
	}
	data, _ := json.Marshal(doc)
	if err := os.WriteFile(h.layout.ConfigPath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := userByName(t, liveSecrets(t, h), "42").HeldSlots(); len(got) != 1 {
		t.Fatalf("fixture bot user holds %v", got)
	}

	previous := h.options.Desired
	desired := previous
	desired.Deployment.Ports = maps.Clone(previous.Deployment.Ports)
	desired.Deployment.Ports[profile.AWG2]++
	h.options.Desired = desired
	h.installed(t, previous)
	h.observeBotCredential()
	h.replan(t)
	if h.options.Approved.Mode != plan.ModeMigrate {
		t.Fatalf("mode = %s", h.options.Approved.Mode)
	}
	if _, err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	bot := userByName(t, liveSecrets(t, h), "42")
	if got := bot.HeldSlots(); len(got) != 1 || !got[profile.PeerSlot(profile.AWG2)] || bot.Peers[profile.AWG2].PublicKey != pair.PublicStd() {
		t.Fatalf("after the migration the bot user holds %v (%#v)", got, bot.Peers)
	}
	if owner := userByName(t, liveSecrets(t, h), "owner"); len(owner.Peers) < 2 || owner.VLESSRealityUUID == "" {
		t.Fatal("the seed user lost credentials")
	}
}
