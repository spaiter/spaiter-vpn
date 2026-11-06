package profile

import (
	"context"
	"encoding/hex"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/config"
)

// TestRegenerateIsIdenticalForAnUnchangedSpec is the property every migration
// rests on. If re-rendering an unchanged deployment produces so much as a
// different UUID, then "change the port" and "replace the server" are the same
// operation as far as clients are concerned.
func TestRegenerateIsIdenticalForAnUnchangedSpec(t *testing.T) {
	spec := Defaults([]string{"alice", "bob"})
	first, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Regenerate(spec, first.Secrets)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Secrets, again.Secrets) {
		t.Fatal("re-rendering an unchanged spec reissued credentials")
	}

	ctx := context.Background()
	before, err := config.Marshal(ctx, first.Options)
	if err != nil {
		t.Fatal(err)
	}
	after, err := config.Marshal(ctx, again.Options)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("re-rendering an unchanged spec produced a different config")
	}
}

// TestRegenerateMovesAPortAndKeepsEveryCredential is the canonical migration:
// the shape changes, the identities do not.
func TestRegenerateMovesAPortAndKeepsEveryCredential(t *testing.T) {
	spec := Defaults([]string{"alice", "bob"})
	first, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}

	moved := Defaults([]string{"alice", "bob"})
	moved.Ports[VLESSReality] = spec.Ports[VLESSReality] + 1000
	next, err := Regenerate(moved, first.Secrets)
	if err != nil {
		t.Fatal(err)
	}

	if next.Secrets.Reality != first.Secrets.Reality {
		t.Error("the Reality keypair was reissued; no existing client could handshake")
	}
	if next.Secrets.ClashAPISecret != first.Secrets.ClashAPISecret {
		t.Error("the clash secret was reissued; the bot and the self-test would get 401s")
	}
	for i := range first.Secrets.Users {
		before, after := first.Secrets.Users[i], next.Secrets.Users[i]
		if before.Name != after.Name {
			t.Fatalf("user %d changed name: %q -> %q", i, before.Name, after.Name)
		}
		if !reflect.DeepEqual(before, after) {
			t.Errorf("user %q credentials changed across a port move", before.Name)
		}
	}
	// And the move actually happened.
	port := next.Secrets.Deployment.Ports[VLESSReality]
	if port != moved.Ports[VLESSReality] {
		t.Errorf("the recorded port is %d, want %d", port, moved.Ports[VLESSReality])
	}
}

// TestRegenerateKeepsPeerAddressesWhenAUserIsRemoved is the trap that
// index-derived addresses walk into.
//
// A fresh generation numbers peers by position in the user list. Once
// credentials are preserved that is wrong: removing the first user shifts
// everybody else down one, so an index-derived address would silently reassign
// addresses that are already in clients' configs — and the first user's old
// address would be handed to the second.
func TestRegenerateKeepsPeerAddressesWhenAUserIsRemoved(t *testing.T) {
	spec := Defaults([]string{"alice", "bob", "carol"})
	first, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	addressOf := func(bundle *Bundle, name string) netip.Prefix {
		user, ok := bundle.Secrets.user(name)
		if !ok {
			t.Fatalf("no credentials for %q", name)
		}
		return user.Peers[AWG2].Address
	}
	bobBefore := addressOf(first, "bob")
	carolBefore := addressOf(first, "carol")

	reduced := Defaults([]string{"bob", "carol"})
	next, err := Regenerate(reduced, first.Secrets)
	if err != nil {
		t.Fatal(err)
	}
	if got := addressOf(next, "bob"); got != bobBefore {
		t.Errorf("bob's peer address moved from %s to %s", bobBefore, got)
	}
	if got := addressOf(next, "carol"); got != carolBefore {
		t.Errorf("carol's peer address moved from %s to %s", carolBefore, got)
	}
	if addressOf(next, "bob") == addressOf(next, "carol") {
		t.Fatal("two users share one peer address")
	}
}

// TestRegenerateIssuesCredentialsOnlyForANewUser.
func TestRegenerateIssuesCredentialsOnlyForANewUser(t *testing.T) {
	spec := Defaults([]string{"alice"})
	first, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	grown := Defaults([]string{"alice", "dave"})
	next, err := Regenerate(grown, first.Secrets)
	if err != nil {
		t.Fatal(err)
	}

	alice, _ := next.Secrets.user("alice")
	aliceBefore, _ := first.Secrets.user("alice")
	if !reflect.DeepEqual(alice, aliceBefore) {
		t.Error("an existing user's credentials changed when another user was added")
	}
	dave, ok := next.Secrets.user("dave")
	if !ok {
		t.Fatal("the new user got no credentials")
	}
	if dave.VLESSRealityUUID == "" || dave.MieruPassword == "" {
		t.Error("the new user is missing credentials that every user needs")
	}
	if dave.VLESSRealityUUID == alice.VLESSRealityUUID {
		t.Fatal("the new user was given the existing user's UUID")
	}
	if dave.Peers[AWG2].Address == alice.Peers[AWG2].Address {
		t.Fatal("the new peer was given an address that is already in use")
	}
}

// TestRegenerateReturnsTheSameCredentialAfterATurnOff. A protocol switched off
// and on again must come back with the credentials its clients already hold,
// not new ones — otherwise "disable for a week" quietly means "re-issue every
// config".
func TestRegenerateReturnsTheSameCredentialAfterATurnOff(t *testing.T) {
	spec := Defaults([]string{"alice"})
	first, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}

	off := Defaults([]string{"alice"})
	// Defaults leaves Enabled nil, which means "every protocol of the tier";
	// turning one off means stating the whole set.
	off.Enabled = map[Protocol]bool{}
	for _, protocol := range off.TierProtocols() {
		off.Enabled[protocol] = true
	}
	off.Enabled[Mieru] = false
	without, err := Regenerate(off, first.Secrets)
	if err != nil {
		t.Fatal(err)
	}
	for _, inbound := range without.Options.Inbounds {
		if inbound.Tag == string(Mieru) {
			t.Fatal("the disabled protocol is still in the config")
		}
	}

	back, err := Regenerate(spec, without.Secrets)
	if err != nil {
		t.Fatal(err)
	}
	aliceFirst, _ := first.Secrets.user("alice")
	aliceBack, _ := back.Secrets.user("alice")
	if aliceBack.MieruPassword != aliceFirst.MieruPassword {
		t.Error("the protocol came back with a new password, so every client config for it is stale")
	}
}

// TestRegenerateRefusesToMoveASubnetSilently. Changing a WireGuard subnet means
// every peer address in every client config is wrong; preserving the old
// addresses into a new prefix would produce an endpoint that cannot start.
func TestRegenerateRefusesToMoveASubnetSilently(t *testing.T) {
	spec := Defaults([]string{"alice"})
	first, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	moved := Defaults([]string{"alice"})
	moved.Subnets[AWG2] = netip.MustParsePrefix("10.77.0.0/24")
	if _, err := Regenerate(moved, first.Secrets); err == nil {
		t.Fatal("a subnet move was rendered silently")
	}
}

// TestRegenerateKeepsAPeerKnownOnlyByItsPublicKey. A peer the bot provisioned
// is recoverable from the live config, but the config holds only its public
// key — the private half is the client's. Minting on an empty private key
// would hand the server a new public key while the client still holds the old
// private one, which is a tunnel that handshakes with nobody.
func TestRegenerateKeepsAPeerKnownOnlyByItsPublicKey(t *testing.T) {
	spec := Defaults([]string{"alice"})
	first, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}

	// What recovery from a live config can see: the public key and address,
	// never the client's private key.
	serverView := first.Secrets
	for i := range serverView.Users {
		peers := map[Protocol]PeerSecrets{}
		for protocol, peer := range serverView.Users[i].Peers {
			peer.PrivateKey = ""
			peers[protocol] = peer
		}
		serverView.Users[i].Peers = peers
	}

	next, err := Regenerate(spec, serverView)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := first.Secrets.user("alice")
	after, _ := next.Secrets.user("alice")
	for protocol, peer := range before.Peers {
		got := after.Peers[protocol]
		if got.PublicKey != peer.PublicKey {
			t.Errorf("%s: the peer key was reissued (%s -> %s); the client's tunnel would stop handshaking",
				protocol, peer.PublicKey, got.PublicKey)
		}
		if got.Address != peer.Address {
			t.Errorf("%s: the peer address moved from %s to %s", protocol, peer.Address, got.Address)
		}
	}
}

// TestRegenerateIssuesNothingNewToARestrictedUser is the bot-user rule: a user
// named in Spec.Mint keeps what it holds and is issued only the slots listed.
// Anything else would hand the server a peer whose private half nobody stores.
func TestRegenerateIssuesNothingNewToARestrictedUser(t *testing.T) {
	spec := Defaults([]string{"alice", "bot"})
	first, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	// The bot user holds one account and one peer, as a bot that provisioned
	// only what its user asked for would leave it.
	held := first.Secrets
	for i := range held.Users {
		if held.Users[i].Name == "bot" {
			held.Users[i] = UserSecrets{
				Name:             "bot",
				VLESSRealityUUID: held.Users[i].VLESSRealityUUID,
				Peers:            map[Protocol]PeerSecrets{AWG2: held.Users[i].Peers[AWG2]},
			}
		}
	}
	spec.Mint = map[string]map[string]bool{"bot": {}}
	next, err := Regenerate(spec, held)
	if err != nil {
		t.Fatal(err)
	}
	bot, _ := next.Secrets.user("bot")
	want := map[string]bool{SlotVLESSReality: true, PeerSlot(AWG2): true}
	if !reflect.DeepEqual(bot.HeldSlots(), want) {
		t.Fatalf("restricted user holds %v, want %v", bot.HeldSlots(), want)
	}
	rendered, err := config.Marshal(context.Background(), next.Options)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(regexp.MustCompile(`"(user)?name":\s*"bot"`).FindAll(rendered, -1)); n != 2 {
		t.Fatalf("the rendered config holds %d entries for the restricted user, want its account and its peer", n)
	}
	alice, _ := next.Secrets.user("alice")
	if alice.MieruPassword == "" || len(alice.Peers) < 2 {
		t.Fatal("an unrestricted user lost credentials")
	}

	// Listed slots are issued even to a restricted user: a rotation.
	rotated := cloneUsers(held)
	for i := range rotated.Users {
		if rotated.Users[i].Name == "bot" {
			rotated.Users[i].VLESSRealityUUID = ""
			rotated.Users[i].Peers[AWG2] = PeerSecrets{Address: rotated.Users[i].Peers[AWG2].Address}
		}
	}
	spec.Mint = map[string]map[string]bool{"bot": want}
	reissued, err := Regenerate(spec, rotated)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := reissued.Secrets.user("bot")
	before, _ := held.user("bot")
	if !reflect.DeepEqual(after.HeldSlots(), want) || after.VLESSRealityUUID == before.VLESSRealityUUID ||
		after.Peers[AWG2].PublicKey == before.Peers[AWG2].PublicKey || after.Peers[AWG2].Address != before.Peers[AWG2].Address {
		t.Fatalf("rotation of a restricted user = %#v", after)
	}
}

func cloneUsers(s Secrets) Secrets {
	out := s
	out.Users = make([]UserSecrets, len(s.Users))
	for i, user := range s.Users {
		out.Users[i] = user.clone()
	}
	return out
}

func TestEveryUserGetsAnMTProtoSecretAndTheSharedOneOnlySurvives(t *testing.T) {
	spec := Defaults([]string{"alice", "bob"})
	spec.MTProtoPerUser = true
	fresh, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Secrets.MTProto.Secret != "" {
		t.Fatal("a new deployment was given a shared MTProto secret")
	}
	alice, _ := fresh.Secrets.user("alice")
	bob, _ := fresh.Secrets.user("bob")
	if alice.MTProtoSecret == "" || alice.MTProtoSecret == bob.MTProtoSecret {
		t.Fatalf("per-user secrets = %q, %q", alice.MTProtoSecret, bob.MTProtoSecret)
	}
	if domain, ok := mtprotoFrontDomain(alice.MTProtoSecret); !ok || domain != spec.MTProtoFrontDomain {
		t.Fatalf("alice's secret fronts %q", domain)
	}

	// The live config is the credential store; recovering it must give back
	// each user's own secret.
	recovered, err := SecretsFromConfig(fresh.Options)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := recovered.user("bob"); got.MTProtoSecret != bob.MTProtoSecret {
		t.Fatal("bob's MTProto secret was not recovered from the config")
	}

	// A deployment that already handed out a shared secret keeps it beside
	// the per-user ones, until it is retired.
	legacy := fresh.Secrets
	legacy.MTProto.Secret = "ee" + strings.Repeat("ab", 16) + hex.EncodeToString([]byte(spec.MTProtoFrontDomain))
	kept, err := Regenerate(spec, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if kept.Secrets.MTProto.Secret != legacy.MTProto.Secret {
		t.Fatal("an existing shared secret was dropped without being retired")
	}
	if got, _ := kept.Secrets.user("alice"); got.MTProtoSecret != alice.MTProtoSecret {
		t.Fatal("alice's secret changed on an unchanged regeneration")
	}
	spec.RetireSharedMTProto = true
	retired, err := Regenerate(spec, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if retired.Secrets.MTProto.Secret != "" {
		t.Fatal("a retired shared secret survived")
	}

	// A new front domain reissues every per-user secret: the domain is in it.
	moved := Defaults([]string{"alice", "bob"})
	moved.MTProtoPerUser = true
	moved.MTProtoFrontDomain = "www.example.org"
	reissued, err := Regenerate(moved, fresh.Secrets)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := reissued.Secrets.user("alice"); got.MTProtoSecret == alice.MTProtoSecret {
		t.Fatal("a secret for the old front domain was kept")
	} else if domain, _ := mtprotoFrontDomain(got.MTProtoSecret); domain != "www.example.org" {
		t.Fatalf("reissued secret fronts %q", domain)
	}
}

// TestWithoutPerUserMTProtoTheConfigFitsTheOlderCore: the default image's core
// does not know MTProto users, so nothing about them may reach its config.
func TestWithoutPerUserMTProtoTheConfigFitsTheOlderCore(t *testing.T) {
	bundle, err := Generate(Defaults([]string{"alice"}))
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Secrets.MTProto.Secret == "" {
		t.Fatal("the shared secret is missing")
	}
	alice, _ := bundle.Secrets.user("alice")
	if alice.MTProtoSecret != "" {
		t.Fatal("a per-user secret was issued without per-user MTProto")
	}
	rendered, err := config.Marshal(context.Background(), bundle.Options)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rendered), `"mtproto"`) && regexp.MustCompile(`"type":\s*"mtproto"[^}]*"users"`).Match(rendered) {
		t.Fatal("the mtproto inbound has users the older core rejects")
	}
}
