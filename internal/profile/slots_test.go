package profile

import (
	"testing"
)

func TestPeerSlot(t *testing.T) {
	tests := []struct {
		protocol Protocol
		want     string
	}{
		{VLESSReality, "peer:vless-reality-in"},
		{Hysteria2, "peer:" + string(Hysteria2)},
		{Protocol("custom"), "peer:custom"},
	}
	for _, tt := range tests {
		if got := PeerSlot(tt.protocol); got != tt.want {
			t.Fatalf("PeerSlot(%q) = %q, want %q", tt.protocol, got, tt.want)
		}
	}
}

func TestCredentialSlots(t *testing.T) {
	// All 11 slots must be present even when empty.
	empty := UserSecrets{}
	got := empty.CredentialSlots()
	wantSlots := []string{
		SlotVLESSReality, SlotVLESSWSCDN, SlotShadowTLS, SlotSnell, SlotMieru,
		SlotHysteria2, SlotTUIC, SlotAnyTLS, SlotNaive, SlotVLESSXHTTP, SlotMTProto,
	}
	if len(got) != len(wantSlots) {
		t.Fatalf("CredentialSlots on empty UserSecrets: got %d slots, want %d", len(got), len(wantSlots))
	}
	for _, slot := range wantSlots {
		if _, ok := got[slot]; !ok {
			t.Fatalf("CredentialSlots on empty UserSecrets: missing slot %q", slot)
		}
		if got[slot] != "" {
			t.Fatalf("CredentialSlots on empty UserSecrets: slot %q = %q, want empty", slot, got[slot])
		}
	}

	// TUIC: both halves filled → UUID + "\x00" + password.
	u := UserSecrets{
		TUICUUID:     "uuid-1",
		TUICPassword: "pass-1",
	}
	if got := u.CredentialSlots()[SlotTUIC]; got != "uuid-1\x00pass-1" {
		t.Fatalf("CredentialSlots TUIC both halves: got %q, want %q", got, "uuid-1\x00pass-1")
	}

	// TUIC: only UUID filled → still non-empty.
	u = UserSecrets{TUICUUID: "uuid-only"}
	if got := u.CredentialSlots()[SlotTUIC]; got == "" {
		t.Fatalf("CredentialSlots TUIC uuid-only: got empty, want non-empty")
	}

	// TUIC: only password filled → still non-empty.
	u = UserSecrets{TUICPassword: "pass-only"}
	if got := u.CredentialSlots()[SlotTUIC]; got == "" {
		t.Fatalf("CredentialSlots TUIC password-only: got empty, want non-empty")
	}

	// A single non-TUIC credential appears under its slot.
	u = UserSecrets{ShadowTLSPassword: "stls-pass"}
	if got := u.CredentialSlots()[SlotShadowTLS]; got != "stls-pass" {
		t.Fatalf("CredentialSlots ShadowTLS: got %q, want %q", got, "stls-pass")
	}
}

func TestHeldSlots(t *testing.T) {
	// Empty user: no slots held.
	empty := UserSecrets{}
	if got := empty.HeldSlots(); len(got) != 0 {
		t.Fatalf("HeldSlots on empty UserSecrets: got %d slots, want 0", len(got))
	}

	// Only non-empty credentials are held; empty ones are not.
	u := UserSecrets{
		VLESSRealityUUID:  "uuid-a",
		ShadowTLSPassword: "",
	}
	held := u.HeldSlots()
	if !held[SlotVLESSReality] {
		t.Fatalf("HeldSlots: expected %q to be held", SlotVLESSReality)
	}
	if held[SlotShadowTLS] {
		t.Fatalf("HeldSlots: %q should not be held (empty value)", SlotShadowTLS)
	}

	// Peers: each protocol in Peers yields peer:<protocol>, even with zero-value PeerSecrets.
	u = UserSecrets{
		Peers: map[Protocol]PeerSecrets{
			VLESSReality: {},
			Hysteria2:    {},
		},
	}
	held = u.HeldSlots()
	for _, p := range []Protocol{VLESSReality, Hysteria2} {
		slot := PeerSlot(p)
		if !held[slot] {
			t.Fatalf("HeldSlots: expected %q to be held for peer", slot)
		}
	}
}

func TestMayMint(t *testing.T) {
	// User absent from Mint: allowed everywhere.
	spec := Spec{Mint: map[string]map[string]bool{}}
	if !spec.mayMint("alice", SlotVLESSReality) {
		t.Fatalf("mayMint: user absent from Mint should be allowed, got false")
	}

	// Nil Mint: allowed everywhere.
	spec = Spec{}
	if !spec.mayMint("alice", SlotTUIC) {
		t.Fatalf("mayMint: nil Mint should allow all, got false")
	}

	// User present in Mint with restricted=true: only listed slots allowed.
	spec = Spec{Mint: map[string]map[string]bool{
		"bob": {SlotVLESSReality: true},
	}}
	if !spec.mayMint("bob", SlotVLESSReality) {
		t.Fatalf("mayMint: bob should be allowed %q", SlotVLESSReality)
	}
	if spec.mayMint("bob", SlotTUIC) {
		t.Fatalf("mayMint: bob should NOT be allowed %q", SlotTUIC)
	}

	// An empty, non-nil entry still restricts: the user may mint nothing.
	spec = Spec{Mint: map[string]map[string]bool{
		"carol": {},
	}}
	if spec.mayMint("carol", SlotTUIC) {
		t.Fatalf("mayMint: carol has an empty allow-list, should be denied %q", SlotTUIC)
	}
	// Restrictions are per user: dave is unlisted and stays unrestricted.
	if !spec.mayMint("dave", SlotTUIC) {
		t.Fatalf("mayMint: unlisted dave should be allowed %q", SlotTUIC)
	}
}
