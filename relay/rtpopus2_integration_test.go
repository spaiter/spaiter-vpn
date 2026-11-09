package main

import (
	"bytes"
	"crypto/rand"
	"testing"

	"wg-turn-client/rtpopus2"
	"wg-turn-client/rtpopus3"
)

func randKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, wrapKeyLen)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// TestUnwrapAnyDetectsProfiles verifies the shim's per-packet profile auto-detect:
// a v1-masked packet and an rtpopus2-masked packet both decrypt against a
// multi-key store, and the matched key + profile are reported correctly. This is
// the core of legacy/rtpopus2 client coexistence.
func TestUnwrapAnyDetectsProfiles(t *testing.T) {
	key1, key2 := randKey(t), randKey(t)
	store := &wrapKeyStore{entries: []wrapKeyEntry{{id: "a", key: key1}, {id: "b", key: key2}}}

	payload := []byte("wireguard handshake bytes 0123456789")
	dst := make([]byte, len(payload)+64)

	// --- v1 packet wrapped with the SECOND key ---
	v1, err := obfsWrapPacket(key2, payload, NewObfsConfig("audio"), NewObfsState())
	if err != nil {
		t.Fatalf("v1 wrap: %v", err)
	}
	gotKey, m, prof, err := store.UnwrapAny(v1, dst)
	if err != nil {
		t.Fatalf("v1 UnwrapAny: %v", err)
	}
	if prof != "v1" {
		t.Errorf("v1 profile = %q, want v1", prof)
	}
	if !bytes.Equal(gotKey, key2) {
		t.Errorf("v1 selected wrong key")
	}
	if !bytes.Equal(dst[:m], payload) {
		t.Errorf("v1 plaintext mismatch: %q", dst[:m])
	}

	// --- rtpopus2 packet wrapped with the SECOND key (client direction) ---
	cli, err := rtpopus2.NewConn(key2, false)
	if err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, cli.MaxWire(len(payload)))
	wn, err := cli.WrapInto(wire, payload)
	if err != nil {
		t.Fatalf("rtpopus2 wrap: %v", err)
	}
	gotKey, m, prof, err = store.UnwrapAny(wire[:wn], dst)
	if err != nil {
		t.Fatalf("rtpopus2 UnwrapAny: %v", err)
	}
	if prof != "rtpopus2" {
		t.Errorf("rtpopus2 profile = %q, want rtpopus2", prof)
	}
	if !bytes.Equal(gotKey, key2) {
		t.Errorf("rtpopus2 selected wrong key")
	}
	if !bytes.Equal(dst[:m], payload) {
		t.Errorf("rtpopus2 plaintext mismatch: %q", dst[:m])
	}

	// --- rtpopus3 packet wrapped with the FIRST key ---
	cli3, err := rtpopus3.NewConn(key1, false)
	if err != nil {
		t.Fatal(err)
	}
	wire3 := make([]byte, cli3.MaxWire(len(payload)))
	wn3, err := cli3.WrapInto(wire3, payload)
	if err != nil {
		t.Fatalf("rtpopus3 wrap: %v", err)
	}
	gotKey, m, prof, err = store.UnwrapAny(wire3[:wn3], dst)
	if err != nil {
		t.Fatalf("rtpopus3 UnwrapAny: %v", err)
	}
	if prof != "rtpopus3" {
		t.Errorf("rtpopus3 profile = %q, want rtpopus3", prof)
	}
	if !bytes.Equal(gotKey, key1) {
		t.Errorf("rtpopus3 selected wrong key")
	}
	if !bytes.Equal(dst[:m], payload) {
		t.Errorf("rtpopus3 plaintext mismatch: %q", dst[:m])
	}

	// --- garbage packet is rejected ---
	junk := make([]byte, 64)
	_, _ = rand.Read(junk)
	junk[0] = 0x80 // pass the RTP-v2 gate but fail AEAD
	junk[1] = 111
	if _, _, _, err := store.UnwrapAny(junk, dst); err == nil {
		t.Error("expected UnwrapAny to reject random packet")
	}
}
