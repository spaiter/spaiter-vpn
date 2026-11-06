package keys

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestNewX25519DerivesTheMatchingPublicKey(t *testing.T) {
	k, err := NewX25519()
	if err != nil {
		t.Fatalf("NewX25519: %v", err)
	}

	// Re-derive independently rather than trusting the struct: the whole value
	// of the keypair is that the public key belongs to the private one.
	priv, err := ecdh.X25519().NewPrivateKey(k.Private[:])
	if err != nil {
		t.Fatalf("NewPrivateKey on the generated private key: %v", err)
	}
	if got, want := priv.PublicKey().Bytes(), k.Public[:]; string(got) != string(want) {
		t.Fatalf("public key does not match private key:\n got %x\nwant %x", got, want)
	}

	// Clamping has to be checked over a batch, not one draw: each clamped bit
	// already lands in the required state in half of all random keys, so a
	// single sample would pass on a generator that never clamps at all.
	for range 100 {
		k, err := NewX25519()
		if err != nil {
			t.Fatalf("NewX25519: %v", err)
		}
		if k.Private[0]&7 != 0 || k.Private[31]&128 != 0 || k.Private[31]&64 == 0 {
			t.Fatalf("private key is not clamped the way wg(8) writes it: %x", k.Private)
		}
	}

	// Both encodings must round-trip to the same 32 bytes, because the fork
	// decodes WireGuard keys with StdEncoding and Reality keys with
	// RawURLEncoding and a mix-up is silent until a handshake fails.
	std, err := base64.StdEncoding.DecodeString(k.PrivateStd())
	if err != nil {
		t.Fatalf("PrivateStd is not standard base64: %v", err)
	}
	url, err := base64.RawURLEncoding.DecodeString(k.PrivateURL())
	if err != nil {
		t.Fatalf("PrivateURL is not raw-url base64: %v", err)
	}
	if string(std) != string(url) || string(std) != string(k.Private[:]) {
		t.Error("the two encodings of the private key disagree")
	}
}

func TestNewX25519IsNotDeterministic(t *testing.T) {
	a, err := NewX25519()
	if err != nil {
		t.Fatalf("NewX25519: %v", err)
	}
	b, err := NewX25519()
	if err != nil {
		t.Fatalf("NewX25519: %v", err)
	}
	if a.Private == b.Private {
		t.Fatal("two calls produced the same private key")
	}
}

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestUUIDIsVersion4(t *testing.T) {
	for range 50 {
		u, err := UUID()
		if err != nil {
			t.Fatalf("UUID: %v", err)
		}
		if !uuidV4.MatchString(u) {
			t.Fatalf("not a v4 UUID: %q", u)
		}
	}
}

func TestMTProtoFakeTLSSecretCarriesTheDomain(t *testing.T) {
	const domain = "www.google.com"
	s, err := MTProtoFakeTLSSecret(domain)
	if err != nil {
		t.Fatalf("MTProtoFakeTLSSecret: %v", err)
	}
	if !strings.HasPrefix(s, "ee") {
		t.Fatalf("fake-TLS secret must start with ee: %q", s)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(s, "ee"))
	if err != nil {
		t.Fatalf("secret body is not hex: %v", err)
	}
	if len(raw) != 16+len(domain) {
		t.Fatalf("secret body is %d bytes, want 16 + %d", len(raw), len(domain))
	}
	if got := string(raw[16:]); got != domain {
		t.Fatalf("fronting domain decoded as %q, want %q", got, domain)
	}

	if _, err := MTProtoFakeTLSSecret(""); err == nil {
		t.Error("an empty fronting domain must be refused, not encoded as nothing")
	}
}

func TestClashAPISecretIs43Characters(t *testing.T) {
	// AGENTS.md documents 43 characters as the sanity check that the right
	// "secret" field was pulled out of the config, so the generator must keep
	// producing that length.
	s, err := ClashAPISecret()
	if err != nil {
		t.Fatalf("ClashAPISecret: %v", err)
	}
	if len(s) != 43 {
		t.Fatalf("clash API secret is %d characters, want 43: %q", len(s), s)
	}
}

func TestShortIDIsEvenLengthHex(t *testing.T) {
	s, err := ShortID()
	if err != nil {
		t.Fatalf("ShortID: %v", err)
	}
	if len(s)%2 != 0 {
		t.Fatalf("short_id must be even-length hex, got %q", s)
	}
	if _, err := hex.DecodeString(s); err != nil {
		t.Fatalf("short_id is not hex: %v", err)
	}
}

func TestRandomBytesRefusesNonPositiveLengths(t *testing.T) {
	for _, n := range []int{0, -1} {
		if _, err := randomBytes(n); err == nil {
			t.Errorf("randomBytes(%d) returned no error; a zero-length secret must not be silently accepted", n)
		}
	}
}

func TestBase64AndHexLengths(t *testing.T) {
	b, err := Base64(16)
	if err != nil {
		t.Fatalf("Base64: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(b)
	if err != nil {
		t.Fatalf("Base64 output is not standard base64: %v", err)
	}
	if len(raw) != 16 {
		t.Fatalf("Base64(16) decoded to %d bytes", len(raw))
	}

	h, err := Hex(16)
	if err != nil {
		t.Fatalf("Hex: %v", err)
	}
	if len(h) != 32 {
		t.Fatalf("Hex(16) is %d characters, want 32", len(h))
	}
	if _, err := strconv.ParseUint(h[:8], 16, 64); err != nil {
		t.Fatalf("Hex output is not hex: %v", err)
	}
}
