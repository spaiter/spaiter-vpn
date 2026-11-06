// Package keys generates every secret a deployment needs using only the
// standard library. A fresh VPS has neither python3 nor jq, and the install
// path must not acquire them just to mint a keypair.
package keys

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// X25519 is an x25519 keypair. WireGuard and Reality use the same curve but
// disagree on the base64 alphabet, so the raw bytes are kept and each consumer
// asks for the encoding it parses: WireGuard/AmneziaWG decode with
// base64.StdEncoding (protocol/awg/endpoint.go), Reality with
// base64.RawURLEncoding (common/tls/reality_server.go).
type X25519 struct {
	Private [32]byte
	Public  [32]byte
}

// PrivateStd and friends.
func (k X25519) PrivateStd() string { return base64.StdEncoding.EncodeToString(k.Private[:]) }
func (k X25519) PublicStd() string  { return base64.StdEncoding.EncodeToString(k.Public[:]) }
func (k X25519) PrivateURL() string { return base64.RawURLEncoding.EncodeToString(k.Private[:]) }
func (k X25519) PublicURL() string  { return base64.RawURLEncoding.EncodeToString(k.Public[:]) }

// NewX25519 mints a keypair the way `wg genkey | wg pubkey` does: 32 random
// bytes, clamped, then scalar-multiplied by the basepoint. The clamping is
// redundant for correctness — X25519 clamps at use — but it keeps the stored
// private key byte-identical to what wg(8) would have written, so a key can be
// compared against `wg show` output without surprises.
func NewX25519() (X25519, error) {
	var k X25519
	if _, err := rand.Read(k.Private[:]); err != nil {
		return X25519{}, fmt.Errorf("read random bytes: %w", err)
	}
	k.Private[0] &= 248
	k.Private[31] &= 127
	k.Private[31] |= 64

	priv, err := ecdh.X25519().NewPrivateKey(k.Private[:])
	if err != nil {
		return X25519{}, fmt.Errorf("derive x25519 key: %w", err)
	}
	copy(k.Public[:], priv.PublicKey().Bytes())
	return k, nil
}

// X25519FromPrivate recovers a keypair from a stored private key, so a public
// key can be derived from what is already in a config rather than regenerated.
//
// That is what a Reality share link needs: the inbound holds the private key
// and the client has to be told the public one. Both base64 alphabets are
// accepted and padding is optional, because the two consumers of this curve
// disagree on the encoding and a key copied from either must work.
func X25519FromPrivate(private string) (X25519, error) {
	raw, err := decodeBase64Either(private)
	if err != nil {
		return X25519{}, fmt.Errorf("decode x25519 private key: %w", err)
	}
	if len(raw) < 32 {
		return X25519{}, fmt.Errorf("x25519 private key is %d bytes, want 32", len(raw))
	}

	var k X25519
	copy(k.Private[:], raw[:32])
	priv, err := ecdh.X25519().NewPrivateKey(k.Private[:])
	if err != nil {
		return X25519{}, fmt.Errorf("derive x25519 key: %w", err)
	}
	copy(k.Public[:], priv.PublicKey().Bytes())
	return k, nil
}

// decodeBase64Either accepts the URL-safe and standard alphabets, padded or
// not.
func decodeBase64Either(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	padded := s
	if n := len(s) % 4; n != 0 {
		padded = s + strings.Repeat("=", 4-n)
	}
	for _, enc := range []*base64.Encoding{base64.URLEncoding, base64.StdEncoding} {
		if raw, err := enc.DecodeString(padded); err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("%q is not base64 in either alphabet", s)
}

// UUID returns a random RFC 4122 version 4 UUID, the form vless users take.
func UUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// Base64 returns n random bytes in padded standard base64. Shadowsocks 2022
// derives its key length from the method, so the caller picks n.
func Base64(n int) (string, error) {
	b, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// Hex returns n random bytes hex-encoded.
func Hex(n int) (string, error) {
	b, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Password returns a URL-safe secret of n random bytes, for the protocols that
// take an opaque passphrase (shadowtls, snell, mieru).
func Password(n int) (string, error) {
	b, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// MTProtoFakeTLSSecret builds an `ee` secret: the fake-TLS form mtglib parses,
// which is "ee" + 16 secret bytes + the fronting domain, all hex.
func MTProtoFakeTLSSecret(frontDomain string) (string, error) {
	if frontDomain == "" {
		return "", fmt.Errorf("mtproto fake-TLS secret needs a fronting domain")
	}
	b, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	return "ee" + hex.EncodeToString(b) + hex.EncodeToString([]byte(frontDomain)), nil
}

// ClashAPISecret returns a secret of the same shape as the live one: 32 random
// bytes in raw-url base64, which is 43 characters. AGENTS.md documents that
// length as the check that the right "secret" field was extracted, so keeping
// it stable is load-bearing for the self-test's error messages.
func ClashAPISecret() (string, error) {
	s, err := Password(32)
	if err != nil {
		return "", err
	}
	return s, nil
}

// ShortID returns a Reality short_id: an even-length hex string, here 8 bytes.
func ShortID() (string, error) {
	return Hex(8)
}

// Fingerprint is a short, non-secret identifier derived from a public key, for
// naming generated artifacts without leaking anything.
func Fingerprint(publicStd string) string {
	s := strings.NewReplacer("+", "", "/", "", "=", "").Replace(publicStd)
	if len(s) > 8 {
		s = s[:8]
	}
	return strings.ToLower(s)
}

func randomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("refusing to generate %d random bytes", n)
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return b, nil
}
