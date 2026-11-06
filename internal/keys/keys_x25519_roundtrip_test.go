package keys

import "testing"

// TestX25519FromPrivateMatchesGeneration is the property a Reality link
// depends on: the public key derived from a stored private key must be the one
// generation produced, or clients are handed a pbk the server will not match.
func TestX25519FromPrivateMatchesGeneration(t *testing.T) {
	k, err := NewX25519()
	if err != nil {
		t.Fatalf("NewX25519: %v", err)
	}
	// Both alphabets, padded and not: a key may have been copied from either
	// consumer of this curve.
	for name, stored := range map[string]string{
		"std":          k.PrivateStd(),
		"url unpadded": k.PrivateURL(),
		"url padded":   k.PrivateURL() + "=",
	} {
		got, err := X25519FromPrivate(stored)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got.PublicStd() != k.PublicStd() {
			t.Errorf("%s: public = %s, want %s", name, got.PublicStd(), k.PublicStd())
		}
		if got.PrivateStd() != k.PrivateStd() {
			t.Errorf("%s: private round trip changed the key", name)
		}
	}

	for _, bad := range []string{"", "not base64 at all !!", "c2hvcnQ="} {
		if _, err := X25519FromPrivate(bad); err == nil {
			t.Errorf("%q was accepted as a private key", bad)
		}
	}
}
