package keys

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

type brokenRand struct{}

func (brokenRand) Read([]byte) (int, error) { return 0, errors.New("entropy source is gone") }

// failRandom replaces the system's random source for the length of the test.
func failRandom(t *testing.T) {
	t.Helper()
	old := rand.Reader
	rand.Reader = brokenRand{}
	t.Cleanup(func() { rand.Reader = old })
}

// crypto/rand.Read cannot be made to fail on current Go (it stops the process
// instead of returning an error), so the byte generators' error branches are
// not reachable from a test. rand.Int reads the replaceable Reader and does
// return the error, which is what the AmneziaWG parameter generators depend on.
func TestObfuscationParametersRefuseWithoutRandomness(t *testing.T) {
	failRandom(t)
	if _, err := NewAWG2Obfuscation(); err == nil {
		t.Error("AWG 2.0 parameters were produced without randomness")
	}
	if _, err := NewAWG3Obfuscation(); err == nil {
		t.Error("AWG 3.1 parameters were produced without randomness")
	}
	if _, err := randInt(1, 5); err == nil || !strings.Contains(err.Error(), "random int") {
		t.Errorf("randInt: %v", err)
	}
	if _, err := randIntExcept(1, 5, 3); err == nil {
		t.Error("randIntExcept succeeded without randomness")
	}
	if _, err := distinctInts(3, 1, 100); err == nil {
		t.Error("distinctInts succeeded without randomness")
	}
}

func TestRandomnessHelpersRefuseNonsense(t *testing.T) {
	for _, n := range []int{0, -3} {
		if _, err := Base64(n); err == nil {
			t.Errorf("Base64(%d) succeeded", n)
		}
	}
	if _, err := MTProtoFakeTLSSecret(""); err == nil {
		t.Error("an empty fronting domain was accepted")
	}
	if _, err := randInt(5, 1); err == nil || !strings.Contains(err.Error(), "empty range") {
		t.Errorf("empty range: %v", err)
	}
	// randIntExcept never returns the forbidden value.
	for i := 0; i < 200; i++ {
		if v, err := randIntExcept(1, 3, 2); err != nil || v == 2 {
			t.Fatalf("v=%d err=%v", v, err)
		}
	}
}

func TestPublicURLAndFingerprintMatchTheirDefinitions(t *testing.T) {
	k, err := NewX25519()
	if err != nil {
		t.Fatal(err)
	}
	if got := k.PublicURL(); strings.ContainsAny(got, "+/=") || len(got) != 43 {
		t.Errorf("PublicURL = %q, want 43 raw-url characters", got)
	}
	if got := Fingerprint("AB+/cd=EFGHIJKLMN"); got != "abcdefgh" {
		t.Errorf("Fingerprint = %q", got)
	}
	if got := Fingerprint("A+B"); got != "ab" {
		t.Errorf("short fingerprint = %q", got)
	}
}
