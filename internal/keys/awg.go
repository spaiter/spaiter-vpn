package keys

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// AWGObfuscation holds the AmneziaWG obfuscation parameters. The field names
// mirror option.AwgOptions so the profile package can copy them across without
// a translation table; the two sets are deliberately kept separate so that a
// schema change in the fork shows up as a compile error in one place.
//
// Randomising these per install matters: the whole point of the parameters is
// that the handshake does not look like WireGuard, and a shared default would
// hand every deployment the same fingerprint.
type AWGObfuscation struct {
	// AmneziaWG 2.0 core.
	Jc   int
	Jmin int
	Jmax int
	S1   int
	S2   int
	H1   string
	H2   string
	H3   string
	H4   string

	// AmneziaWG 3.x additions. Empty on a 2.0 profile.
	S3                     int
	S4                     int
	I1                     string
	I2                     string
	HeaderProtectionKey    string
	ContentPaddingAddition string
	RekeyAfterTime         string
	RekeyTimeout           string
	RejectAfterTime        string
	KeepaliveTimeout       string
	MaxHandshakeAttempts   string
	RandomTrailers         bool
}

// NewAWG2Obfuscation generates parameters for an AmneziaWG 2.0 endpoint.
//
// The constraints are the protocol's, not stylistic:
//   - H1..H4 replace the four WireGuard message types, so they must be
//     distinct and must not collide with 1..4.
//   - S1+56 != S2, otherwise the obfuscated handshake initiation and response
//     come out the same size and the padding achieves nothing.
//   - Jmin < Jmax, and Jmax stays under the 1280-byte floor every tunnel here
//     is sized against.
func NewAWG2Obfuscation() (AWGObfuscation, error) {
	o := AWGObfuscation{}

	jc, err := randInt(3, 10)
	if err != nil {
		return o, err
	}
	jmin, err := randInt(50, 500)
	if err != nil {
		return o, err
	}
	jmax, err := randInt(jmin+200, 1280)
	if err != nil {
		return o, err
	}
	s1, err := randInt(15, 150)
	if err != nil {
		return o, err
	}
	s2, err := randIntExcept(15, 150, s1+56)
	if err != nil {
		return o, err
	}
	headers, err := distinctHeaders(4)
	if err != nil {
		return o, err
	}

	o.Jc, o.Jmin, o.Jmax, o.S1, o.S2 = jc, jmin, jmax, s1, s2
	o.H1, o.H2, o.H3, o.H4 = headers[0], headers[1], headers[2], headers[3]
	return o, nil
}

// NewAWG3Obfuscation generates parameters for an AmneziaWG 3.1 endpoint. 3.1
// takes the header types as ranges rather than single values, adds two more
// junk sizes, a header-protection key, packet templates and randomised
// timings. The shape follows the live `awg3-in` endpoint.
func NewAWG3Obfuscation() (AWGObfuscation, error) {
	o, err := NewAWG2Obfuscation()
	if err != nil {
		return o, err
	}

	// Header ranges must not overlap each other, so each lands in its own
	// million-wide band and spans a random window inside it.
	bands, err := distinctInts(4, 1, 1000)
	if err != nil {
		return o, err
	}
	ranges := make([]string, 4)
	for i, band := range bands {
		base := band * 1_000_000
		width, err := randInt(100_000, 999_999)
		if err != nil {
			return o, err
		}
		ranges[i] = fmt.Sprintf("%d-%d", base, base+width)
	}
	o.H1, o.H2, o.H3, o.H4 = ranges[0], ranges[1], ranges[2], ranges[3]

	if o.S3, err = randInt(15, 150); err != nil {
		return o, err
	}
	if o.S4, err = randIntExcept(15, 150, o.S3+56); err != nil {
		return o, err
	}

	// i1/i2 are literal junk-packet templates in AmneziaWG's mini-language:
	// <b hex> emits fixed bytes, <r n> n random bytes, <rd n> random decimal
	// digits, <rc n> random alphanumerics, <t> a timestamp. These two imitate
	// a TLS 1.2 ClientHello record and an application-data record.
	pad1, err := randInt(180, 260)
	if err != nil {
		return o, err
	}
	o.I1 = fmt.Sprintf("<b 0x16030100><r %d><t>", pad1)
	o.I2 = "<b 0x170303><rd 32><rc 64>"

	if o.HeaderProtectionKey, err = Base64(32); err != nil {
		return o, err
	}

	padMax, err := randInt(32, 64)
	if err != nil {
		return o, err
	}
	o.ContentPaddingAddition = fmt.Sprintf("0-%d", padMax)

	// Timing ranges straddle the WireGuard defaults (rekey 120 s, rekey
	// timeout 5 s, reject 180 s, keepalive 10 s, 18 handshake attempts) so the
	// tunnel still behaves like WireGuard while no two installs tick alike.
	o.RekeyAfterTime = "110-140"
	o.RekeyTimeout = "5-8"
	o.RejectAfterTime = "170-200"
	o.KeepaliveTimeout = "9-13"
	o.MaxHandshakeAttempts = "16-20"
	o.RandomTrailers = true
	return o, nil
}

// distinctHeaders returns n distinct header type values. WireGuard uses 1..4,
// so the generated ones start well above that and stay inside int32.
func distinctHeaders(n int) ([]string, error) {
	values, err := distinctInts(n, 5, 2_147_483_600)
	if err != nil {
		return nil, err
	}
	out := make([]string, n)
	for i, v := range values {
		out[i] = fmt.Sprintf("%d", v)
	}
	return out, nil
}

func distinctInts(n, min, max int) ([]int, error) {
	if max-min+1 < n {
		return nil, fmt.Errorf("cannot draw %d distinct values from [%d,%d]", n, min, max)
	}
	seen := make(map[int]struct{}, n)
	out := make([]int, 0, n)
	for len(out) < n {
		v, err := randInt(min, max)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out, nil
}

// randInt returns a uniform value in [min,max], inclusive.
func randInt(min, max int) (int, error) {
	if max < min {
		return 0, fmt.Errorf("empty range [%d,%d]", min, max)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return 0, fmt.Errorf("read random int: %w", err)
	}
	return min + int(n.Int64()), nil
}

func randIntExcept(min, max, forbidden int) (int, error) {
	for {
		v, err := randInt(min, max)
		if err != nil {
			return 0, err
		}
		if v != forbidden {
			return v, nil
		}
	}
}
