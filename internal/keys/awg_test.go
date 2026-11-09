package keys

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

func TestAWG2ObfuscationRespectsTheProtocolConstraints(t *testing.T) {
	// Run a batch: every constraint here is a randomised draw, so a single
	// sample proves nothing about the generator.
	for i := range 200 {
		o, err := NewAWG2Obfuscation()
		if err != nil {
			t.Fatalf("NewAWG2Obfuscation: %v", err)
		}

		if o.Jc < 1 || o.Jc > 128 {
			t.Fatalf("draw %d: jc=%d outside 1..128", i, o.Jc)
		}
		if o.Jmin >= o.Jmax {
			t.Fatalf("draw %d: jmin=%d must be below jmax=%d", i, o.Jmin, o.Jmax)
		}
		if o.Jmax > 1280 {
			t.Fatalf("draw %d: jmax=%d exceeds 1280", i, o.Jmax)
		}
		if o.S1+56 == o.S2 {
			t.Fatalf("draw %d: s1+56 == s2 (%d), which makes initiation and response the same size", i, o.S2)
		}

		headers := []string{o.H1, o.H2, o.H3, o.H4}
		seen := map[string]struct{}{}
		for _, h := range headers {
			v, err := strconv.Atoi(h)
			if err != nil {
				t.Fatalf("draw %d: header %q is not an integer", i, h)
			}
			if v < 5 {
				t.Fatalf("draw %d: header %d collides with a WireGuard message type", i, v)
			}
			if _, dup := seen[h]; dup {
				t.Fatalf("draw %d: duplicate header %s in %v", i, h, headers)
			}
			seen[h] = struct{}{}
		}
	}
}

func TestAWG3ObfuscationUsesDisjointHeaderRanges(t *testing.T) {
	for i := range 200 {
		o, err := NewAWG3Obfuscation()
		if err != nil {
			t.Fatalf("NewAWG3Obfuscation: %v", err)
		}

		type span struct{ lo, hi int }
		var spans []span
		for _, r := range []string{o.H1, o.H2, o.H3, o.H4} {
			lo, hi, ok := parseRange(r)
			if !ok {
				t.Fatalf("draw %d: header %q is not an \"a-b\" range", i, r)
			}
			if lo >= hi {
				t.Fatalf("draw %d: header range %q is empty or inverted", i, r)
			}
			if lo < 5 {
				t.Fatalf("draw %d: header range %q reaches into the WireGuard message types", i, r)
			}
			spans = append(spans, span{lo, hi})
		}
		for a := range spans {
			for b := a + 1; b < len(spans); b++ {
				if spans[a].lo <= spans[b].hi && spans[b].lo <= spans[a].hi {
					t.Fatalf("draw %d: header ranges %v and %v overlap", i, spans[a], spans[b])
				}
			}
		}

		if o.S3+56 == o.S4 {
			t.Fatalf("draw %d: s3+56 == s4 (%d)", i, o.S4)
		}

		key, err := base64.StdEncoding.DecodeString(o.HeaderProtectionKey)
		if err != nil {
			t.Fatalf("draw %d: header_protection_key is not standard base64: %v", i, err)
		}
		if len(key) != 32 {
			t.Fatalf("draw %d: header_protection_key is %d bytes, want 32", i, len(key))
		}

		if !strings.HasPrefix(o.I1, "<b 0x16030100><r ") || !strings.HasSuffix(o.I1, "><t>") {
			t.Fatalf("draw %d: i1 template was mangled: %q", i, o.I1)
		}
		if !o.RandomTrailers {
			t.Fatalf("draw %d: random_trailers must be on for a 3.x profile", i)
		}
		for name, r := range map[string]string{
			"content_padding_addition": o.ContentPaddingAddition,
			"rekey_after_time":         o.RekeyAfterTime,
			"rekey_timeout":            o.RekeyTimeout,
			"reject_after_time":        o.RejectAfterTime,
			"keepalive_timeout":        o.KeepaliveTimeout,
			"max_handshake_attempts":   o.MaxHandshakeAttempts,
		} {
			if lo, hi, ok := parseRange(r); !ok || lo > hi {
				t.Fatalf("draw %d: %s=%q is not a valid range", i, name, r)
			}
		}
	}
}

func TestAWG2AndAWG3DifferInShape(t *testing.T) {
	// A 2.0 endpoint must not carry 3.x fields: the fork gates the 3.x UAPI on
	// their presence, so leaking them would silently change the wire format
	// for clients that only speak 2.0.
	o, err := NewAWG2Obfuscation()
	if err != nil {
		t.Fatalf("NewAWG2Obfuscation: %v", err)
	}
	if o.S3 != 0 || o.S4 != 0 || o.I1 != "" || o.HeaderProtectionKey != "" ||
		o.ContentPaddingAddition != "" || o.RandomTrailers {
		t.Fatalf("2.0 profile carries 3.x fields: %+v", o)
	}
}

func TestDistinctIntsRefusesImpossibleDraws(t *testing.T) {
	if _, err := distinctInts(5, 1, 3); err == nil {
		t.Error("drawing 5 distinct values from a range of 3 must fail, not loop forever")
	}
}

func parseRange(s string) (lo, hi int, ok bool) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	lo, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	hi, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}
	return lo, hi, true
}
