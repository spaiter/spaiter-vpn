package option

import (
	"context"
	"testing"
)

func TestAwgFlatToNestedMigration(t *testing.T) {
	ctx := context.Background()

	// Legacy flat schema (params at top level).
	flat := `{"private_key":"aGVsbG8=","address":["10.0.0.1/24"],"listen_port":10863,"jc":4,"jmin":8,"s1":15,"h1":"1234567890","i1":"abcd"}`
	var o AwgEndpointOptions
	if err := o.UnmarshalJSONContext(ctx, []byte(flat)); err != nil {
		t.Fatal(err)
	}
	if o.Awg.Jc != 4 || o.Awg.Jmin != 8 || o.Awg.S1 != 15 || o.Awg.H1 != "1234567890" || o.Awg.I1 != "abcd" {
		t.Fatalf("flat params not folded into Awg: %+v", o.Awg)
	}
	if o.ListenPort != 10863 {
		t.Fatalf("listen_port lost: %d", o.ListenPort)
	}

	// Nested schema keeps working.
	nested := `{"private_key":"aGVsbG8=","address":["10.0.0.1/24"],"awg":{"jc":7,"s2":20}}`
	var o2 AwgEndpointOptions
	if err := o2.UnmarshalJSONContext(ctx, []byte(nested)); err != nil {
		t.Fatal(err)
	}
	if o2.Awg.Jc != 7 || o2.Awg.S2 != 20 {
		t.Fatalf("nested schema broken: %+v", o2.Awg)
	}

	// When both present, nested wins (no accidental override from legacy flat).
	both := `{"private_key":"aGVsbG8=","address":["10.0.0.1/24"],"jc":1,"awg":{"jc":9}}`
	var o3 AwgEndpointOptions
	if err := o3.UnmarshalJSONContext(ctx, []byte(both)); err != nil {
		t.Fatal(err)
	}
	if o3.Awg.Jc != 9 {
		t.Fatalf("nested should take precedence, got Jc=%d", o3.Awg.Jc)
	}

	// Minimal prod-style config (no obfuscation) stays empty, no error.
	minimal := `{"tag":"awg-in","private_key":"aGVsbG8=","address":["10.0.0.1/24"],"listen_port":10863,"mtu":1280}`
	var o4 AwgEndpointOptions
	if err := o4.UnmarshalJSONContext(ctx, []byte(minimal)); err != nil {
		t.Fatal(err)
	}
	if o4.Awg.IsAvailble() {
		t.Fatalf("minimal config should have empty Awg, got %+v", o4.Awg)
	}
}

func TestAwg3Options(t *testing.T) {
	ctx := context.Background()

	nested := `{"private_key":"aGVsbG8=","address":["10.0.0.1/24"],"awg":{"s1":16,"s2":16,"s3":16,"s4":16,` +
		`"header_protection_key":"SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvIQ==","content_padding_addition":"0-32",` +
		`"rekey_after_time":"100-140","max_handshake_attempts":"3-6","random_trailers":true,"disable_cookies":true}}`
	var o AwgEndpointOptions
	if err := o.UnmarshalJSONContext(ctx, []byte(nested)); err != nil {
		t.Fatal(err)
	}
	if o.Awg.ContentPaddingAddition != "0-32" || o.Awg.RekeyAfterTime != "100-140" ||
		o.Awg.MaxHandshakeAttempts != "3-6" || !o.Awg.RandomTrailers || !o.Awg.DisableCookies {
		t.Fatalf("awg3 params not parsed: %+v", o.Awg)
	}

	// A config carrying only AWG 3.x params must still register as "available",
	// otherwise the flat->nested fallback would clobber it. //H awg3
	flat := `{"private_key":"aGVsbG8=","address":["10.0.0.1/24"],"header_protection_key":"SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvIQ=="}`
	var o2 AwgEndpointOptions
	if err := o2.UnmarshalJSONContext(ctx, []byte(flat)); err != nil {
		t.Fatal(err)
	}
	if !o2.Awg.IsAvailble() || o2.Awg.HeaderProtectionKey == "" {
		t.Fatalf("awg3-only flat config not folded: %+v", o2.Awg)
	}
}
