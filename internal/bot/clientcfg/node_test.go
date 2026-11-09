package clientcfg

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bot"
)

// oracle is what bot.py produced for the same fixture, see testdata/README.md.
type oracle struct {
	Nodes   map[string]json.RawMessage `json:"nodes"`
	Configs map[string]json.RawMessage `json:"configs"`
}

func loadOracle(t *testing.T) oracle {
	t.Helper()
	data, err := os.ReadFile("testdata/python-nodes.json")
	if err != nil {
		t.Fatalf("read oracle: %v", err)
	}
	var o oracle
	if err := json.Unmarshal(data, &o); err != nil {
		t.Fatalf("parse oracle: %v", err)
	}
	return o
}

// oracleUser is the user the oracle was generated with. It carries every
// credential shape at once, because one dump has to serve inbounds that key
// their users differently.
func oracleUser() User {
	return User{
		Name:     "user1",
		Username: "user1",
		UUID:     "00000000-0000-4000-8000-000000000001",
		Password: "pw-password-1",
		UserKey:  "pw-userkey-1",
	}
}

// TestBundleNodesMatchThePythonBot compares structures rather than bytes.
//
// Byte equality is not the requirement here and chasing it would be false
// precision: the structural hash the refresh loop stores is computed with
// sorted keys, so key order cannot change it, and the spacing of the rendered
// JSON differs between the two languages for no semantic reason. What has to
// match is the content -- a missing field is a node that will not decode, and
// an extra one is a config the client rejects outright.
func TestBundleNodesMatchThePythonBot(t *testing.T) {
	cfg := bot.ExampleConfig()
	f := loadFixture(t)
	o := loadOracle(t)

	compared := 0
	for _, raw := range f.Inbounds {
		in, err := ParseInbound(raw)
		if err != nil {
			t.Fatalf("parse inbound: %v", err)
		}
		expectedRaw, ok := o.Nodes[in.Tag]
		if !ok {
			t.Errorf("no oracle node for %s", in.Tag)
			continue
		}

		label := cfg.UI.TagLabel[in.Tag]
		if label == "" {
			label = in.Tag
		}
		got, err := BundleNode(cfg, in, oracleUser(), label)
		if err != nil {
			t.Errorf("%s: %v", in.Tag, err)
			continue
		}

		// The oracle stores null for an inbound with no bundle node. Checked
		// before decoding, because unmarshalling null into a map succeeds and
		// yields a nil map rather than an error.
		if string(expectedRaw) == "null" {
			if got != nil {
				t.Errorf("%s: produced a node where the Python produced none: %v", in.Tag, got)
			}
			compared++
			continue
		}
		var want map[string]any
		if err := json.Unmarshal(expectedRaw, &want); err != nil {
			t.Errorf("%s: oracle entry does not parse: %v", in.Tag, err)
			continue
		}
		if got == nil {
			t.Errorf("%s: produced no node, the Python produced one", in.Tag)
			continue
		}
		assertSameJSON(t, in.Tag, got, want)
		compared++
	}
	if compared != len(o.Nodes) {
		t.Errorf("compared %d nodes, oracle has %d", compared, len(o.Nodes))
	}
}

// TestJSONConfigsMatchThePythonBot covers the config-file protocols,
// including the two that exist only because their shape cannot be a URI.
func TestJSONConfigsMatchThePythonBot(t *testing.T) {
	cfg := bot.ExampleConfig()
	f := loadFixture(t)
	o := loadOracle(t)

	byTag := map[string]Inbound{}
	for _, raw := range f.Inbounds {
		in, err := ParseInbound(raw)
		if err != nil {
			t.Fatalf("parse inbound: %v", err)
		}
		byTag[in.Tag] = in
	}
	backend := byTag["ss-stls-in"]

	for tag, expectedRaw := range o.Configs {
		in, ok := byTag[tag]
		if !ok {
			t.Errorf("oracle has a config for %s, the fixture has no such inbound", tag)
			continue
		}
		input := JSONConfigInput{Inbound: in, User: oracleUser()}
		if in.Type == "shadowtls" {
			input.Backend = &backend
		}

		data, err := JSONConfig(cfg, input)
		if err != nil {
			t.Errorf("%s: %v", tag, err)
			continue
		}
		var got, want map[string]any
		if err := json.Unmarshal(data, &got); err != nil {
			t.Errorf("%s: own output does not parse: %v", tag, err)
			continue
		}
		if err := json.Unmarshal(expectedRaw, &want); err != nil {
			t.Errorf("%s: oracle does not parse: %v", tag, err)
			continue
		}
		assertSameJSON(t, tag, got, want)
	}
	if len(o.Configs) != len(bot.JSONTags()) {
		t.Errorf("oracle covers %d config-file protocols, JSONTags lists %d",
			len(o.Configs), len(bot.JSONTags()))
	}
}

// TestShadowTLSNeedsItsBackend: the pair's visible leg is shadowsocks and its
// credentials live in another inbound. Generating the config without them
// would produce something that connects and then fails to authenticate.
func TestShadowTLSNeedsItsBackend(t *testing.T) {
	cfg := bot.ExampleConfig()
	in := inboundByTag(t, loadFixture(t), "shadowtls-in")

	if _, err := JSONConfig(cfg, JSONConfigInput{Inbound: in, User: oracleUser()}); err == nil {
		t.Fatal("a shadowtls config was produced with no backend")
	}
}

// TestNaiveConfigIsNotSingBox records the exception: what comes back is a
// naiveproxy client config, and feeding it to a sing-box validator would be a
// category error rather than a finding.
func TestNaiveConfigIsNotSingBox(t *testing.T) {
	cfg := bot.ExampleConfig()
	in := inboundByTag(t, loadFixture(t), "naive-in")

	data, err := JSONConfig(cfg, JSONConfigInput{Inbound: in, User: oracleUser()})
	if err != nil {
		t.Fatalf("JSONConfig: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, hasOutbounds := parsed["outbounds"]; hasOutbounds {
		t.Error("the naive config looks like sing-box; it is read by naiveproxy")
	}
	if parsed["listen"] != "socks://127.0.0.1:1080" {
		t.Errorf("listen = %v", parsed["listen"])
	}
}

// TestVlessNodeOmitsTransportForPlainTCP keeps a config that a client already
// imported from changing shape for no reason.
func TestVlessNodeOmitsTransportForPlainTCP(t *testing.T) {
	cfg := bot.ExampleConfig()
	in := Inbound{
		Type: "vless", Tag: "plain", ListenPort: 443,
		TLS: &TLS{Enabled: true, ServerName: "example.org"},
	}
	node, err := BundleNode(cfg, in, oracleUser(), "Plain")
	if err != nil {
		t.Fatalf("BundleNode: %v", err)
	}
	if _, has := node["transport"]; has {
		t.Error("plain TCP got a transport block")
	}

	in.Transport = &Transport{Type: "tcp"}
	node, err = BundleNode(cfg, in, oracleUser(), "Plain")
	if err != nil {
		t.Fatalf("BundleNode: %v", err)
	}
	if _, has := node["transport"]; has {
		t.Error("an explicit tcp transport still got a transport block")
	}
}

// TestUnofferedTypesProduceNoNode is the boundary: a type with no client
// outbound must be skipped rather than guessed at.
func TestUnofferedTypesProduceNoNode(t *testing.T) {
	cfg := bot.ExampleConfig()
	for _, kind := range []string{"trojan", "vmess", "hysteria", "shadowtls", "shadowsocks", "mtproto"} {
		node, err := BundleNode(cfg, Inbound{Type: kind, Tag: kind + "-in"}, oracleUser(), kind)
		if err != nil {
			t.Errorf("%s: %v", kind, err)
		}
		if node != nil {
			t.Errorf("%s produced a bundle node: %v", kind, node)
		}
	}
}

// assertSameJSON compares two decoded objects and reports the first difference
// by path, which is far more useful than a dump of both.
func assertSameJSON(t *testing.T, label string, got, want map[string]any) {
	t.Helper()
	diffJSON(t, label, normalise(got), normalise(want))
}

func diffJSON(t *testing.T, path string, got, want any) {
	t.Helper()
	switch wantVal := want.(type) {
	case map[string]any:
		gotMap, ok := got.(map[string]any)
		if !ok {
			t.Errorf("%s: got %T, want an object", path, got)
			return
		}
		for key, wantChild := range wantVal {
			gotChild, present := gotMap[key]
			if !present {
				t.Errorf("%s.%s is missing; the Python emits %v", path, key, wantChild)
				continue
			}
			diffJSON(t, path+"."+key, gotChild, wantChild)
		}
		for key, gotChild := range gotMap {
			if _, present := wantVal[key]; !present {
				t.Errorf("%s.%s = %v is extra; an unknown key makes the client reject the config",
					path, key, gotChild)
			}
		}
	case []any:
		gotSlice, ok := got.([]any)
		if !ok {
			t.Errorf("%s: got %T, want an array", path, got)
			return
		}
		if len(gotSlice) != len(wantVal) {
			t.Errorf("%s: %d elements, want %d", path, len(gotSlice), len(wantVal))
			return
		}
		for i := range wantVal {
			diffJSON(t, path+"["+itoa(i)+"]", gotSlice[i], wantVal[i])
		}
	default:
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v, want %#v", path, got, want)
		}
	}
}

// normalise rounds numeric types together: a port is float64 after a JSON
// round trip and uint16 when freshly built, and that difference is noise.
func normalise(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, child := range val {
			out[k] = normalise(child)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, child := range val {
			out[i] = normalise(child)
		}
		return out
	case Node:
		return normalise(map[string]any(val))
	case StringOrList:
		out := make([]any, len(val))
		for i, s := range val {
			out[i] = s
		}
		return out
	case []string:
		out := make([]any, len(val))
		for i, s := range val {
			out[i] = s
		}
		return out
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case uint16:
		return float64(val)
	case json.Number:
		f, _ := val.Float64()
		return f
	default:
		return v
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}
