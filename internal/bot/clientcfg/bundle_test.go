package clientcfg

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bot"
)

func TestAssembleAddsTheAutoGroup(t *testing.T) {
	cfg := bot.ExampleConfig()
	nodes := []any{
		Node{"type": "vless", "tag": "VLESS Reality"},
		Node{"type": "awg", "tag": "AmneziaWG"},
		Chain{Type: "chain", Tag: "WARP → сервер"},
	}

	bundle := Assemble(cfg, nodes)
	if len(bundle.Outbounds) != len(nodes)+1 {
		t.Fatalf("%d outbounds, want the nodes plus the group", len(bundle.Outbounds))
	}
	group, ok := bundle.Outbounds[len(bundle.Outbounds)-1].(map[string]any)
	if !ok || group["type"] != "urltest" {
		t.Fatalf("last outbound = %v, want the url-test group", bundle.Outbounds[len(bundle.Outbounds)-1])
	}
	if group["tag"] != AutoTag {
		t.Errorf("group tag = %v", group["tag"])
	}

	raced, ok := group["outbounds"].([]string)
	if !ok {
		t.Fatalf("group members = %T", group["outbounds"])
	}
	// WARP is excluded by default: it cannot win a 15-second probe, and
	// including it hangs the race instead, leaving the group spinning rather
	// than settling on a method that works.
	if slices.Contains(raced, "WARP → сервер") {
		t.Error("the WARP chain is in the race; it can only hang it")
	}
	for _, want := range []string{"VLESS Reality", "AmneziaWG"} {
		if !slices.Contains(raced, want) {
			t.Errorf("%s is missing from the race", want)
		}
	}
	// Excluded, but still offered: that is how someone reaches for it when the
	// fast methods are blocked.
	if tagOf(t, bundle, "WARP → сервер") == nil {
		t.Error("the excluded node was dropped from the bundle entirely")
	}
}

func TestAssembleWithNothingToOffer(t *testing.T) {
	bundle := Assemble(bot.ExampleConfig(), nil)
	if len(bundle.Outbounds) != 0 {
		t.Errorf("outbounds = %v, want none", bundle.Outbounds)
	}
	// And it still renders as an array rather than null, or a client sees a
	// malformed subscription instead of an empty one.
	data, err := bundle.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(data) != "{\n  \"outbounds\": []\n}" {
		t.Errorf("rendered = %s", data)
	}
}

func TestAssembleWithEverythingExcluded(t *testing.T) {
	cfg := bot.ExampleConfig()
	cfg.Bundle.AutoExcludeTags = []string{"only"}
	bundle := Assemble(cfg, []any{Node{"type": "wdtt", "tag": "only"}})

	// No group at all rather than an empty one: a url-test over nothing is a
	// node that can never answer.
	for _, out := range bundle.Outbounds {
		if node, ok := out.(map[string]any); ok && node["type"] == "urltest" {
			t.Error("an empty url-test group was added")
		}
	}
	if len(bundle.Outbounds) != 1 {
		t.Errorf("outbounds = %v", bundle.Outbounds)
	}
}

// TestStructuralHashIgnoresPoolRotation is the property that keeps six people
// from being told their configuration changed several times a day. The VK pool
// rotates hourly and the worker count moves with its size; both are refreshed
// in the served config regardless, and neither is something a user can act on.
func TestStructuralHashIgnoresPoolRotation(t *testing.T) {
	cfg := bot.ExampleConfig()

	build := func(hashes []string) []byte {
		t.Helper()
		bundle := Assemble(cfg, []any{
			Node{"type": "vless", "tag": "VLESS Reality", "server_port": 10861},
			WDTTNode(cfg, "pw", hashes),
		})
		data, err := bundle.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		return data
	}

	four := build([]string{"a", "b", "c", "d"})
	one := build([]string{"z"})

	hashFour, err := StructuralHash(four)
	if err != nil {
		t.Fatalf("StructuralHash: %v", err)
	}
	hashOne, err := StructuralHash(one)
	if err != nil {
		t.Fatalf("StructuralHash: %v", err)
	}
	if hashFour != hashOne {
		t.Error("the pool rotating changed the structural hash; every subscriber would be nudged")
	}

	// A real change does move it.
	changed := Assemble(cfg, []any{
		Node{"type": "vless", "tag": "VLESS Reality", "server_port": 20000},
		WDTTNode(cfg, "pw", []string{"a"}),
	})
	data, err := changed.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	hashChanged, err := StructuralHash(data)
	if err != nil {
		t.Fatalf("StructuralHash: %v", err)
	}
	if hashChanged == hashFour {
		t.Error("a changed port did not move the hash; nobody would be told to re-import")
	}

	// A changed password must move it too: that is a credential the user has
	// to pick up.
	other := Assemble(cfg, []any{WDTTNode(cfg, "different-pw", []string{"a"})})
	otherData, _ := other.Marshal()
	otherHash, err := StructuralHash(otherData)
	if err != nil {
		t.Fatalf("StructuralHash: %v", err)
	}
	if otherHash == hashFour {
		t.Error("a changed password did not move the hash")
	}
}

// TestStructuralHashIgnoresNodeOrder: the bundle is built by walking maps, and
// the order nodes happen to come out in is not a change anyone can act on.
func TestStructuralHashIgnoresKeyOrder(t *testing.T) {
	a := []byte(`{"outbounds":[{"type":"vless","tag":"x","server":"h"}]}`)
	b := []byte(`{"outbounds":[{"server":"h","tag":"x","type":"vless"}]}`)

	hashA, err := StructuralHash(a)
	if err != nil {
		t.Fatalf("StructuralHash: %v", err)
	}
	hashB, err := StructuralHash(b)
	if err != nil {
		t.Fatalf("StructuralHash: %v", err)
	}
	if hashA != hashB {
		t.Error("key order changed the hash")
	}
}

func TestStructuralHashRejectsNonsense(t *testing.T) {
	if _, err := StructuralHash([]byte(`not json`)); err == nil {
		t.Error("a malformed bundle was hashed")
	}
}

func TestNodeLabelFallsBackThroughTheConfig(t *testing.T) {
	cfg := bot.ExampleConfig()

	if got := NodeLabel(cfg, Inbound{Tag: "awg-in", Type: "awg"}); got != "AmneziaWG" {
		t.Errorf("tagged label = %q", got)
	}
	// No per-tag label: the protocol's name is better than a bare tag.
	if got := NodeLabel(cfg, Inbound{Tag: "unknown-in", Type: "vless"}); got != "VLESS" {
		t.Errorf("protocol label = %q", got)
	}
	// Neither: the type, which at least says what it is.
	if got := NodeLabel(cfg, Inbound{Tag: "x", Type: "brand-new"}); got != "brand-new" {
		t.Errorf("fallback label = %q", got)
	}
}

func tagOf(t *testing.T, b Bundle, tag string) any {
	t.Helper()
	for _, out := range b.Outbounds {
		if nodeTag(out) == tag {
			return out
		}
	}
	return nil
}

// TestBundleRendersChainsWithTheirLegs keeps the chain's shape: the client
// expands _chain into one outbound per leg, so losing it loses the node.
func TestBundleRendersChainsWithTheirLegs(t *testing.T) {
	bundle := Assemble(bot.ExampleConfig(), []any{
		Chain{Type: "chain", Tag: "ShadowTLS", Legs: []Node{
			{"type": "shadowsocks", "tag": "proxy", "detour": "stls"},
			{"type": "shadowtls", "tag": "stls"},
		}},
	})
	data, err := bundle.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var parsed struct {
		Outbounds []map[string]json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	legs, ok := parsed.Outbounds[0]["_chain"]
	if !ok {
		t.Fatal("the chain lost its legs")
	}
	var decoded []map[string]any
	if err := json.Unmarshal(legs, &decoded); err != nil || len(decoded) != 2 {
		t.Fatalf("legs = %s (%v)", legs, err)
	}
	if decoded[0]["detour"] != "stls" {
		t.Error("the detour between the legs was lost")
	}
}
