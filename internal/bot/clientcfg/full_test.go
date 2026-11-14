package clientcfg

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// fullBundle is the shape the refresh loop serves: plain nodes, a two-leg
// chain written the way ShadowTLSChain writes it, and the url-test group.
const fullBundle = `{"outbounds":[
 {"type":"vless","tag":"VLESS Reality","server":"h","server_port":1},
 {"type":"tuic","tag":"TUIC v5","server":"h","server_port":2},
 {"type":"wdtt","tag":"WG-over-VK","server":"h","server_port":3},
 {"type":"chain","tag":"ShadowTLS","_chain":[
  {"type":"shadowsocks","tag":"proxy","detour":"stls","server":"h","server_port":4},
  {"type":"shadowtls","tag":"stls","server":"h","server_port":4}]},
 {"type":"urltest","tag":"🚀 Авто (лучший)","outbounds":["VLESS Reality","TUIC v5","ShadowTLS"],
  "url":"https://www.gstatic.com/generate_204","interval":"10m0s","idle_timeout":"30m0s"}
]}`

type fullDoc struct {
	DNS struct {
		Servers []map[string]any `json:"servers"`
		Final   string           `json:"final"`
	} `json:"dns"`
	Inbounds  []map[string]any `json:"inbounds"`
	Outbounds []map[string]any `json:"outbounds"`
	Route     map[string]any   `json:"route"`
}

func renderFull(t *testing.T, bundle string) fullDoc {
	t.Helper()
	data, err := Full([]byte(bundle), PlatformIOS)
	if err != nil {
		t.Fatalf("Full: %v", err)
	}
	var doc fullDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return doc
}

func outboundByTag(doc fullDoc, tag string) map[string]any {
	for _, o := range doc.Outbounds {
		if o["tag"] == tag {
			return o
		}
	}
	return nil
}

func TestFullExpandsChainsLikeTheAndroidApp(t *testing.T) {
	doc := renderFull(t, fullBundle)

	head := outboundByTag(doc, "ShadowTLS")
	if head == nil || head["type"] != "shadowsocks" {
		t.Fatalf("chain head = %v, want the first leg under the chain's tag", head)
	}
	if head["detour"] != "ShadowTLS-c0" {
		t.Errorf("head detour = %v, want ShadowTLS-c0", head["detour"])
	}
	dep := outboundByTag(doc, "ShadowTLS-c0")
	if dep == nil || dep["type"] != "shadowtls" {
		t.Fatalf("second leg = %v", dep)
	}
	for _, o := range doc.Outbounds {
		if o["type"] == "chain" || o["_chain"] != nil {
			t.Errorf("a chain node reached the config: %v", o)
		}
		if o["tag"] == "proxy" || o["tag"] == "stls" {
			t.Errorf("a leg kept its local tag %v, which collides across chains", o["tag"])
		}
	}
}

func TestFullKeepsTUICOutOfTheGroupButAsANode(t *testing.T) {
	doc := renderFull(t, fullBundle)

	group := outboundByTag(doc, AutoTag)
	if group == nil {
		t.Fatal("the url-test group is missing")
	}
	members, _ := group["outbounds"].([]any)
	if slices.Contains(members, any("TUIC v5")) {
		t.Errorf("group members = %v, TUIC must not be raced on iOS", members)
	}
	if !slices.Contains(members, any("ShadowTLS")) || !slices.Contains(members, any("VLESS Reality")) {
		t.Errorf("group members = %v, lost a raced node", members)
	}
	if outboundByTag(doc, "TUIC v5") == nil {
		t.Error("TUIC was dropped as a node; it must stay pickable by hand")
	}
	if doc.Route["final"] != AutoTag {
		t.Errorf("route.final = %v, want the group", doc.Route["final"])
	}
}

// The Android app turns on the core's ENABLE_DEPRECATED_* switches; a stock
// client does not, and the core then refuses legacy DNS servers and outbounds
// that resolve without a resolver. The config must not depend on either.
func TestFullNeedsNoDeprecatedOptions(t *testing.T) {
	doc := renderFull(t, fullBundle)

	for _, server := range doc.DNS.Servers {
		if server["type"] == nil {
			t.Errorf("DNS server %v is untyped (legacy address form)", server)
		}
		if _, ok := server["address"]; ok {
			t.Errorf("DNS server %v uses the legacy address field", server)
		}
	}
	resolver, _ := doc.Route["default_domain_resolver"].(string)
	if resolver == "" {
		t.Fatal("route.default_domain_resolver is unset")
	}
	found := false
	for _, server := range doc.DNS.Servers {
		if server["tag"] == resolver {
			found = true
		}
	}
	if !found {
		t.Errorf("default_domain_resolver %q names no DNS server", resolver)
	}
	if doc.DNS.Final == resolver {
		t.Errorf("dns.final is the local resolver: queries would leave outside the tunnel")
	}
}

func TestFullHasATunAndADirectExit(t *testing.T) {
	doc := renderFull(t, fullBundle)

	if len(doc.Inbounds) != 1 || doc.Inbounds[0]["type"] != "tun" {
		t.Fatalf("inbounds = %v, want one tun", doc.Inbounds)
	}
	if mtu, _ := doc.Inbounds[0]["mtu"].(float64); mtu != fullTunMTU {
		t.Errorf("tun mtu = %v, want %d", doc.Inbounds[0]["mtu"], fullTunMTU)
	}
	if direct := outboundByTag(doc, fullDirectTag); direct == nil || direct["type"] != "direct" {
		t.Errorf("no direct outbound for private addresses: %v", direct)
	}
}

func TestFullWithoutAGroupRoutesToTheFirstNode(t *testing.T) {
	doc := renderFull(t, `{"outbounds":[{"type":"vless","tag":"A"},{"type":"hysteria2","tag":"B"}]}`)
	if doc.Route["final"] != "A" {
		t.Errorf("route.final = %v, want the first node", doc.Route["final"])
	}
}

func TestFullDropsAGroupWithOnlyTUIC(t *testing.T) {
	doc := renderFull(t, `{"outbounds":[{"type":"tuic","tag":"T"},
	 {"type":"urltest","tag":"`+AutoTag+`","outbounds":["T"]}]}`)
	if outboundByTag(doc, AutoTag) != nil {
		t.Error("an empty group reached the config; the core refuses it")
	}
	if doc.Route["final"] != "T" {
		t.Errorf("route.final = %v, want the only node", doc.Route["final"])
	}
}

func TestFullRefusesWhatItCannotRender(t *testing.T) {
	for name, tc := range map[string]struct {
		bundle, platform, want string
	}{
		"unknown platform": {fullBundle, "android", "unknown platform"},
		"not json":         {"{", PlatformIOS, "parse bundle"},
		"no nodes":         {`{"outbounds":[]}`, PlatformIOS, "no nodes"},
		"untagged node":    {`{"outbounds":[{"type":"vless"}]}`, PlatformIOS, "no tag"},
		"reserved tag":     {`{"outbounds":[{"type":"vless","tag":"direct"}]}`, PlatformIOS, "reserved"},
		"empty chain":      {`{"outbounds":[{"type":"chain","tag":"C","_chain":[]}]}`, PlatformIOS, "no legs"},
		"bad leg":          {`{"outbounds":[{"type":"chain","tag":"C","_chain":[1]}]}`, PlatformIOS, "not an object"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Full([]byte(tc.bundle), tc.platform)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestFullPlatformKnown(t *testing.T) {
	if !FullPlatformKnown(PlatformIOS) || FullPlatformKnown("android") || FullPlatformKnown("") {
		t.Error("FullPlatformKnown disagrees with what Full renders")
	}
}
