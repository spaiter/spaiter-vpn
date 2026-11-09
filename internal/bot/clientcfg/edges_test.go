package clientcfg

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/keys"
)

func realityInbound(t *testing.T) Inbound {
	t.Helper()
	pair, err := keys.NewX25519()
	if err != nil {
		t.Fatal(err)
	}
	return Inbound{
		Type: "vless", Tag: "vless-in", ListenPort: 443,
		TLS: &TLS{Enabled: true, ServerName: "example.com", Reality: &Reality{Enabled: true, PrivateKey: pair.PrivateStd(), ShortID: StringOrList{"ab"}}},
	}
}

func TestParsersRefuseWhatIsNotJSONAndAcceptTheCapitalisedUserForm(t *testing.T) {
	if _, err := ParseInbound(json.RawMessage(`"x"`)); err == nil {
		t.Error("an inbound that is a string")
	}
	if _, err := ParseUser(json.RawMessage(`[1]`)); err == nil {
		t.Error("a user that is an array")
	}
	if _, err := ParseEndpoint(json.RawMessage(`"x"`)); err == nil {
		t.Error("an endpoint that is a string")
	}
	if ep, err := ParseEndpoint(json.RawMessage(`{"tag":"awg-in","listen_port":1}`)); err != nil || ep.Tag != "awg-in" {
		t.Errorf("endpoint = %+v, %v", ep, err)
	}
	// A core that writes Go-style field names.
	user, err := ParseUser(json.RawMessage(`{"Username":"bob","Password":"pw"}`))
	if err != nil || user.Username != "bob" || user.Password != "pw" {
		t.Errorf("capitalised user = %+v, %v", user, err)
	}
	// An account with neither name field still parses, and stays nameless.
	if user, err = ParseUser(json.RawMessage(`{}`)); err != nil || user.Name != "" || user.Username != "" {
		t.Errorf("nameless user = %+v, %v", user, err)
	}
}

func TestAccessorsTolerateMissingBlocks(t *testing.T) {
	var in Inbound
	if in.ServerName() != "" || in.TransportPath() != "" || in.TransportType() != "" {
		t.Error("empty inbound reported values")
	}
}

func TestBadRealityKeysAreNamedAtEveryRenderer(t *testing.T) {
	cfg := bot.ExampleConfig()
	in := realityInbound(t)
	in.TLS.Reality.PrivateKey = "not-a-key"
	user := User{Name: "u", UUID: "uuid"}

	if _, err := BundleNode(cfg, in, user, "node"); err == nil || !strings.Contains(err.Error(), "reality public key") {
		t.Errorf("BundleNode: %v", err)
	}
	if _, err := Link(cfg, in, user); err == nil || !strings.Contains(err.Error(), "reality public key") {
		t.Errorf("Link: %v", err)
	}
	if _, err := WARPChain(cfg, in, user, state.WARPAccount(`{}`), "warp"); err == nil {
		t.Error("WARPChain accepted a bad inner key")
	}

	in.Tag = "vless-xhttp-in"
	in.TLS.Reality.PrivateKey = ""
	if _, err := JSONConfig(cfg, JSONConfigInput{Inbound: in, User: user}); err == nil || !strings.Contains(err.Error(), "no private key") {
		t.Errorf("JSONConfig without a key: %v", err)
	}
	in.TLS.Reality.PrivateKey = "not-a-key"
	if _, err := JSONConfig(cfg, JSONConfigInput{Inbound: in, User: user}); err == nil || !strings.Contains(err.Error(), "reality public key") {
		t.Errorf("JSONConfig with a bad key: %v", err)
	}
	if _, err := JSONConfig(cfg, JSONConfigInput{Inbound: Inbound{Type: "trojan"}, User: user}); err == nil || !strings.Contains(err.Error(), "no config-file form") {
		t.Errorf("JSONConfig for an unsupported type: %v", err)
	}
}

func TestDefaultsFillWhatTheCoreLeavesOut(t *testing.T) {
	cfg := bot.ExampleConfig()
	user := User{Name: "u", UUID: "uuid", Password: "pw", Flow: "xtls-rprx-vision"}

	// A CDN-fronted inbound with no transport still gets ws and "/".
	cdn := Inbound{Type: "vless", Tag: "cdn-in", ListenPort: 443}
	cfg.Public.CDN = map[string]bot.CDNFront{"cdn-in": {Host: "edge.example.com", SNI: "edge.example.com", Port: 443}}
	node, err := BundleNode(cfg, cdn, user, "cdn")
	if err != nil || node["transport"].(map[string]any)["type"] != "ws" || node["transport"].(map[string]any)["path"] != "/" {
		t.Errorf("cdn node = %v, %v", node, err)
	}
	link, err := Link(cfg, cdn, user)
	if err != nil || !strings.Contains(link, "type=ws") || !strings.Contains(link, "path=%2F") {
		t.Errorf("cdn link = %q, %v", link, err)
	}
	cfg.Public.CDN = nil

	// tuic without a congestion setting uses bbr.
	tuic := Inbound{Type: "tuic", Tag: "tuic-in", ListenPort: 1, TLS: &TLS{Enabled: true, ServerName: "x"}}
	if node, _ := BundleNode(cfg, tuic, user, "t"); node["congestion_control"] != "bbr" {
		t.Errorf("tuic node = %v", node)
	}
	if link, _ := Link(cfg, tuic, user); !strings.Contains(link, "congestion_control=bbr") {
		t.Errorf("tuic link = %q", link)
	}

	// snell: the server's mode and version are mirrored, with 6 as the default.
	snell := Inbound{Type: "snell", Tag: "snell-in", ListenPort: 2, PSK: "p", Mode: "quiet"}
	node, _ = BundleNode(cfg, snell, user, "s")
	if node["mode"] != "quiet" || node["version"] != 6 {
		t.Errorf("snell node = %v", node)
	}
	snell.Version = 5
	if node, _ = BundleNode(cfg, snell, user, "s"); node["version"] != 5 {
		t.Errorf("snell version = %v", node["version"])
	}
	out, err := JSONConfig(cfg, JSONConfigInput{Inbound: snell, User: user})
	if err != nil || !strings.Contains(string(out), `"mode": "quiet"`) {
		t.Errorf("snell json = %s, %v", out, err)
	}

	// vless: flow, plain TLS, xhttp with a host, and no transport at all on plain TCP.
	in := realityInbound(t)
	in.Transport = &Transport{Type: "xhttp", Path: "/x", Host: StringOrList{"h.example"}, XPaddingBytes: "10-20"}
	node, err = BundleNode(cfg, in, user, "v")
	if err != nil || node["flow"] != "xtls-rprx-vision" || node["transport"].(map[string]any)["host"] != "h.example" {
		t.Errorf("vless node = %v, %v", node, err)
	}
	plain := Inbound{Type: "vless", Tag: "p", ListenPort: 1, TLS: &TLS{Enabled: true, ServerName: "x"}}
	link, _ = Link(cfg, plain, user)
	if !strings.Contains(link, "security=tls") || !strings.Contains(link, "type=tcp") || !strings.Contains(link, "flow=") {
		t.Errorf("plain tls link = %q", link)
	}
	if node, _ := BundleNode(cfg, plain, user, "p"); node["transport"] != nil {
		t.Errorf("plain tcp got a transport: %v", node)
	}

	// The XHTTP JSON form falls back to "/" for a missing path.
	xhttp := realityInbound(t)
	xhttp.Tag = "vless-xhttp-in"
	xhttp.Transport = &Transport{Type: "xhttp"}
	out, err = JSONConfig(cfg, JSONConfigInput{Inbound: xhttp, User: user})
	if err != nil || !strings.Contains(string(out), `"path": "/"`) {
		t.Errorf("xhttp json = %s, %v", out, err)
	}
}

func TestWireGuardFamilyNodesFillDefaultsAndRefuseBadKeys(t *testing.T) {
	cfg := bot.ExampleConfig()
	pair, _ := keys.NewX25519()
	peer := state.Peer{Priv: "priv", Pub: "pub", IP: "10.0.0.2"}
	ep := Endpoint{Tag: "awg-in", Type: "awg", PrivateKey: pair.PrivateStd(), ListenPort: 10860,
		AWG: map[string]any{"jc": float64(5), "s1": float64(0), "enabled": true, "i1": "", "list": []any{}, "other": struct{}{}}}

	node, err := AWGNode(ep, peer, "AWG", "host.example")
	if err != nil || node["mtu"] != uint32(1200) || node["jc"] != float64(5) {
		t.Errorf("awg node = %v, %v", node, err)
	}
	if _, ok := node["s1"]; ok {
		t.Error("a zero obfuscation parameter was emitted")
	}
	masque, err := MASQUEWGNode(cfg, ep, peer, 0, "")
	if err != nil || masque["mtu"] != uint32(1200) {
		t.Errorf("masque node = %v, %v", masque, err)
	}
	conf, err := WireGuardConf(ep, peer, "host.example", "")
	if err != nil || !strings.Contains(conf, "DNS = 1.1.1.1") || !strings.Contains(conf, "MTU = 1200") || !strings.Contains(conf, "Jc = 5") {
		t.Errorf("conf = %q, %v", conf, err)
	}

	bad := ep
	bad.PrivateKey = "not-a-key"
	if _, err := bad.ServerPublicKey(); err == nil {
		t.Error("ServerPublicKey accepted a bad key")
	}
	if _, err := AWGNode(bad, peer, "AWG", "h"); err == nil {
		t.Error("AWGNode accepted a bad key")
	}
	if _, err := MASQUEWGNode(cfg, bad, peer, 1, "/m"); err == nil {
		t.Error("MASQUEWGNode accepted a bad key")
	}
	if _, err := WireGuardConf(bad, peer, "h", "9.9.9.9"); err == nil {
		t.Error("WireGuardConf accepted a bad key")
	}
}

func TestSmallRenderingHelpers(t *testing.T) {
	if clamp(1, 3, 10) != 3 || clamp(99, 3, 10) != 10 || clamp(5, 3, 0) != 5 {
		t.Error("clamp")
	}
	cfg := bot.ExampleConfig()
	cfg.WDTT.ServerHost, cfg.Public.IPv4Host, cfg.Public.Host = "", "", "dual.example"
	if wdttHost(cfg) != "dual.example" {
		t.Error("wdttHost falls back to the public host")
	}
	cfg.Public.IPv4Host = "v4.example"
	if wdttHost(cfg) != "v4.example" {
		t.Error("wdttHost prefers the IPv4-only name")
	}
	cfg.WDTT.ServerHost = "relay.example"
	if wdttHost(cfg) != "relay.example" {
		t.Error("wdttHost prefers the configured relay host")
	}
	for _, c := range []struct {
		in   any
		want string
	}{{true, "on"}, {false, "off"}, {"s", "s"}, {float64(7), "7"}, {[]any{1}, "[1]"}} {
		if confValue(c.in) != c.want {
			t.Errorf("confValue(%v) = %q, want %q", c.in, confValue(c.in), c.want)
		}
	}
	for _, c := range []struct {
		in   any
		want bool
	}{{nil, true}, {false, true}, {true, false}, {"", true}, {"x", false}, {float64(0), true}, {float64(1), false}, {[]any{}, true}, {[]any{1}, false}, {3, false}} {
		if isZero(c.in) != c.want {
			t.Errorf("isZero(%v) = %v, want %v", c.in, isZero(c.in), c.want)
		}
	}
	if nodeTag(Node{"tag": "a"}) != "a" || nodeTag(map[string]any{"tag": "b"}) != "b" || nodeTag(42) != "" {
		t.Error("nodeTag")
	}
	if _, err := StructuralHash([]byte("{")); err == nil {
		t.Error("garbage hashed")
	}
}

func TestWARPChainFillsThePathAndCarriesTheAccountVerbatim(t *testing.T) {
	cfg := bot.ExampleConfig()
	inner := realityInbound(t)
	inner.Transport = &Transport{Type: "xhttp"}
	chain, err := WARPChain(cfg, inner, User{UUID: "u"}, state.WARPAccount(`{"private_key":"k"}`), "WARP")
	if err != nil {
		t.Fatal(err)
	}
	transport := chain.Legs[0]["transport"].(map[string]any)
	if transport["path"] != "/" {
		t.Errorf("transport = %v", transport)
	}
	if string(chain.Legs[1]["config"].(json.RawMessage)) != `{"private_key":"k"}` {
		t.Errorf("account was altered: %v", chain.Legs[1])
	}
}
