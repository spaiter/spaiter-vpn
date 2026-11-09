package clientcfg

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/keys"
)

// liveShape is the key set of a node the running deployment actually serves,
// captured from a real subscription. Names only, no values: the point is that
// the Go node has the same fields, and an extra or missing one is what makes a
// client reject the configuration.
type liveShape struct {
	Type string      `json:"type"`
	Keys []string    `json:"keys"`
	Legs []liveShape `json:"legs,omitempty"`
}

func loadShapes(t *testing.T) map[string]liveShape {
	t.Helper()
	data, err := os.ReadFile("testdata/live-node-shapes.json")
	if err != nil {
		t.Fatalf("read shapes: %v", err)
	}
	var shapes map[string]liveShape
	if err := json.Unmarshal(data, &shapes); err != nil {
		t.Fatalf("parse shapes: %v", err)
	}
	return shapes
}

func assertKeys(t *testing.T, label string, node Node, want []string) {
	t.Helper()
	got := make([]string, 0, len(node))
	for key := range node {
		got = append(got, key)
	}
	slices.Sort(got)
	wantSorted := slices.Clone(want)
	slices.Sort(wantSorted)

	for _, key := range wantSorted {
		if !slices.Contains(got, key) {
			t.Errorf("%s is missing %q; the running deployment serves it", label, key)
		}
	}
	for _, key := range got {
		if !slices.Contains(wantSorted, key) {
			t.Errorf("%s has extra %q; an unknown key makes the client reject the config", label, key)
		}
	}
}

// testEndpoint is an AmneziaWG endpoint with the obfuscation parameters the
// live awg3-in carries, so the flat-vs-nested distinction is exercised.
func testEndpoint(t *testing.T) Endpoint {
	t.Helper()
	pair, err := keys.NewX25519()
	if err != nil {
		t.Fatalf("NewX25519: %v", err)
	}
	return Endpoint{
		Tag: "awg3-in", PrivateKey: pair.PrivateStd(), ListenPort: 10860, MTU: 1200,
		AWG: map[string]any{
			"jc": float64(4), "jmin": float64(40), "jmax": float64(70),
			"s1": float64(0), // zero: must not be emitted
			"h1": float64(1), "h2": float64(2),
			"header_protection_key": "a-key",
			"random_trailers":       true,
			"disable_cookies":       false, // false: must not be emitted
			"i1":                    "<b 0x16030100>",
		},
	}
}

func testPeer() state.Peer {
	return state.Peer{Priv: "client-priv", Pub: "client-pub", IP: "10.40.0.3"}
}

// TestAWGNodeMatchesWhatIsServed checks the node against the live shape and,
// more importantly, that the obfuscation parameters sit FLAT on the outbound.
// The server endpoint nests them under "awg" and the client rejects that form,
// so this is the difference that decides whether the node works at all.
func TestAWGNodeMatchesWhatIsServed(t *testing.T) {
	ep := testEndpoint(t)
	node, err := AWGNode(ep, testPeer(), "AmneziaWG 3.1", "wgvk.example.org")
	if err != nil {
		t.Fatalf("AWGNode: %v", err)
	}

	if _, nested := node["awg"]; nested {
		t.Error("the obfuscation parameters are nested under awg; the client reads them flat")
	}
	for _, key := range []string{"jc", "jmin", "jmax", "h1", "h2", "header_protection_key", "random_trailers", "i1"} {
		if _, ok := node[key]; !ok {
			t.Errorf("%s is missing from the outbound", key)
		}
	}
	// A zero or false parameter is absent rather than present-and-empty: the
	// server did not set it, and sending it would change behaviour.
	for _, key := range []string{"s1", "disable_cookies"} {
		if _, ok := node[key]; ok {
			t.Errorf("%s is zero on the endpoint but was emitted", key)
		}
	}

	peers, ok := node["peers"].([]any)
	if !ok || len(peers) != 1 {
		t.Fatalf("peers = %v", node["peers"])
	}
	peer := peers[0].(map[string]any)
	// A name, not a literal address: the public IPv4 of this line rotates, and
	// a baked literal breaks the tunnel and spams a config change every time.
	if peer["address"] != "wgvk.example.org" {
		t.Errorf("peer address = %v, want the name it was given", peer["address"])
	}
	if peer["port"] != ep.ListenPort {
		t.Errorf("peer port = %v, want %d", peer["port"], ep.ListenPort)
	}
	pair, _ := keys.X25519FromPrivate(ep.PrivateKey)
	if peer["public_key"] != pair.PublicStd() {
		t.Error("peer public_key is not the endpoint's public half")
	}

	shapes := loadShapes(t)
	live, ok := shapes["awg"]
	if !ok {
		t.Fatal("no live awg shape captured")
	}
	// The live node carries whichever parameters that endpoint had set, so
	// compare only the structural keys, not the obfuscation ones.
	structural := []string{"type", "tag", "private_key", "address", "mtu", "peers"}
	for _, key := range structural {
		if !slices.Contains(live.Keys, key) {
			t.Errorf("captured shape lacks %q; the fixture may be stale", key)
		}
		if _, ok := node[key]; !ok {
			t.Errorf("node lacks %q, which the deployment serves", key)
		}
	}
}

func TestMASQUEWGNodeMatchesWhatIsServed(t *testing.T) {
	cfg := bot.ExampleConfig()
	ep := Endpoint{Tag: "wg-masque-in", PrivateKey: mustKey(t), ListenPort: 10877, MTU: 1280}

	node, err := MASQUEWGNode(cfg, ep, testPeer(), 10876, "/m")
	if err != nil {
		t.Fatalf("MASQUEWGNode: %v", err)
	}
	assertKeys(t, "masque-wg", node, loadShapes(t)["masque-wg"].Keys)

	// Its own endpoint has no obfuscation: oversized junk does not fit the
	// small QUIC datagrams a mobile MTU allows.
	for _, key := range awgOutboundKeys {
		if _, ok := node[key]; ok {
			t.Errorf("masque-wg carries %q; its endpoint is deliberately plain", key)
		}
	}
	if node["server_port"] != uint16(10876) {
		t.Errorf("server_port = %v, want the tunnel's own port", node["server_port"])
	}
}

func TestWDTTNodeMatchesWhatIsServed(t *testing.T) {
	cfg := bot.ExampleConfig()
	cfg.WDTT.ServerHost = "wgvk.example.org"

	node := WDTTNode(cfg, "pw", []string{"h1", "h2"})
	assertKeys(t, "wdtt", node, loadShapes(t)["wdtt"].Keys)

	if node["server"] != "wgvk.example.org" {
		t.Errorf("server = %v, want the A-only name", node["server"])
	}
	// The field has to be an array even when empty: nil renders as null and
	// the client expects a list.
	empty := WDTTNode(cfg, "pw", nil)
	data, err := json.Marshal(empty["vk_hashes"])
	if err != nil || string(data) != "[]" {
		t.Errorf("vk_hashes with an empty pool = %s (%v), want []", data, err)
	}
}

func TestWDTTWorkersScaleWithThePool(t *testing.T) {
	cfg := bot.ExampleConfig() // 9 per hash, cap 108, auto
	for _, tc := range []struct {
		hashes int
		want   int
	}{
		{0, 9},    // floored at one set: zero workers would mean no tunnel
		{1, 9},    //
		{4, 36},   //
		{11, 99},  //
		{20, 108}, // capped
	} {
		if got := WDTTWorkers(cfg, tc.hashes); got != tc.want {
			t.Errorf("%d hashes -> %d workers, want %d", tc.hashes, got, tc.want)
		}
	}

	fixed := bot.ExampleConfig()
	fixed.WDTT.Workers = 50
	if got := WDTTWorkers(fixed, 1); got != 50 {
		t.Errorf("a pinned count was ignored: %d", got)
	}
	fixed.WDTT.Workers = 500
	if got := WDTTWorkers(fixed, 1); got != 108 {
		t.Errorf("a pinned count above the cap = %d, want the cap", got)
	}
}

func TestChainsMatchWhatIsServed(t *testing.T) {
	cfg := bot.ExampleConfig()
	f := loadFixture(t)
	shapes := loadShapes(t)

	t.Run("shadowtls", func(t *testing.T) {
		in := inboundByTag(t, f, "shadowtls-in")
		backend := inboundByTag(t, f, "ss-stls-in")
		chain := ShadowTLSChain(cfg, in, backend, oracleUser(), "ShadowTLS")

		live := shapes["ShadowTLS"]
		if len(chain.Legs) != len(live.Legs) {
			t.Fatalf("%d legs, the deployment serves %d", len(chain.Legs), len(live.Legs))
		}
		for i, leg := range chain.Legs {
			if leg["type"] != live.Legs[i].Type {
				t.Errorf("leg %d is %v, want %s", i, leg["type"], live.Legs[i].Type)
			}
			assertKeys(t, "shadowtls leg "+live.Legs[i].Type, leg, live.Legs[i].Keys)
		}
		// The visible leg detours through the hidden one; without that they are
		// two unrelated outbounds and nothing is hidden.
		if chain.Legs[0]["detour"] != "stls" {
			t.Error("the shadowsocks leg does not detour through shadowtls")
		}
	})

	t.Run("warp", func(t *testing.T) {
		inner := inboundByTag(t, f, "vless-reality-in")
		account := state.WARPAccount(`{"private_key":"k","ipv4":"172.16.0.2"}`)
		chain, err := WARPChain(cfg, inner, oracleUser(), account, "WARP → сервер")
		if err != nil {
			t.Fatalf("WARPChain: %v", err)
		}

		live := shapes["WARP → сервер"]
		if len(chain.Legs) != len(live.Legs) {
			t.Fatalf("%d legs, the deployment serves %d", len(chain.Legs), len(live.Legs))
		}
		for i, leg := range chain.Legs {
			assertKeys(t, "warp leg "+live.Legs[i].Type, leg, live.Legs[i].Keys)
		}

		// The MASQUE leg takes a nested tls{sni}, not the flat server_name and
		// port the server core reads. Emitting the flat form is what made every
		// shipped client reject the whole subscription on 2026-10-31.
		warp := chain.Legs[1]
		tls, ok := warp["tls"].(map[string]any)
		if !ok {
			t.Fatalf("warp leg tls = %v, want a nested object", warp["tls"])
		}
		if tls["sni"] != cfg.WARP.SNI {
			t.Errorf("sni = %v, want %q", tls["sni"], cfg.WARP.SNI)
		}
		for _, forbidden := range []string{"server_name", "port", "fragment"} {
			if _, present := warp[forbidden]; present {
				t.Errorf("the warp leg carries top-level %q, which no client core knows", forbidden)
			}
		}
		if _, hasConfig := warp["config"]; !hasConfig {
			t.Error("no baked account: a client behind a whitelist cannot register one")
		}
	})
}

func TestWireGuardConfRendersBooleansAsOnOff(t *testing.T) {
	ep := testEndpoint(t)
	conf, err := WireGuardConf(ep, testPeer(), "wgvk.example.org", "")
	if err != nil {
		t.Fatalf("WireGuardConf: %v", err)
	}

	// awg-tools' parser takes only on/off; a literal "true" makes the official
	// Amnezia client reject the whole file.
	if strings.Contains(conf, "= true") || strings.Contains(conf, "= false") {
		t.Errorf("a boolean was rendered as a literal:\n%s", conf)
	}
	if !strings.Contains(conf, "RandomTrailers = on") {
		t.Error("RandomTrailers should be on")
	}
	// A parameter the server did not set must be absent, not off.
	if strings.Contains(conf, "DisableCookies") {
		t.Error("DisableCookies is unset on the endpoint but appears in the file")
	}

	for _, want := range []string{
		"[Interface]", "PrivateKey = client-priv", "Address = 10.40.0.3/32",
		"DNS = 1.1.1.1", "MTU = 1200",
		"[Peer]", "AllowedIPs = 0.0.0.0/0, ::/0",
		"Endpoint = wgvk.example.org:10860", "PersistentKeepalive = 25",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q from:\n%s", want, conf)
		}
	}
	// Numbers come back from JSON as float64 and must not be rendered that
	// way. Checked per line rather than by substring: AllowedIPs and Address
	// legitimately contain dotted quads.
	floaty := regexp.MustCompile(`^(J|S|H|I|Content|Rekey|Reject|Keepalive|Max|MTU)\S* = \d+\.\d+$`)
	for _, line := range strings.Split(conf, "\n") {
		if floaty.MatchString(strings.TrimSpace(line)) {
			t.Errorf("a parameter was rendered as a float: %q", line)
		}
	}
}

func mustKey(t *testing.T) string {
	t.Helper()
	pair, err := keys.NewX25519()
	if err != nil {
		t.Fatalf("NewX25519: %v", err)
	}
	return pair.PrivateStd()
}
