package clientcfg

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bot"
)

// fixture is the live deployment's inbounds with every credential replaced.
// Real shapes matter here: the fields a link is built from are exactly the ones
// that differ between protocols, and inventing them would test the invention.
type fixture struct {
	Inbounds  []json.RawMessage `json:"inbounds"`
	Endpoints []json.RawMessage `json:"endpoints"`
}

func loadFixture(t *testing.T) fixture {
	t.Helper()
	data, err := os.ReadFile("testdata/inbounds.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f fixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return f
}

func inboundByTag(t *testing.T, f fixture, tag string) Inbound {
	t.Helper()
	for _, raw := range f.Inbounds {
		in, err := ParseInbound(raw)
		if err != nil {
			t.Fatalf("parse inbound: %v", err)
		}
		if in.Tag == tag {
			return in
		}
	}
	t.Fatalf("fixture has no inbound tagged %s", tag)
	return Inbound{}
}

func testUser() User {
	return User{
		Name:     "user1",
		UUID:     "00000000-0000-4000-8000-000000000001",
		Password: "pw-password-1",
	}
}

// TestLinkForEveryFixtureInbound walks the real inbound set and checks each
// link is either absent for a good reason or parses into the right protocol.
// It is the breadth test: a protocol added to the deployment shows up here.
func TestLinkForEveryFixtureInbound(t *testing.T) {
	cfg := bot.ExampleConfig()
	f := loadFixture(t)

	// Protocols with no clean URI. shadowsocks is absent from the picker
	// entirely -- it exists only as the ShadowTLS detour backend.
	noLink := map[string]bool{
		"shadowtls-in": true, "naive-in": true, "mieru-in": true,
		"snell-in": true, "ss-stls-in": true, "masque-wg-in": true,
	}
	wantScheme := map[string]string{
		"vless-reality-in":    "vless",
		"vless-xhttp-in":      "vless",
		"vless-xhttp-obfs-in": "vless",
		"vless-ws-cdn-in":     "vless",
		"hysteria-in":         "hysteria2",
		"tuic-in":             "tuic",
		"anytls-in":           "anytls",
		"mtproto-in":          "tg",
	}

	seen := map[string]bool{}
	for _, raw := range f.Inbounds {
		in, err := ParseInbound(raw)
		if err != nil {
			t.Fatalf("parse inbound: %v", err)
		}
		link, err := Link(cfg, in, testUser())
		if err != nil {
			t.Errorf("%s: %v", in.Tag, err)
			continue
		}
		seen[in.Tag] = true

		if noLink[in.Tag] {
			if link != "" {
				t.Errorf("%s produced a link (%q) but is delivered as a config file", in.Tag, link)
			}
			continue
		}
		want, known := wantScheme[in.Tag]
		if !known {
			t.Errorf("%s is neither in the no-link set nor expected to produce one; "+
				"a new protocol needs a decision here", in.Tag)
			continue
		}
		if link == "" {
			t.Errorf("%s produced no link", in.Tag)
			continue
		}
		u, err := url.Parse(link)
		if err != nil {
			t.Errorf("%s: link does not parse: %v", in.Tag, err)
			continue
		}
		if u.Scheme != want {
			t.Errorf("%s: scheme %q, want %q", in.Tag, u.Scheme, want)
		}
	}
	for tag := range wantScheme {
		if !seen[tag] {
			t.Errorf("fixture is missing %s; the test would silently stop covering it", tag)
		}
	}
}

// TestRealityLinkCarriesWhatTheHandshakeNeeds is the link users actually get
// most often, and every one of these parameters is load-bearing.
func TestRealityLinkCarriesWhatTheHandshakeNeeds(t *testing.T) {
	cfg := bot.ExampleConfig()
	in := inboundByTag(t, loadFixture(t), "vless-reality-in")

	link, err := Link(cfg, in, testUser())
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.User.Username() != testUser().UUID {
		t.Errorf("uuid = %q", u.User.Username())
	}
	if u.Host != "vpn.example.com:10861" {
		t.Errorf("host = %q, want the public host and the inbound's port", u.Host)
	}
	q := u.Query()
	for key, want := range map[string]string{
		"encryption": "none",
		"security":   "reality",
		"fp":         "chrome",
		"sid":        "0123456789abcdef",
		"sni":        in.ServerName(),
	} {
		if got := q.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	// pbk has to be the public half of the inbound's own private key: a client
	// handed anything else fails the handshake with no useful error.
	if pbk := q.Get("pbk"); pbk == "" {
		t.Error("no pbk: a Reality client cannot connect without it")
	} else if pbk == in.TLS.Reality.PrivateKey {
		t.Error("pbk is the private key, not the public one")
	}
	if frag := u.Fragment; frag != "user1" {
		t.Errorf("fragment = %q, want the user name", frag)
	}
}

// TestXHTTPLinkKeepsItsPath is the regression that shipped: the path lived
// under the http branch, so the xhttp inbound's /xh never reached the client
// and the only route to that inbound produced an unusable link.
func TestXHTTPLinkKeepsItsPath(t *testing.T) {
	cfg := bot.ExampleConfig()
	f := loadFixture(t)

	for _, tag := range []string{"vless-xhttp-in", "vless-xhttp-obfs-in"} {
		in := inboundByTag(t, f, tag)
		if in.TransportPath() == "" {
			t.Fatalf("%s: fixture has no transport path to test with", tag)
		}
		link, err := Link(cfg, in, testUser())
		if err != nil {
			t.Fatalf("%s: %v", tag, err)
		}
		u, _ := url.Parse(link)
		if got := u.Query().Get("path"); got != in.TransportPath() {
			t.Errorf("%s: path = %q, want %q", tag, got, in.TransportPath())
		}
	}
}

// TestCDNLinkPointsAtTheEdge: a CDN-fronted inbound is reached at the edge
// with the edge's SNI, not at the host. Getting this wrong sends the client
// straight at an origin that is blocked by IP, which is the whole point of
// having the front.
func TestCDNLinkPointsAtTheEdge(t *testing.T) {
	cfg := bot.ExampleConfig()
	in := inboundByTag(t, loadFixture(t), "vless-ws-cdn-in")

	link, err := Link(cfg, in, testUser())
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	u, _ := url.Parse(link)
	front := cfg.Public.CDN["vless-ws-cdn-in"]
	if u.Host != "cdn.example.com:443" {
		t.Errorf("host = %q, want the CDN edge", u.Host)
	}
	q := u.Query()
	if q.Get("sni") != front.SNI || q.Get("host") != front.Host {
		t.Errorf("sni/host = %q/%q, want the edge's", q.Get("sni"), q.Get("host"))
	}
	if q.Get("security") != "tls" {
		t.Errorf("security = %q, want tls at the edge", q.Get("security"))
	}
	if q.Get("path") == "" {
		t.Error("no path: the tunnel origin is addressed by it")
	}
}

func TestProtocolSpecificLinks(t *testing.T) {
	cfg := bot.ExampleConfig()
	f := loadFixture(t)

	t.Run("hysteria2 carries obfs when the inbound has it", func(t *testing.T) {
		in := inboundByTag(t, f, "hysteria-in")
		link, err := Link(cfg, in, testUser())
		if err != nil {
			t.Fatalf("Link: %v", err)
		}
		u, _ := url.Parse(link)
		if u.User.Username() != "pw-password-1" {
			t.Errorf("credential = %q, want the password", u.User.Username())
		}
		if in.Obfs != nil && in.Obfs.Type != "" {
			if u.Query().Get("obfs") != in.Obfs.Type {
				t.Errorf("obfs = %q, want %q", u.Query().Get("obfs"), in.Obfs.Type)
			}
		}
	})

	t.Run("tuic carries both halves of the credential", func(t *testing.T) {
		in := inboundByTag(t, f, "tuic-in")
		user := testUser()
		link, err := Link(cfg, in, user)
		if err != nil {
			t.Fatalf("Link: %v", err)
		}
		u, _ := url.Parse(link)
		if u.User.Username() != user.UUID {
			t.Errorf("uuid = %q", u.User.Username())
		}
		if pw, _ := u.User.Password(); pw != user.Password {
			t.Errorf("password = %q", pw)
		}
		if q := u.Query(); q.Get("alpn") == "" || q.Get("congestion_control") == "" {
			t.Errorf("alpn/congestion_control missing: %v", q)
		}
	})

	t.Run("mtproto uses the inbound secret and no user", func(t *testing.T) {
		in := inboundByTag(t, f, "mtproto-in")
		link, err := Link(cfg, in, User{})
		if err != nil {
			t.Fatalf("Link: %v", err)
		}
		if !strings.HasPrefix(link, "tg://proxy?server=vpn.example.com&port=10868&secret=") {
			t.Errorf("link = %q", link)
		}
	})
}

// TestLinkEscaping covers the two things net/url would have done differently
// and that would change links users already hold.
func TestLinkEscaping(t *testing.T) {
	cfg := bot.ExampleConfig()
	in := inboundByTag(t, loadFixture(t), "anytls-in")

	link, err := Link(cfg, in, User{Name: "a b", Password: "p/w+x=y"})
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	// A space is %20, not "+": the links are compared against ones handed out
	// before, where the encoder rendered it that way.
	if !strings.HasSuffix(link, "#a%20b") {
		t.Errorf("fragment not percent-encoded: %q", link)
	}
	// And reserved characters in a credential are escaped rather than left to
	// be reinterpreted as syntax.
	if !strings.Contains(link, "p%2Fw%2Bx%3Dy@") {
		t.Errorf("credential not escaped: %q", link)
	}
}

// TestParameterOrderIsStable keeps a regenerated link byte-identical to the
// one a user already imported, so nothing asks them to re-import for nothing.
func TestParameterOrderIsStable(t *testing.T) {
	cfg := bot.ExampleConfig()
	in := inboundByTag(t, loadFixture(t), "vless-reality-in")

	link, err := Link(cfg, in, testUser())
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	raw := link[strings.Index(link, "?")+1 : strings.Index(link, "#")]
	var order []string
	for _, part := range strings.Split(raw, "&") {
		order = append(order, strings.SplitN(part, "=", 2)[0])
	}
	want := []string{"encryption", "type", "security", "sni", "fp", "pbk", "sid"}
	if len(order) < len(want) {
		t.Fatalf("query = %v", order)
	}
	for i, key := range want {
		if order[i] != key {
			t.Errorf("parameter %d is %q, want %q (order is part of the output)", i, order[i], key)
		}
	}
}

func TestStringOrListAcceptsBothShapes(t *testing.T) {
	for _, tc := range []struct {
		json string
		want string
	}{
		{`"one"`, "one"},
		{`["first","second"]`, "first"},
		{`[]`, ""},
		{`""`, ""},
	} {
		var s StringOrList
		if err := json.Unmarshal([]byte(tc.json), &s); err != nil {
			t.Errorf("%s: %v", tc.json, err)
			continue
		}
		if got := s.First(); got != tc.want {
			t.Errorf("%s -> %q, want %q", tc.json, got, tc.want)
		}
	}
	var s StringOrList
	if err := json.Unmarshal([]byte(`{"not":"either"}`), &s); err == nil {
		t.Error("an object was accepted as a string-or-list")
	}
}

// TestParseUserAcceptsNaivesCapitals matters because naive-in's users are
// stored Username/Password on disk. A user whose key decodes empty looks
// unprovisioned and gets provisioned again under the same name.
func TestParseUserAcceptsNaivesCapitals(t *testing.T) {
	u, err := ParseUser([]byte(`{"Username":"user1","Password":"pw"}`))
	if err != nil {
		t.Fatalf("ParseUser: %v", err)
	}
	if u.Key() != "user1" || u.Password != "pw" {
		t.Errorf("user = %+v", u)
	}

	lower, err := ParseUser([]byte(`{"name":"bob","uuid":"u"}`))
	if err != nil {
		t.Fatalf("ParseUser: %v", err)
	}
	if lower.Key() != "bob" {
		t.Errorf("key = %q", lower.Key())
	}
}

// TestMieruTransportComesFromTheInbound: the client needs TCP or UDP where the
// inbound says portBindings, and the two schemas are not interchangeable.
func TestMieruTransportComesFromTheInbound(t *testing.T) {
	in := inboundByTag(t, loadFixture(t), "mieru-in")
	if got := in.MieruTransport(); got != "TCP" {
		t.Errorf("transport = %q, want TCP from the inbound's binding", got)
	}

	udp := Inbound{PortBindings: []PortBinding{{Protocol: "udp", Port: 1}}}
	if got := udp.MieruTransport(); got != "UDP" {
		t.Errorf("transport = %q, want UDP uppercased", got)
	}
	if got := (Inbound{}).MieruTransport(); got != "TCP" {
		t.Errorf("default transport = %q, want TCP", got)
	}
}

// TestXHTTPObfsFieldsOnlyWhenTheInboundSaysSo keeps configs for the plain
// inbound byte-identical: emitting the padding fields there would make every
// existing client re-import for nothing.
func TestXHTTPObfsFieldsOnlyWhenTheInboundSaysSo(t *testing.T) {
	f := loadFixture(t)

	plain := inboundByTag(t, f, "vless-xhttp-in")
	if fields := plain.XHTTPObfsFields(); len(fields) != 0 {
		t.Errorf("plain xhttp emitted %v", fields)
	}

	obfs := inboundByTag(t, f, "vless-xhttp-obfs-in")
	fields := obfs.XHTTPObfsFields()
	if len(fields) == 0 {
		t.Fatal("the obfs inbound emitted no padding fields; a client would get 400 on every request")
	}
	if fields["x_padding_obfs_mode"] != true {
		t.Error("obfs mode flag missing")
	}
	for _, key := range []string{"x_padding_key", "x_padding_header", "x_padding_placement", "x_padding_method"} {
		if _, ok := fields[key]; !ok {
			t.Errorf("%s missing: all of them must be present or the server rejects the request", key)
		}
	}
}

// TestLinksMatchThePythonBot is the parity check that matters during the port.
//
// testdata/python-links.json was produced by running bot.py's build_link over
// the same fixture with the same user, inside the bot's own image. Byte
// equality is the requirement, not equivalence: a user who re-imports must get
// what they already had, and a reordered query or a differently escaped space
// is a different string even when it describes the same server.
//
// Regenerate with the recipe in testdata/README.md after changing a generator
// on purpose -- and only after confirming the change was intended.
func TestLinksMatchThePythonBot(t *testing.T) {
	cfg := bot.ExampleConfig()
	f := loadFixture(t)

	data, err := os.ReadFile("testdata/python-links.json")
	if err != nil {
		t.Fatalf("read oracle: %v", err)
	}
	var want map[string]string
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatalf("parse oracle: %v", err)
	}

	checked := 0
	for _, raw := range f.Inbounds {
		in, err := ParseInbound(raw)
		if err != nil {
			t.Fatalf("parse inbound: %v", err)
		}
		expected, ok := want[in.Tag]
		if !ok {
			t.Errorf("no oracle entry for %s", in.Tag)
			continue
		}
		got, err := Link(cfg, in, testUser())
		if err != nil {
			t.Errorf("%s: %v", in.Tag, err)
			continue
		}
		if got != expected {
			t.Errorf("%s:\n  go     %s\n  python %s", in.Tag, got, expected)
			continue
		}
		checked++
	}
	if checked != len(want) {
		t.Errorf("compared %d links, oracle has %d", checked, len(want))
	}
}
