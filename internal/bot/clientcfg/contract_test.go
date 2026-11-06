package clientcfg

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/keys"
	"github.com/spaiter/spaiter-vpn/internal/singbox"
)

// This file is the contract between the bot and the cores: every artefact a
// generator produces is handed to the core that will actually read it.
//
// Two cores, because their option schemas have diverged and a config checked
// against the wrong one is worse than unchecked. That is not hypothetical --
// on 2026-11-01 a client-facing MASQUE config was moved to the server's flat
// schema, passed a check against the server core, and left six users without
// the WARP path for two days. The split below is the lesson:
//
//   - everything a user receives goes to the CLIENT core;
//   - the WARP registration config, which only ever runs on this host, goes to
//     the server core.
//
// The client core lives outside this repository and is host-specific, so its
// absence is a skip. Set CONTRACT_REQUIRED=1 -- as scripts/check.sh does -- to
// turn every skip here into a failure, so a gate cannot report success for
// checks that never ran.

// contractCores are the two binaries, either of which may be absent.
type contractCores struct {
	server *singbox.Checker
	client *singbox.Checker
}

func loadCores(t *testing.T) contractCores {
	t.Helper()
	return contractCores{
		server: findCore(t, "SING_BOX_BIN", "sing-box-server", "server"),
		client: findCore(t, "SING_BOX_CLIENT_BIN", "sing-box-client", "client"),
	}
}

// findCore locates one core by environment variable, falling back to the path
// scripts/check.sh builds it at.
//
// Deliberately not singbox.Detect: that falls back to whatever sing-box is on
// PATH, and here the whole point is which binary runs the check. A core picked
// up by accident is the failure mode this file exists to prevent.
func findCore(t *testing.T, env, cached, role string) *singbox.Checker {
	t.Helper()
	if path := os.Getenv(env); path != "" {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s points at %s, which is not there: %v", env, path, err)
		}
		return &singbox.Checker{Binary: path}
	}
	// ../../.. is the repository root; the gate builds both cores into .cache.
	path := filepath.Join("..", "..", "..", ".cache", cached)
	if _, err := os.Stat(path); err == nil {
		absolute, err := filepath.Abs(path)
		if err != nil {
			t.Fatalf("resolve %s: %v", path, err)
		}
		return &singbox.Checker{Binary: absolute}
	}
	requireContract(t, fmt.Sprintf("no %s core: set %s or build it into .cache/%s", role, env, cached))
	return nil
}

// requireContract skips, unless the caller asked for the contract to be
// enforced, in which case the absence is the failure.
func requireContract(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("CONTRACT_REQUIRED") != "" {
		t.Fatalf("CONTRACT_REQUIRED is set: %s", reason)
	}
	t.Skipf("%s", reason)
}

// check runs one artefact past one core.
func check(t *testing.T, core *singbox.Checker, name string, config []byte) {
	t.Helper()
	if core == nil {
		requireContract(t, "the core for "+name+" is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := core.Check(ctx, config); err != nil {
		t.Errorf("%s was rejected by %s:\n%v\n\nthe config was:\n%s",
			name, core.Describe(), err, config)
	}
}

// asOutboundOnly wraps one node so it can be checked alone.
//
// A chain carries its legs in _chain, which is not a sing-box type at all --
// the client expands it into an outbound per leg and wires the detour between
// them. Expanded the same way here, because checking the unexpanded form would
// only prove the core rejects a key it has never heard of.
func asOutboundOnly(t *testing.T, node any) []byte {
	t.Helper()
	encoded, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("render node: %v", err)
	}
	var probe struct {
		Type  string            `json:"type"`
		Chain []json.RawMessage `json:"_chain"`
	}
	if err := json.Unmarshal(encoded, &probe); err != nil {
		t.Fatalf("read node: %v", err)
	}

	outbounds := []json.RawMessage{encoded}
	if probe.Type == "chain" {
		outbounds = probe.Chain
	}
	config, err := json.MarshalIndent(map[string]any{
		"log":       map[string]any{"level": "warn"},
		"outbounds": outbounds,
	}, "", "  ")
	if err != nil {
		t.Fatalf("render config: %v", err)
	}
	return config
}

// contractPeer has real keys, unlike testPeer. A core parses the key material,
// so a placeholder would fail the check for a reason that has nothing to do
// with the node's shape.
func contractPeer(t *testing.T) state.Peer {
	t.Helper()
	pair, err := keys.NewX25519()
	if err != nil {
		t.Fatalf("NewX25519: %v", err)
	}
	return state.Peer{Priv: pair.PrivateStd(), Pub: pair.PublicStd(), IP: "10.40.0.3"}
}

// contractWARPAccount is a registered Cloudflare account's shape with throwaway
// values, since the real one cannot be committed and registering during a test
// would reach the network.
func contractWARPAccount(t *testing.T) state.WARPAccount {
	t.Helper()
	pair, err := keys.NewX25519()
	if err != nil {
		t.Fatalf("NewX25519: %v", err)
	}
	// The field set is option.MASQUEAccount's, exactly. The core rejects an
	// unknown field outright, so an invented one fails the check for a reason
	// that has nothing to do with the node being tested -- which is how this
	// fixture was wrong the first time round.
	account, err := json.Marshal(map[string]any{
		"private_key":      pair.PrivateStd(),
		"endpoint_v4":      "162.159.198.1:443",
		"endpoint_v6":      "[2606:4700:103::1]:443",
		"endpoint_h2_v4":   "162.159.198.1:443",
		"endpoint_h2_v6":   "[2606:4700:103::1]:443",
		"endpoint_pub_key": contractECDSAPublicKey,
		"license":          "contract-license",
		"id":               "contract-device-id",
		"access_token":     "contract-access-token",
		"ipv4":             "172.16.0.2",
		"ipv6":             "2606:4700:110:8a1b:c1a4:1f2c:a9ba:6a1d",
	})
	if err != nil {
		t.Fatalf("render account: %v", err)
	}
	return state.WARPAccount(account)
}

// parsedInbounds decodes the fixture's inbounds once.
func parsedInbounds(t *testing.T, f fixture) []Inbound {
	t.Helper()
	out := make([]Inbound, 0, len(f.Inbounds))
	for _, raw := range f.Inbounds {
		in, err := ParseInbound(raw)
		if err != nil {
			t.Fatalf("parse inbound: %v", err)
		}
		out = append(out, in)
	}
	return out
}

// parsedEndpoints decodes the fixture's endpoints by tag.
func parsedEndpoints(t *testing.T, f fixture) map[string]Endpoint {
	t.Helper()
	out := map[string]Endpoint{}
	for _, raw := range f.Endpoints {
		var endpoint Endpoint
		if err := json.Unmarshal(raw, &endpoint); err != nil {
			t.Fatalf("parse endpoint: %v", err)
		}
		out[endpoint.Tag] = endpoint
	}
	return out
}

// inboundsByTag indexes the fixture for the generators that need a second
// inbound -- ShadowTLS needs the shadowsocks one it detours through.
func inboundsByTag(t *testing.T, f fixture) map[string]Inbound {
	t.Helper()
	out := map[string]Inbound{}
	for _, in := range parsedInbounds(t, f) {
		out[in.Tag] = in
	}
	return out
}

// contractECDSAPublicKey is the endpoint key a MASQUE account pins its server
// by. Generated for this test and used nowhere; it has to be a real PEM because
// the core parses it rather than carrying it as a string.
const contractECDSAPublicKey = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOZuHChllspABDSO3OjjuOYfWmaVg\nyktccz95DBdnMXEFx50H+Gt0aEWL1e4yV47dFyhM4jw+dhhtKw2+fPD6/g==\n-----END PUBLIC KEY-----\n"

// ssKeySizes is how many raw bytes each shadowsocks 2022 method needs.
var ssKeySizes = map[string]int{
	"2022-blake3-aes-128-gcm":       16,
	"2022-blake3-aes-256-gcm":       32,
	"2022-blake3-chacha20-poly1305": 32,
}

// withParseableKey replaces a redacted shadowsocks password with a real one.
//
// The fixture's credentials are placeholders by design, but a core does not
// merely carry this field -- it decodes it as a key of the method's exact
// length, and "redacted-password" fails at byte 8. Substituting here keeps the
// redaction in the fixture while still exercising the shape, which is what is
// actually under test. The alternative, putting a key in the fixture, would
// mean regenerating the Python oracle that quotes it.
func withParseableKey(t *testing.T, in Inbound) Inbound {
	t.Helper()
	if in.Type != "shadowsocks" {
		return in
	}
	size, known := ssKeySizes[in.Method]
	if !known {
		t.Fatalf("no key size known for shadowsocks method %q; "+
			"add it, or the core will reject the credential for the wrong reason", in.Method)
	}
	key, err := keys.Base64(size)
	if err != nil {
		t.Fatalf("generate a shadowsocks key: %v", err)
	}
	in.Password = key
	return in
}

// TestContractBundleNodesAreAcceptedByTheClientCore covers every node a
// subscriber receives for a proxy inbound.
func TestContractBundleNodesAreAcceptedByTheClientCore(t *testing.T) {
	cores := loadCores(t)
	cfg := contractConfig()
	fixture := loadFixture(t)

	for _, inbound := range parsedInbounds(t, fixture) {
		// A node for an inbound that is never put in a bundle is not worth
		// checking: naive is offered only as a config file, and the client core
		// is not even built with its outbound.
		if slices.Contains(cfg.Bundle.SkipTags, inbound.Tag) {
			continue
		}
		node, err := BundleNode(cfg, inbound, oracleUser(), NodeLabel(cfg, inbound))
		if err != nil {
			t.Errorf("%s: %v", inbound.Tag, err)
			continue
		}
		if node == nil {
			continue // arrives by another route; covered by its own test
		}
		t.Run("bundle/"+inbound.Tag, func(t *testing.T) {
			check(t, cores.client, inbound.Tag, asOutboundOnly(t, node))
		})
	}
}

// TestContractJSONConfigsAreAcceptedByTheClientCore covers the protocols
// delivered as a whole config because they have no usable share URI.
func TestContractJSONConfigsAreAcceptedByTheClientCore(t *testing.T) {
	cores := loadCores(t)
	cfg := contractConfig()
	fixture := loadFixture(t)
	byTag := inboundsByTag(t, fixture)

	// notSingBox is output that is deliberately not a sing-box config, so
	// handing it to a core would assert the wrong thing.
	notSingBox := map[string]string{
		"naive-in": "a naiveproxy client config, not sing-box",
	}

	for tag := range bot.JSONTags() {
		inbound, ok := byTag[tag]
		if !ok {
			t.Errorf("%s is in JSONTags but not in the fixture, so it is untested", tag)
			continue
		}
		t.Run("json/"+tag, func(t *testing.T) {
			if reason, skip := notSingBox[tag]; skip {
				t.Skipf("%s", reason)
			}
			in := JSONConfigInput{Inbound: withParseableKey(t, inbound), User: oracleUser()}
			if inbound.Type == "shadowtls" {
				backend := withParseableKey(t, byTag["ss-stls-in"])
				in.Backend = &backend
			}
			config, err := JSONConfig(cfg, in)
			if err != nil {
				t.Fatalf("JSONConfig: %v", err)
			}
			check(t, cores.client, tag, config)
		})
	}
}

// TestContractSpecialNodesAreAcceptedByTheClientCore covers the nodes built
// from WireGuard endpoints and the two chains, which is where the two cores'
// schemas differ most: the server nests the obfuscation parameters under "awg"
// and the client wants them flat, and MASQUE's account is nested here and flat
// there.
func TestContractSpecialNodesAreAcceptedByTheClientCore(t *testing.T) {
	cores := loadCores(t)
	cfg := contractConfig()
	fixture := loadFixture(t)
	peer := contractPeer(t)

	endpoints := parsedEndpoints(t, fixture)
	inbounds := inboundsByTag(t, fixture)

	t.Run("awg/awg-in", func(t *testing.T) {
		node, err := AWGNode(endpoints["awg-in"], peer, "AmneziaWG", cfg.Public.Host)
		if err != nil {
			t.Fatalf("AWGNode: %v", err)
		}
		check(t, cores.client, "awg-in", asOutboundOnly(t, node))
	})

	t.Run("awg/awg3-in", func(t *testing.T) {
		node, err := AWGNode(endpoints["awg3-in"], peer, "AmneziaWG 3.1", cfg.Public.Host)
		if err != nil {
			t.Fatalf("AWGNode: %v", err)
		}
		check(t, cores.client, "awg3-in", asOutboundOnly(t, node))
	})

	t.Run("masque-wg", func(t *testing.T) {
		node, err := MASQUEWGNode(cfg, endpoints["wg-masque-in"], peer, 443, "/m")
		if err != nil {
			t.Fatalf("MASQUEWGNode: %v", err)
		}
		check(t, cores.client, "masque-wg", asOutboundOnly(t, node))
	})

	// The server core has no wdtt outbound and must never grow one -- the relay
	// is the only implementation of that side, see relay/README.md -- so this
	// node is checkable by the client core alone.
	t.Run("wdtt", func(t *testing.T) {
		node := WDTTNode(cfg, "relay-password", []string{"aaaaaaaaaaaa", "bbbbbbbbbbbb"})
		check(t, cores.client, "wdtt", asOutboundOnly(t, node))
	})

	t.Run("chain/shadowtls", func(t *testing.T) {
		chain := ShadowTLSChain(cfg, inbounds["shadowtls-in"],
			withParseableKey(t, inbounds["ss-stls-in"]), oracleUser(), "ShadowTLS")
		check(t, cores.client, "shadowtls chain", asOutboundOnly(t, chain))
	})

	t.Run("chain/warp", func(t *testing.T) {
		chain, err := WARPChain(cfg, inbounds["vless-reality-in"], oracleUser(),
			contractWARPAccount(t), "WARP → сервер")
		if err != nil {
			t.Fatalf("WARPChain: %v", err)
		}
		check(t, cores.client, "warp chain", asOutboundOnly(t, chain))
	})
}

// TestContractTheWholeBundleIsAcceptedByTheClientCore checks what is actually
// served, not just its parts.
//
// Worth having separately: a node that is valid alone can still be rejected in
// company -- a duplicated tag, a detour pointing at a leg that got expanded
// away, a url-test group naming an outbound that is not there.
func TestContractTheWholeBundleIsAcceptedByTheClientCore(t *testing.T) {
	cores := loadCores(t)
	cfg := contractConfig()
	// As this host serves it, with both gates on: the defaults have them off
	// for a fresh deployment, and with chains off this check never saw two
	// chains together -- which is exactly where the duplicate tag hid.
	cfg.Bundle.EnableChains = true
	cfg.Bundle.EnableAWG3 = true
	nodes := assembleContractBundle(t, cfg)

	bundle := Assemble(cfg, nodes)
	served, err := bundle.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Chains are expanded the way the client does before the core sees it, and
	// the url-test group is kept: a group naming a tag that expansion removed
	// is precisely the kind of breakage this catches.
	check(t, cores.client, "the whole bundle", expandChains(t, served))
}

// TestContractTheWarpRegistrationConfigIsAcceptedByTheServerCore is the one
// artefact that belongs to the server core: it runs on this host to mint an
// account and is never handed to anyone.
//
// Note what this does not cover. The registration config is schema-valid
// without store_masque_config, and the core silently writes no account without
// it, so `check` passing says nothing about whether registration works. That
// gap is still open and is why the Python's warp-registration check found
// nothing when registration had quietly stopped producing accounts.
func TestContractTheWarpRegistrationConfigIsAcceptedByTheServerCore(t *testing.T) {
	cores := loadCores(t)
	cfg := contractConfig()

	config, err := json.MarshalIndent(WARPRegistrationConfig(cfg, "/tmp/contract-warp-cache.db"), "", "  ")
	if err != nil {
		t.Fatalf("render registration config: %v", err)
	}
	check(t, cores.server, "warp registration", config)

	// The flag the core gates the cache write on. Absent, registration runs,
	// reports nothing wrong and produces no account.
	if !strings.Contains(string(config), `"store_masque_config"`) {
		t.Error("the registration config does not ask for the account to be stored, " +
			"so it would register and save nothing")
	}
}

// TestContractBundleHasEveryFamily guards against a bundle that shrinks
// quietly.
//
// Families rather than a count: a count shifts whenever a protocol is added,
// which trains everyone to update the number. What matters is that every way a
// user is expected to connect is still offered -- a builder that errored used
// to be left out of the Python's bundle, and a short bundle looked healthy.
func TestContractBundleHasEveryFamily(t *testing.T) {
	cfg := contractConfig()
	// Chains and AmneziaWG 3.1 are off in the defaults, which mirror bot.py;
	// this host enables both, and the bundle has to be checked as served.
	cfg.Bundle.EnableChains = true
	cfg.Bundle.EnableAWG3 = true

	bundle := Assemble(cfg, assembleContractBundle(t, cfg))
	served, err := bundle.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var parsed struct {
		Outbounds []struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(served, &parsed); err != nil {
		t.Fatalf("parse bundle: %v", err)
	}

	present := map[string]bool{}
	tags := map[string]bool{}
	for _, outbound := range parsed.Outbounds {
		present[outbound.Type] = true
		if tags[outbound.Tag] {
			t.Errorf("two outbounds are tagged %q; the client keeps one of them", outbound.Tag)
		}
		tags[outbound.Tag] = true
	}

	expected := []string{
		"vless", "hysteria2", "tuic", "mieru", "anytls", "snell",
		"awg", "wdtt", "masque-wg", "chain", "urltest",
	}
	for _, family := range expected {
		if !present[family] {
			t.Errorf("the bundle offers no %s node; a user who relies on it has nothing to pick", family)
		}
	}
}

// TestContractLinksAgreeWithTheirBundleNode is the cross-check the Python
// added after a link and a node disagreed about a port.
//
// A user has two ways to the same inbound -- tap the button for a link, or take
// the one in the subscription -- and they must arrive at the same server. A
// discrepancy is silent: both import cleanly and one of them does not connect.
func TestContractLinksAgreeWithTheirBundleNode(t *testing.T) {
	cfg := contractConfig()
	fixture := loadFixture(t)
	jsonTags := bot.JSONTags()

	for _, inbound := range parsedInbounds(t, fixture) {
		if jsonTags[inbound.Tag] {
			continue // delivered as a config, not a link
		}
		link, err := Link(cfg, inbound, oracleUser())
		if err != nil || link == "" {
			continue // no share URI for this type
		}
		node, err := BundleNode(cfg, inbound, oracleUser(), NodeLabel(cfg, inbound))
		if err != nil {
			t.Errorf("%s: %v", inbound.Tag, err)
			continue
		}
		if node == nil {
			// Some protocols are only ever a link: mtproto has no sing-box
			// outbound at all and is handed to a Telegram client directly.
			continue
		}

		t.Run("link/"+inbound.Tag, func(t *testing.T) {
			server, _ := node["server"].(string)
			if server != "" && !strings.Contains(link, server) {
				t.Errorf("the link does not name %s, which the bundle node dials:\n%s", server, link)
			}
			port := nodePort(node)
			if port != 0 && !strings.Contains(link, fmt.Sprint(port)) {
				t.Errorf("the link does not carry port %d, which the bundle node dials:\n%s", port, link)
			}
			if uuid, _ := node["uuid"].(string); uuid != "" && !strings.Contains(link, uuid) {
				t.Errorf("the link carries a different credential than the bundle node:\n%s", link)
			}
		})
	}
}

// TestContractAWGConfInvariants covers the .conf a user imports into the
// Amnezia client, which no core can validate: it is an ini file for a different
// program.
func TestContractAWGConfInvariants(t *testing.T) {
	cfg := contractConfig()
	fixture := loadFixture(t)
	peer := contractPeer(t)

	required := map[string][]string{
		"Interface": {"PrivateKey", "Address", "MTU"},
		"Peer":      {"PublicKey", "AllowedIPs", "Endpoint"},
	}

	for _, endpoint := range parsedEndpoints(t, fixture) {
		if endpoint.Tag != "awg-in" && endpoint.Tag != "awg3-in" {
			continue // the other endpoints are not delivered as a .conf
		}
		t.Run("conf/"+endpoint.Tag, func(t *testing.T) {
			address := fmt.Sprintf("%s:%d", cfg.Public.Host, endpoint.ListenPort)
			conf, err := WireGuardConf(endpoint, peer, address, "")
			if err != nil {
				t.Fatalf("WireGuardConf: %v", err)
			}
			sections := parseINI(t, conf)
			for section, fields := range required {
				for _, field := range fields {
					if sections[section][field] == "" {
						t.Errorf("[%s] has no %s; the client refuses the file", section, field)
					}
				}
			}
			// Booleans go out as on/off. Amnezia's parser takes the ini
			// convention and reads "true" as unset, which silently disables an
			// obfuscation parameter the server requires.
			for section, fields := range sections {
				for field, value := range fields {
					lowered := strings.ToLower(value)
					if lowered == "true" || lowered == "false" {
						t.Errorf("[%s] %s = %s; the client wants on/off and reads this as unset",
							section, field, value)
					}
				}
			}
		})
	}
}

// expandChains rewrites a served bundle the way the client does, so a core can
// read it.
func expandChains(t *testing.T, served []byte) []byte {
	t.Helper()
	var parsed struct {
		Outbounds []map[string]json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(served, &parsed); err != nil {
		t.Fatalf("parse bundle: %v", err)
	}

	expanded := make([]any, 0, len(parsed.Outbounds))
	for _, outbound := range parsed.Outbounds {
		legs, isChain := outbound["_chain"]
		if !isChain {
			expanded = append(expanded, outbound)
			continue
		}
		var decoded []map[string]json.RawMessage
		if err := json.Unmarshal(legs, &decoded); err != nil {
			t.Fatalf("parse chain legs: %v", err)
		}
		// Namespaced by their chain, which is what the client does and what
		// makes two chains able to coexist. Both of ours tag their entry leg
		// "proxy", so expanding them flat produces a duplicate tag and the core
		// rejects the whole config -- found by expanding a live subscription by
		// hand during the cutover, because this test only ever had one chain
		// enabled at a time.
		var chainTag string
		if raw, ok := outbound["tag"]; ok {
			_ = json.Unmarshal(raw, &chainTag)
		}
		for _, leg := range decoded {
			expanded = append(expanded, namespaceLeg(t, leg, chainTag))
		}
	}

	config, err := json.MarshalIndent(map[string]any{
		"log":       map[string]any{"level": "warn"},
		"outbounds": expanded,
	}, "", "  ")
	if err != nil {
		t.Fatalf("render bundle: %v", err)
	}
	return config
}

// namespaceLeg prefixes a chain leg's tag with the chain's own, and rewrites
// the detour that points at its sibling so the two still reference each other.
func namespaceLeg(t *testing.T, leg map[string]json.RawMessage, chainTag string) map[string]json.RawMessage {
	t.Helper()
	out := make(map[string]json.RawMessage, len(leg))
	for key, value := range leg {
		out[key] = value
	}
	for _, field := range []string{"tag", "detour"} {
		raw, ok := out[field]
		if !ok {
			continue
		}
		var name string
		if err := json.Unmarshal(raw, &name); err != nil {
			continue
		}
		renamed, err := json.Marshal(chainTag + "/" + name)
		if err != nil {
			t.Fatalf("rename %s: %v", field, err)
		}
		out[field] = renamed
	}
	return out
}

// assembleContractBundle builds the node list the way the service layer will,
// from the fixture rather than from a live server.
func assembleContractBundle(t *testing.T, cfg bot.Config) []any {
	t.Helper()
	fixture := loadFixture(t)
	peer := contractPeer(t)

	byTag := inboundsByTag(t, fixture)
	endpoints := parsedEndpoints(t, fixture)

	var nodes []any
	for _, inbound := range parsedInbounds(t, fixture) {
		if slices.Contains(cfg.Bundle.SkipTags, inbound.Tag) {
			continue
		}
		node, err := BundleNode(cfg, inbound, oracleUser(), NodeLabel(cfg, inbound))
		if err != nil {
			// An error here must not quietly shorten the bundle, which is how
			// the Python lost a protocol without anyone noticing.
			t.Fatalf("%s: %v", inbound.Tag, err)
		}
		// Being in JSONTags does not keep an inbound out of the bundle -- it
		// means the button hands out a config file as well, and mieru and snell
		// are in both places in the live subscription.
		if node != nil {
			nodes = append(nodes, node)
		}
	}

	awg, err := AWGNode(endpoints["awg-in"], peer, "AmneziaWG", cfg.Public.Host)
	if err != nil {
		t.Fatalf("AWGNode: %v", err)
	}
	nodes = append(nodes, awg)

	if cfg.Bundle.EnableAWG3 {
		awg3, err := AWGNode(endpoints["awg3-in"], peer, "AmneziaWG 3.1", cfg.Public.Host)
		if err != nil {
			t.Fatalf("AWGNode awg3: %v", err)
		}
		nodes = append(nodes, awg3)
	}

	masque, err := MASQUEWGNode(cfg, endpoints["wg-masque-in"], peer, 443, "/m")
	if err != nil {
		t.Fatalf("MASQUEWGNode: %v", err)
	}
	nodes = append(nodes, masque)
	nodes = append(nodes, WDTTNode(cfg, "relay-password", []string{"aaaaaaaaaaaa"}))

	if cfg.Bundle.EnableChains {
		nodes = append(nodes, ShadowTLSChain(cfg, byTag["shadowtls-in"],
			withParseableKey(t, byTag["ss-stls-in"]), oracleUser(), "ShadowTLS"))
		warp, err := WARPChain(cfg, byTag["vless-reality-in"], oracleUser(),
			contractWARPAccount(t), "WARP → сервер")
		if err != nil {
			t.Fatalf("WARPChain: %v", err)
		}
		nodes = append(nodes, warp)
	}
	return nodes
}

// nodePort reads a node's port whichever way JSON decoded it.
func nodePort(node Node) int {
	switch value := node["server_port"].(type) {
	case float64:
		return int(value)
	case int:
		return value
	case uint16:
		return int(value)
	}
	return 0
}

// parseINI reads the .conf the way a client does: sections and key = value.
func parseINI(t *testing.T, text string) map[string]map[string]string {
	t.Helper()
	sections := map[string]map[string]string{}
	current := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.Trim(line, "[]")
			sections[current] = map[string]string{}
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			t.Errorf("unparseable line in the .conf: %q", line)
			continue
		}
		if current == "" {
			t.Errorf("%q appears before any section", line)
			continue
		}
		sections[current][strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return sections
}

// contractConfig is the example configuration with the server addressed by an
// IP literal. The client core resolves WireGuard peer endpoints while it checks
// a config, and example.com subdomains do not resolve; a literal also keeps
// these tests off the network.
func contractConfig() bot.Config {
	cfg := bot.ExampleConfig()
	cfg.Public.Host = "192.0.2.10"
	cfg.Public.IPv4Host = "192.0.2.10"
	return cfg
}
