package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/provision"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/keys"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// fakeAPI is the core's management interface, holding the config the way the
// core does and counting the calls that change it.
type fakeAPI struct {
	mu        sync.Mutex
	inbounds  map[string]map[string]any
	order     []string
	users     map[string][]json.RawMessage
	noUsers   map[string]bool // inbounds whose protocol has no users on this core
	endpoints map[string]map[string]any
	stats     []manage.UserStat

	adds    int
	puts    int
	deletes int
}

func (f *fakeAPI) Inbounds(context.Context) ([]manage.InboundRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]manage.InboundRef, 0, len(f.order))
	for _, tag := range f.order {
		kind, _ := f.inbounds[tag]["type"].(string)
		out = append(out, manage.InboundRef{Tag: tag, Type: kind})
	}
	return out, nil
}

func (f *fakeAPI) Inbound(_ context.Context, tag string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	inbound, ok := f.inbounds[tag]
	if !ok {
		return nil, manage.ErrNotFound
	}
	return json.Marshal(inbound)
}

func (f *fakeAPI) Users(_ context.Context, tag string) ([]json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.noUsers[tag] {
		// What the core answers for a protocol without per-user accounts.
		return nil, fmt.Errorf("GET /manage/inbounds/%s/users: %w: protocol does not support users", tag, manage.ErrBadRequest)
	}
	return f.users[tag], nil
}

func (f *fakeAPI) AddUser(_ context.Context, tag string, user any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	encoded, err := json.Marshal(user)
	if err != nil {
		return err
	}
	f.adds++
	f.users[tag] = append(f.users[tag], encoded)
	return nil
}

func (f *fakeAPI) Endpoints(context.Context) ([]json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]json.RawMessage, 0, len(f.endpoints))
	for _, endpoint := range f.endpoints {
		encoded, err := json.Marshal(endpoint)
		if err != nil {
			return nil, err
		}
		out = append(out, encoded)
	}
	return out, nil
}

func (f *fakeAPI) Endpoint(_ context.Context, tag string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	endpoint, ok := f.endpoints[tag]
	if !ok {
		return nil, manage.ErrNotFound
	}
	return json.Marshal(endpoint)
}

func (f *fakeAPI) PutEndpoint(_ context.Context, tag string, endpoint any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	encoded, err := json.Marshal(endpoint)
	if err != nil {
		return err
	}
	var stored map[string]any
	if err := json.Unmarshal(encoded, &stored); err != nil {
		return err
	}
	f.puts++
	f.endpoints[tag] = stored
	return nil
}

func (f *fakeAPI) UserStats(context.Context) ([]manage.UserStat, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats, nil
}

func (f *fakeAPI) mutations() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.adds, f.puts
}

// countingBatcher records how many applies a run cost, which is the whole
// reason the batch exists.
type countingBatcher struct {
	mu      sync.Mutex
	applies int
	opens   int
}

type batchKey struct{}

func (b *countingBatcher) Begin(ctx context.Context) (context.Context, func()) {
	b.mu.Lock()
	b.opens++
	outermost := ctx.Value(batchKey{}) == nil
	b.mu.Unlock()

	if !outermost {
		return ctx, func() {}
	}
	ctx = context.WithValue(ctx, batchKey{}, true)
	return ctx, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.applies++
	}
}

func (b *countingBatcher) Request(context.Context) error { return nil }

func (b *countingBatcher) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.applies
}

type fakeRegistrar struct {
	calls int
	err   error
}

func (f *fakeRegistrar) Register(context.Context) (json.RawMessage, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return json.RawMessage(`{"private_key":"k","ipv4":"172.16.0.2"}`), nil
}

func newAPI(t *testing.T) *fakeAPI {
	t.Helper()
	pair, err := keys.NewX25519()
	if err != nil {
		t.Fatalf("NewX25519: %v", err)
	}

	endpoint := func(tag string) map[string]any {
		return map[string]any{
			"type": "awg", "tag": tag, "private_key": pair.PrivateStd(),
			"address": []any{"10.40.0.1/24"}, "listen_port": float64(10860),
			"mtu": float64(1200), "peers": []any{},
		}
	}
	return &fakeAPI{
		order: []string{"vless-reality-in", "hysteria-in", "mtproto-in"},
		inbounds: map[string]map[string]any{
			"vless-reality-in": {
				"type": "vless", "tag": "vless-reality-in", "listen_port": float64(10861),
				"tls": map[string]any{
					"enabled": true, "server_name": "www.example.com",
					"reality": map[string]any{
						"enabled": true, "private_key": pair.PrivateStd(),
						"short_id": []any{"0123456789abcdef"},
					},
				},
			},
			"hysteria-in": {
				"type": "hysteria2", "tag": "hysteria-in", "listen_port": float64(10862),
				"tls": map[string]any{"enabled": true, "server_name": "www.example.com"},
			},
			// Per-user on this fake core (its users resource answers), with
			// nobody provisioned yet: the normal start of a deployment that
			// kept only its shared secret.
			"mtproto-in": {"type": "mtproto", "tag": "mtproto-in", "listen_port": float64(10863), "secret": "ee" + strings.Repeat("0", 32) + "7777772e6578616d706c652e636f6d"},
		},
		users: map[string][]json.RawMessage{},
		endpoints: map[string]map[string]any{
			"awg-in":       endpoint("awg-in"),
			"awg3-in":      endpoint("awg3-in"),
			"wg-masque-in": endpoint("wg-masque-in"),
			"wg-wdtt-in":   endpoint("wg-wdtt-in"),
		},
	}
}

func newService(t *testing.T) (*Service, *fakeAPI, *countingBatcher, *state.Store, *fakeRegistrar) {
	t.Helper()
	api := newAPI(t)
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	// The relay's config directory is a mount in the deployment, so it has to
	// exist for a WG-over-VK provisioning to be able to write its password.
	relayDir := filepath.Join(t.TempDir(), "wdtt")
	if err := os.MkdirAll(relayDir, 0o700); err != nil {
		t.Fatal(err)
	}

	cfg := bot.ExampleConfig()
	cfg.Paths.DataDir = store.Dir()
	cfg.Paths.WDTTConfigDir = relayDir

	batch := &countingBatcher{}
	registrar := &fakeRegistrar{}
	prov := provision.New(api, store, batch, quiet())
	return New(cfg, api, prov, store, batch, registrar, quiet()), api, batch, store, registrar
}

func TestUserInboundsOffersMTProtoWhereTheCoreHasUsers(t *testing.T) {
	s, _, _, _, _ := newService(t)

	inbounds, err := s.UserInbounds(context.Background())
	if err != nil {
		t.Fatalf("UserInbounds: %v", err)
	}
	// Nobody is provisioned on mtproto-in yet; the method is offered anyway,
	// because the first account is minted on request.
	var offered bool
	for _, inbound := range inbounds {
		offered = offered || inbound.Type == "mtproto"
	}
	if !offered {
		t.Error("mtproto missing from the menu although the core has a users resource for it")
	}
	if len(inbounds) != 3 {
		t.Errorf("inbounds = %d, want all three user types", len(inbounds))
	}
}

func TestUserInboundsLeavesOutMTProtoOnACoreWithoutUsers(t *testing.T) {
	s, api, _, _, _ := newService(t)
	api.noUsers = map[string]bool{"mtproto-in": true}

	inbounds, err := s.UserInbounds(context.Background())
	if err != nil {
		t.Fatalf("UserInbounds: %v", err)
	}
	for _, inbound := range inbounds {
		if inbound.Type == "mtproto" {
			t.Error("mtproto reached the menu on a core that cannot hold its users; provisioning there would be rejected")
		}
	}
	if len(inbounds) != 2 {
		t.Errorf("inbounds = %d, want the two with accounts", len(inbounds))
	}
}

// TestOfferedEndpointsHidesTheInternalOnes: the MASQUE and VK endpoints are
// forwarded into from this host, and handing one out as a profile would give
// the user a tunnel to a port nothing answers on from outside.
func TestOfferedEndpointsHidesTheInternalOnes(t *testing.T) {
	s, _, _, _, _ := newService(t)

	endpoints, err := s.OfferedEndpoints(context.Background())
	if err != nil {
		t.Fatalf("OfferedEndpoints: %v", err)
	}
	offered := map[string]bool{}
	for _, endpoint := range endpoints {
		offered[endpoint.Tag] = true
	}
	for _, internal := range []string{"wg-masque-in", "wg-wdtt-in"} {
		if offered[internal] {
			t.Errorf("%s was offered as a profile", internal)
		}
	}
	for _, usable := range []string{"awg-in", "awg3-in"} {
		if !offered[usable] {
			t.Errorf("%s was not offered", usable)
		}
	}
}

// TestBundleWithoutProvisioningTouchesNothing is the invariant the refresh loop
// and the HTTP handler depend on. Both run without anyone pressing anything,
// and creating accounts from a timer would grow the configuration of a user who
// asked for nothing.
func TestBundleWithoutProvisioningTouchesNothing(t *testing.T) {
	s, api, batch, _, registrar := newService(t)

	bundle, err := s.Bundle(context.Background(), "42", false)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	adds, puts := api.mutations()
	if adds != 0 || puts != 0 {
		t.Errorf("the server was modified: %d accounts, %d endpoint writes", adds, puts)
	}
	if batch.count() != 0 {
		t.Errorf("applies = %d, want none", batch.count())
	}
	if registrar.calls != 0 {
		t.Error("a WARP registration was started by a read-only rebuild")
	}

	// A user with nothing provisioned gets an empty node list rather than an
	// error: that is what a subscription issued seconds ago looks like.
	var parsed struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(bundle, &parsed); err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	if len(parsed.Outbounds) != 0 {
		t.Errorf("outbounds = %d, want none for an unprovisioned user", len(parsed.Outbounds))
	}
}

// TestBundleWithProvisioningCostsOneApply is why the batch exists: provisioning
// one user touches every inbound and four endpoints, and an apply per helper
// was six round trips for one button press.
func TestBundleWithProvisioningCostsOneApply(t *testing.T) {
	s, api, batch, _, _ := newService(t)

	bundle, err := s.Bundle(context.Background(), "42", true)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	if batch.count() != 1 {
		t.Errorf("applies = %d, want exactly one for the whole run", batch.count())
	}

	adds, puts := api.mutations()
	if adds != 2 {
		t.Errorf("accounts created = %d, want one per user inbound", adds)
	}
	// Three endpoints by default: awg-in, the MASQUE one and the VK one. AWG
	// 3.1 is gated off in the defaults.
	if puts != 3 {
		t.Errorf("endpoint writes = %d, want three peers", puts)
	}

	var parsed struct {
		Outbounds []struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(bundle, &parsed); err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	present := map[string]bool{}
	for _, outbound := range parsed.Outbounds {
		present[outbound.Type] = true
	}
	for _, family := range []string{"vless", "hysteria2", "awg", "masque-wg", "wdtt", "urltest"} {
		if !present[family] {
			t.Errorf("the provisioned bundle has no %s node", family)
		}
	}
}

// TestBundleIsStableOnASecondRun: the second press must not re-key anything,
// or the configuration the user just imported stops working.
func TestBundleIsStableOnASecondRun(t *testing.T) {
	s, api, _, _, _ := newService(t)

	first, err := s.Bundle(context.Background(), "42", true)
	if err != nil {
		t.Fatalf("first Bundle: %v", err)
	}
	adds, puts := api.mutations()

	second, err := s.Bundle(context.Background(), "42", true)
	if err != nil {
		t.Fatalf("second Bundle: %v", err)
	}
	if adds2, puts2 := api.mutations(); adds2 != adds || puts2 != puts {
		t.Errorf("the second run created more: accounts %d->%d, endpoints %d->%d",
			adds, adds2, puts, puts2)
	}
	if string(first) != string(second) {
		t.Error("the bundle changed between two runs with nothing else happening")
	}
}

// TestTheReadOnlyBundleSeesWhatWasProvisioned ties the two modes together: what
// provisioning created is exactly what a later refresh rebuilds.
func TestTheReadOnlyBundleSeesWhatWasProvisioned(t *testing.T) {
	s, _, _, _, _ := newService(t)

	provisioned, err := s.Bundle(context.Background(), "42", true)
	if err != nil {
		t.Fatalf("provisioning Bundle: %v", err)
	}
	rebuilt, err := s.Bundle(context.Background(), "42", false)
	if err != nil {
		t.Fatalf("read-only Bundle: %v", err)
	}
	if string(provisioned) != string(rebuilt) {
		t.Error("a read-only rebuild differs from what provisioning produced; " +
			"the subscription would change under the user on the next refresh")
	}
}

// TestABrokenGeneratorIsAnErrorNotAShortBundle is the behaviour bot.py did not
// have. Every builder there was wrapped in a bare except, so a generator broken
// by a schema change produced a shorter bundle that looked healthy, and the
// symptom was a protocol quietly vanishing from everyone's client.
func TestABrokenGeneratorIsAnErrorNotAShortBundle(t *testing.T) {
	s, api, _, _, _ := newService(t)

	// An inbound whose Reality key cannot be decoded: the node builder has to
	// fail, and the failure has to reach the caller.
	api.inbounds["vless-reality-in"]["tls"] = map[string]any{
		"enabled": true, "server_name": "www.example.com",
		"reality": map[string]any{"enabled": true, "private_key": "not-a-key"},
	}

	if _, err := s.Bundle(context.Background(), "42", true); err == nil {
		t.Fatal("a bundle was produced despite a generator failing")
	} else if !strings.Contains(err.Error(), "vless-reality-in") {
		t.Errorf("the error should name the method: %v", err)
	}
}

func TestLinkProvisionsAndIsStable(t *testing.T) {
	s, api, batch, _, _ := newService(t)

	first, err := s.Link(context.Background(), "vless-reality-in", "42")
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	if !strings.HasPrefix(first, "vless://") {
		t.Errorf("link = %q", first)
	}
	if batch.count() != 1 {
		t.Errorf("applies = %d, want one", batch.count())
	}

	second, err := s.Link(context.Background(), "vless-reality-in", "42")
	if err != nil {
		t.Fatalf("second Link: %v", err)
	}
	// Same credential: a fresh UUID would leave the client holding one the core
	// rejects.
	if first != second {
		t.Errorf("the link changed between presses:\n%s\n%s", first, second)
	}
	if adds, _ := api.mutations(); adds != 1 {
		t.Errorf("accounts created = %d, want 1", adds)
	}
}

func TestLinkRefusesAProtocolThatHasNone(t *testing.T) {
	s, api, _, _, _ := newService(t)
	api.inbounds["mieru-in"] = map[string]any{
		"type": "mieru", "tag": "mieru-in", "listen_port": float64(10864),
		"portBindings": []any{map[string]any{"port": "10864", "protocol": "TCP"}},
	}
	api.order = append(api.order, "mieru-in")

	// Mieru is handed out as a config file; a link would be a string the client
	// cannot use, so saying so beats returning one.
	_, err := s.Link(context.Background(), "mieru-in", "42")
	if err == nil {
		t.Fatal("a link was produced for a config-only protocol")
	}
}

// TestJSONConfigForShadowTLSCarriesTheBackend: the client authenticates at the
// TLS layer and then speaks shadowsocks inside, so a config with only the outer
// credential connects and carries nothing.
func TestJSONConfigForShadowTLSCarriesTheBackend(t *testing.T) {
	s, api, _, _, _ := newService(t)
	api.inbounds["ss-stls-in"] = map[string]any{
		"type": "shadowsocks", "tag": "ss-stls-in", "listen_port": float64(10041),
		"method": "2022-blake3-aes-128-gcm", "password": "YWJjZGVmZ2hpamtsbW5v",
	}
	api.inbounds["shadowtls-in"] = map[string]any{
		"type": "shadowtls", "tag": "shadowtls-in", "listen_port": float64(10870),
		"detour": "ss-stls-in", "version": float64(3),
		"handshake": map[string]any{"server": "www.microsoft.com", "server_port": float64(443)},
	}
	api.order = append(api.order, "shadowtls-in")

	config, err := s.JSONConfig(context.Background(), "shadowtls-in", "42")
	if err != nil {
		t.Fatalf("JSONConfig: %v", err)
	}
	if !strings.Contains(string(config), "2022-blake3-aes-128-gcm") {
		t.Errorf("the backend's method is missing, so the inner protocol is undefined:\n%s", config)
	}
	if !strings.Contains(string(config), "YWJjZGVmZ2hpamtsbW5v") {
		t.Error("the backend's credential is missing")
	}
}

func TestAWGConfProvisionsAPeer(t *testing.T) {
	s, api, _, store, _ := newService(t)

	conf, err := s.AWGConf(context.Background(), "awg-in", "42")
	if err != nil {
		t.Fatalf("AWGConf: %v", err)
	}
	if !strings.Contains(conf, "[Interface]") || !strings.Contains(conf, "[Peer]") {
		t.Errorf("conf is not a WireGuard profile:\n%s", conf)
	}
	if _, found, _ := store.Peer("42", "awg-in"); !found {
		t.Error("the peer was not recorded")
	}
	if _, puts := api.mutations(); puts != 1 {
		t.Errorf("endpoint writes = %d, want 1", puts)
	}
	// The resolver has to be in there: the tunnel carries none of its own and a
	// profile without it connects and resolves nothing.
	if !strings.Contains(conf, "DNS") {
		t.Error("the profile names no resolver")
	}
}

func TestWDTTConfigWritesTheRelayPassword(t *testing.T) {
	s, _, _, store, _ := newService(t)

	config, err := s.WDTTConfig(context.Background(), "42")
	if err != nil {
		t.Fatalf("WDTTConfig: %v", err)
	}
	password, found, err := store.WDTTPassword("42")
	if err != nil || !found {
		t.Fatalf("password: found=%v err=%v", found, err)
	}
	if !strings.Contains(string(config), password) {
		t.Error("the config does not carry the password the relay was told about")
	}
	// Standalone: the client needs somewhere to send traffic and a default for
	// where it goes, or it imports and routes nothing.
	for _, needed := range []string{`"inbounds"`, `"final": "proxy"`} {
		if !strings.Contains(string(config), needed) {
			t.Errorf("the config is missing %s", needed)
		}
	}
}

func TestWARPChainConfigRegistersOnce(t *testing.T) {
	s, _, _, _, registrar := newService(t)

	config, err := s.WARPChainConfig(context.Background(), "42")
	if err != nil {
		t.Fatalf("WARPChainConfig: %v", err)
	}
	if _, err := s.WARPChainConfig(context.Background(), "42"); err != nil {
		t.Fatalf("second WARPChainConfig: %v", err)
	}
	if registrar.calls != 1 {
		t.Errorf("registered %d times, want 1: it is a network call to Cloudflare", registrar.calls)
	}

	// Both legs, and the exit is ours: the point of the chain is that the user
	// keeps our egress address rather than Cloudflare's.
	for _, needed := range []string{`"masque"`, `"vless"`, `"detour"`} {
		if !strings.Contains(string(config), needed) {
			t.Errorf("the chain is missing %s:\n%s", needed, config)
		}
	}
}

// TestAFailedWARPRegistrationCostsOnlyItsOwnNode: registration reaches
// Cloudflare and can fail for reasons that have nothing to do with this user.
// One method missing beats no subscription at all.
func TestAFailedWARPRegistrationCostsOnlyItsOwnNode(t *testing.T) {
	s, _, _, _, registrar := newService(t)
	s.cfg.Bundle.EnableChains = true
	registrar.err = errors.New("cloudflare said no")

	bundle, err := s.Bundle(context.Background(), "42", true)
	if err != nil {
		t.Fatalf("a failed registration broke the whole bundle: %v", err)
	}
	if strings.Contains(string(bundle), `"masque"`) {
		t.Error("a WARP node was emitted despite registration failing")
	}
	if !strings.Contains(string(bundle), `"wdtt"`) {
		t.Error("the other methods were lost with it")
	}
}

func TestStatsTellsNoDataFromZero(t *testing.T) {
	s, api, _, _, _ := newService(t)

	// A user who has never connected has no row at all, which is not the same
	// as zero bytes: zero on a config that was imported means something is
	// wrong, while no row just means it was not used.
	if _, found, err := s.Stats(context.Background(), "42"); err != nil || found {
		t.Errorf("found=%v err=%v, want no record", found, err)
	}

	api.stats = []manage.UserStat{{User: "42", Upload: 10, Download: 20}}
	stat, found, err := s.Stats(context.Background(), "42")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if stat.Upload != 10 || stat.Download != 20 {
		t.Errorf("stat = %+v", stat)
	}
}

func (f *fakeAPI) DeleteUser(_ context.Context, tag, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := make([]json.RawMessage, 0, len(f.users[tag]))
	for _, raw := range f.users[tag] {
		if provision.UserKey(raw) != name {
			kept = append(kept, raw)
		}
	}
	if len(kept) == len(f.users[tag]) {
		return manage.ErrNotFound
	}
	f.users[tag] = kept
	f.deletes++
	return nil
}

func (f *fakeAPI) ResetUserStats(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, row := range f.stats {
		if row.User == name {
			f.stats[i] = manage.UserStat{User: name}
			return nil
		}
	}
	return manage.ErrNotFound
}

// TestDeleteUserAppliesAtOnce: an account removed from the config but still
// held by the running inbound keeps working, so the apply is the deletion.
func TestDeleteUserAppliesAtOnce(t *testing.T) {
	s, api, batch, _, _ := newService(t)

	if _, err := s.Link(context.Background(), "vless-reality-in", "42"); err != nil {
		t.Fatalf("Link: %v", err)
	}
	applies := batch.count()

	if err := s.DeleteUser(context.Background(), "vless-reality-in", "42"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if api.deletes != 1 {
		t.Errorf("deletes = %d", api.deletes)
	}
	if batch.count() != applies+1 {
		t.Error("the deletion was not applied, so the credential still works")
	}

	// And it is gone from a rebuild rather than lingering.
	bundle, err := s.Bundle(context.Background(), "42", false)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	if strings.Contains(string(bundle), `"vless"`) {
		t.Error("the deleted account is still in the subscription")
	}
}

func TestDeletingSomethingThatIsNotThereSaysSo(t *testing.T) {
	s, _, _, _, _ := newService(t)
	if err := s.DeleteUser(context.Background(), "vless-reality-in", "nobody"); err == nil {
		t.Fatal("deleting an account that does not exist was reported as success")
	}
}

// TestAccountsComesFromTheInboundsNotTheRegistry is the bug this test exists
// for: the admin view listed the user registry, which records everyone who ever
// messaged the bot, so people who had been refused access appeared in a list an
// admin reads as "who has the VPN".
func TestAccountsComesFromTheInboundsNotTheRegistry(t *testing.T) {
	s, _, _, store, _ := newService(t)

	// Someone who messaged the bot and was never approved.
	if err := store.Register(state.User{ID: 999, FirstName: "Refused"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := store.AddPending(999); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	// And someone who was actually provisioned.
	if _, err := s.Link(context.Background(), "vless-reality-in", "42"); err != nil {
		t.Fatalf("Link: %v", err)
	}
	if _, err := s.Link(context.Background(), "hysteria-in", "42"); err != nil {
		t.Fatalf("Link: %v", err)
	}

	accounts, err := s.Accounts(context.Background())
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	if _, listed := accounts["999"]; listed {
		t.Error("a user who was refused access is listed as holding a configuration")
	}
	tags, listed := accounts["42"]
	if !listed {
		t.Fatal("a provisioned user is not listed")
	}
	// Every inbound they are on, so an admin can see what they actually hold.
	if !slices.Equal(tags, []string{"hysteria-in", "vless-reality-in"}) {
		t.Errorf("tags = %v, want both inbounds sorted", tags)
	}
}

// TestAccountsStillListsARevokedUser: the whitelist says who may ask for a
// configuration, this says who holds one. A revoked user keeps connecting until
// their accounts are deleted, and that is exactly what an admin needs to see.
func TestAccountsStillListsARevokedUser(t *testing.T) {
	s, _, _, store, _ := newService(t)

	if _, err := s.Link(context.Background(), "vless-reality-in", "42"); err != nil {
		t.Fatalf("Link: %v", err)
	}
	if err := store.Allow(42); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if err := store.Deny(42); err != nil {
		t.Fatalf("Deny: %v", err)
	}

	accounts, err := s.Accounts(context.Background())
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	if _, listed := accounts["42"]; !listed {
		t.Error("a revoked user whose accounts still exist was hidden; " +
			"their credentials keep working and an admin would not know")
	}
}

func TestAccountsWithNobodyProvisioned(t *testing.T) {
	s, _, _, _, _ := newService(t)
	accounts, err := s.Accounts(context.Background())
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	if len(accounts) != 0 {
		t.Errorf("accounts = %v, want none", accounts)
	}
}
