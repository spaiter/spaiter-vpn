// Package servicetest is a ready service.Service over a fake management API,
// for tests of the layers above it (the Telegram interface, the bot command).
//
// It is a real Service with a real provisioner and state store, talking to an
// in-memory stand-in for the core, so what a test exercises is the same code a
// deployment runs. Only the core is faked.
package servicetest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/provision"
	"github.com/spaiter/spaiter-vpn/internal/bot/service"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/keys"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// Fixture is a service and the pieces behind it.
type Fixture struct {
	Service   *service.Service
	API       *API
	Batcher   *Batcher
	Store     *state.Store
	Registrar *Registrar
	// Config is what the service was built with; callers may copy and adjust it.
	Config bot.Config
}

// New builds a service over a core with three per-user inbounds (vless
// reality, hysteria2, mtproto) and four WireGuard-family endpoints.
func New(t *testing.T) *Fixture {
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

	batch := &Batcher{}
	registrar := &Registrar{}
	prov := provision.New(api, store, batch, quiet())
	return &Fixture{
		Service: service.New(cfg, api, prov, store, batch, registrar, quiet()),
		API:     api, Batcher: batch, Store: store, Registrar: registrar, Config: cfg,
	}
}

// SetStats replaces the per-user traffic the core reports.
func (f *API) SetStats(rows ...manage.UserStat) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stats = rows
}

// SetNoUsers marks inbounds whose protocol has no per-user accounts.
func (f *API) SetNoUsers(tags ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.noUsers = map[string]bool{}
	for _, tag := range tags {
		f.noUsers[tag] = true
	}
}

// Counts reports how many accounts were added, endpoints rewritten and
// accounts deleted.
func (f *API) Counts() (adds, puts, deletes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.adds, f.puts, f.deletes
}

// Applies is how many times a provisioning run asked the core to reload.
func (b *Batcher) Applies() int { return b.count() }

// API is the core's management interface, holding the config the way the
// core does and counting the calls that change it.
type API struct {
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
	applies int

	failures map[string]error
}

// FailOn makes every later call of a management method ("Inbounds", "Users",
// "UserStats", "Endpoints") return err; nil restores it.
func (f *API) FailOn(method string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failures == nil {
		f.failures = map[string]error{}
	}
	f.failures[method] = err
}

func (f *API) Inbounds(context.Context) ([]manage.InboundRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failures["Inbounds"]; err != nil {
		return nil, err
	}
	out := make([]manage.InboundRef, 0, len(f.order))
	for _, tag := range f.order {
		kind, _ := f.inbounds[tag]["type"].(string)
		out = append(out, manage.InboundRef{Tag: tag, Type: kind})
	}
	return out, nil
}

func (f *API) Inbound(_ context.Context, tag string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	inbound, ok := f.inbounds[tag]
	if !ok {
		return nil, manage.ErrNotFound
	}
	return json.Marshal(inbound)
}

func (f *API) Users(_ context.Context, tag string) ([]json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failures["Users"]; err != nil {
		return nil, err
	}
	if f.noUsers[tag] {
		// What the core answers for a protocol without per-user accounts.
		return nil, fmt.Errorf("GET /manage/inbounds/%s/users: %w: protocol does not support users", tag, manage.ErrBadRequest)
	}
	return f.users[tag], nil
}

func (f *API) AddUser(_ context.Context, tag string, user any) error {
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

func (f *API) Endpoints(context.Context) ([]json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failures["Endpoints"]; err != nil {
		return nil, err
	}
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

func (f *API) Endpoint(_ context.Context, tag string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	endpoint, ok := f.endpoints[tag]
	if !ok {
		return nil, manage.ErrNotFound
	}
	return json.Marshal(endpoint)
}

func (f *API) PutEndpoint(_ context.Context, tag string, endpoint any) error {
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

func (f *API) UserStats(context.Context) ([]manage.UserStat, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failures["UserStats"]; err != nil {
		return nil, err
	}
	return f.stats, nil
}

// Batcher records how many applies a run cost, which is the whole
// reason the batch exists.
type Batcher struct {
	mu      sync.Mutex
	applies int
	opens   int
}

type batchKey struct{}

func (b *Batcher) Begin(ctx context.Context) (context.Context, func()) {
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

func (b *Batcher) Request(context.Context) error { return nil }

func (b *Batcher) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.applies
}

type Registrar struct {
	calls int
	err   error
}

func (f *Registrar) Register(context.Context) (json.RawMessage, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return json.RawMessage(`{"private_key":"k","ipv4":"172.16.0.2"}`), nil
}

func newAPI(t *testing.T) *API {
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
	return &API{
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

func (f *API) DeleteUser(_ context.Context, tag, name string) error {
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

func (f *API) ResetUserStats(_ context.Context, name string) error {
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

// Calls is how many WARP registrations were requested.
func (f *Registrar) Calls() int { return f.calls }

func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }

// AddShadowTLS adds a ShadowTLS front and its shadowsocks backend to the core,
// the one pair of inbounds whose client config is delivered as a JSON file.
func (f *API) AddShadowTLS() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inbounds["shadowtls-in"] = map[string]any{
		"type": "shadowtls", "tag": "shadowtls-in", "listen_port": float64(10864),
		"detour": "ss-in", "handshake": map[string]any{"server": "www.example.org"},
	}
	f.inbounds["ss-in"] = map[string]any{
		"type": "shadowsocks", "tag": "ss-in", "listen_port": float64(0),
		"method": "2022-blake3-aes-128-gcm", "password": "backend-secret",
	}
	f.order = append(f.order, "shadowtls-in", "ss-in")
}
