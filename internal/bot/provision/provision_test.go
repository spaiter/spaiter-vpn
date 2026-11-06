package provision

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

// fakeAPI stands in for the core's management API, holding the config the way
// the core does: inbounds with user lists, endpoints with peer lists.
type fakeAPI struct {
	mu        sync.Mutex
	inbounds  map[string]map[string]any
	users     map[string][]json.RawMessage
	endpoints map[string]map[string]any
	adds      int
	puts      int
	putErr    error
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{
		inbounds:  map[string]map[string]any{},
		users:     map[string][]json.RawMessage{},
		endpoints: map[string]map[string]any{},
	}
}

func (f *fakeAPI) Inbound(_ context.Context, tag string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	inbound, ok := f.inbounds[tag]
	if !ok {
		return nil, errors.New("no such inbound")
	}
	return json.Marshal(inbound)
}

func (f *fakeAPI) Users(_ context.Context, tag string) ([]json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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

func (f *fakeAPI) Endpoint(_ context.Context, tag string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	endpoint, ok := f.endpoints[tag]
	if !ok {
		return nil, errors.New("no such endpoint")
	}
	return json.Marshal(endpoint)
}

func (f *fakeAPI) PutEndpoint(_ context.Context, tag string, endpoint any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putErr != nil {
		return f.putErr
	}
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

func (f *fakeAPI) peers(t *testing.T, tag string) []endpointPeer {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	encoded, err := json.Marshal(f.endpoints[tag]["peers"])
	if err != nil {
		t.Fatalf("marshal peers: %v", err)
	}
	var peers []endpointPeer
	if err := json.Unmarshal(encoded, &peers); err != nil {
		t.Fatalf("read peers: %v", err)
	}
	return peers
}

type countingReloader struct {
	mu        sync.Mutex
	requests  int
	requested error
}

func (c *countingReloader) Request(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests++
	return c.requested
}

func (c *countingReloader) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests
}

// serverPrivate is a throwaway endpoint key; any 32 bytes will do, since the
// public half is derived and never checked against anything external.
const serverPrivate = "c3BhaXRlci12cG4gcHJvdmlzaW9uIHRlc3Qga2V5ISE="

func newTestProvisioner(t *testing.T) (*Provisioner, *fakeAPI, *countingReloader, *state.Store) {
	t.Helper()
	api := newFakeAPI()
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	rl := &countingReloader{}
	return New(api, store, rl, slog.New(slog.DiscardHandler)), api, rl, store
}

func TestEnsureUserCreatesAnAccount(t *testing.T) {
	p, api, rl, _ := newTestProvisioner(t)
	api.inbounds["vless-reality-in"] = map[string]any{"type": "vless", "tag": "vless-reality-in"}

	account, err := p.EnsureUser(context.Background(), "vless-reality-in", "42")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	if !account.Created {
		t.Error("a new account was reported as pre-existing")
	}
	if UserKey(account.User) != "42" {
		t.Errorf("user key = %q", UserKey(account.User))
	}
	if rl.count() != 1 {
		t.Errorf("reload requests = %d, want one for the new account", rl.count())
	}
}

// TestEnsureUserIsIdempotent is what keeps the six live users from being
// re-provisioned when this binary replaces the one that first served them.
func TestEnsureUserIsIdempotent(t *testing.T) {
	p, api, rl, _ := newTestProvisioner(t)
	api.inbounds["tuic-in"] = map[string]any{"type": "tuic"}

	first, err := p.EnsureUser(context.Background(), "tuic-in", "42")
	if err != nil {
		t.Fatalf("first EnsureUser: %v", err)
	}
	second, err := p.EnsureUser(context.Background(), "tuic-in", "42")
	if err != nil {
		t.Fatalf("second EnsureUser: %v", err)
	}

	if second.Created {
		t.Error("the second call minted a second account for the same user")
	}
	if api.adds != 1 {
		t.Errorf("AddUser called %d times, want 1", api.adds)
	}
	if rl.count() != 1 {
		t.Errorf("reload requests = %d: an account that already existed asked for an apply", rl.count())
	}
	// And the credentials are the ones already issued, not fresh ones: handing
	// back a new UUID would leave the client with a password the core rejects.
	if string(first.User) != string(second.User) {
		t.Errorf("credentials changed between calls:\n%s\n%s", first.User, second.User)
	}
}

// TestEnsureUserFindsUsernameKeyedAccounts: naive and mieru have no name field,
// and reading the wrong one makes every lookup miss and mint a duplicate.
func TestEnsureUserFindsUsernameKeyedAccounts(t *testing.T) {
	for _, inboundType := range []string{"naive", "mieru"} {
		t.Run(inboundType, func(t *testing.T) {
			p, api, _, _ := newTestProvisioner(t)
			api.inbounds["in"] = map[string]any{"type": inboundType}

			if _, err := p.EnsureUser(context.Background(), "in", "42"); err != nil {
				t.Fatalf("first: %v", err)
			}
			second, err := p.EnsureUser(context.Background(), "in", "42")
			if err != nil {
				t.Fatalf("second: %v", err)
			}
			if second.Created || api.adds != 1 {
				t.Errorf("a username-keyed account was not recognised: adds = %d", api.adds)
			}
		})
	}
}

func TestUserKeyPrefersNameThenUsername(t *testing.T) {
	cases := map[string]string{
		`{"name":"42","uuid":"x"}`:         "42",
		`{"username":"42","password":"x"}`: "42",
		`{"name":"","username":"42"}`:      "42",
		`{"uuid":"x"}`:                     "",
		`not json`:                         "",
	}
	for input, want := range cases {
		if got := UserKey(json.RawMessage(input)); got != want {
			t.Errorf("UserKey(%s) = %q, want %q", input, got, want)
		}
	}
}

// TestCredentialShapes pins the field names per protocol. The API accepts an
// object with the wrong fields and the inbound then ignores it, producing a
// user who exists in the config and cannot authenticate.
func TestCredentialShapes(t *testing.T) {
	cases := []struct {
		inboundType string
		want        []string
		absent      []string
	}{
		{"vless", []string{"name", "uuid"}, []string{"password"}},
		{"vmess", []string{"name", "uuid"}, nil},
		{"hysteria2", []string{"name", "password"}, nil},
		{"trojan", []string{"name", "password"}, nil},
		{"shadowsocks", []string{"name", "password"}, nil},
		{"tuic", []string{"name", "uuid", "password"}, nil},
		{"naive", []string{"username", "password"}, []string{"name"}},
		{"mieru", []string{"username", "password"}, []string{"name"}},
		{"snell", []string{"name", "userkey"}, []string{"password"}},
		{"something-new", []string{"name", "password"}, nil},
	}
	for _, c := range cases {
		account, err := Credentials(c.inboundType, "42")
		if err != nil {
			t.Fatalf("%s: %v", c.inboundType, err)
		}
		for _, field := range c.want {
			value, ok := account[field]
			if !ok {
				t.Errorf("%s: missing %q in %v", c.inboundType, field, account)
				continue
			}
			if s, _ := value.(string); s == "" {
				t.Errorf("%s: %q is empty", c.inboundType, field)
			}
		}
		for _, field := range c.absent {
			if _, present := account[field]; present {
				t.Errorf("%s: unexpected %q in %v", c.inboundType, field, account)
			}
		}
		if len(account) != len(c.want) {
			t.Errorf("%s: fields = %v, want exactly %v", c.inboundType, account, c.want)
		}
	}
}

// TestShadowsocksPasswordIsARawKey: SS2022 reads the password as 16 raw bytes
// in standard base64, and a urlsafe or differently sized one is rejected at
// startup rather than at connect.
func TestShadowsocksPasswordIsARawKey(t *testing.T) {
	account, err := Credentials("shadowsocks", "42")
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	password, _ := account["password"].(string)
	decoded, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		t.Fatalf("password %q is not standard base64: %v", password, err)
	}
	if len(decoded) != 16 {
		t.Errorf("key is %d bytes, want 16", len(decoded))
	}
}

func TestCredentialsAreNotReused(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		account, err := Credentials("vless", "42")
		if err != nil {
			t.Fatalf("Credentials: %v", err)
		}
		uuid, _ := account["uuid"].(string)
		if seen[uuid] {
			t.Fatalf("uuid %q handed out twice", uuid)
		}
		seen[uuid] = true
	}
}

func endpointWith(peers []any) map[string]any {
	return map[string]any{
		"type":        "wireguard",
		"private_key": serverPrivate,
		"address":     []any{"10.10.0.1/24"},
		"listen_port": float64(10863),
		"mtu":         float64(1200),
		"peers":       peers,
		// A field this package knows nothing about, to prove it survives.
		"workers": float64(4),
	}
}

func TestEnsurePeerRegistersAndReportsTheEndpointsOwnSettings(t *testing.T) {
	p, api, rl, store := newTestProvisioner(t)
	api.endpoints["awg-in"] = endpointWith(nil)

	peer, err := p.EnsurePeer(context.Background(), "awg-in", "42")
	if err != nil {
		t.Fatalf("EnsurePeer: %v", err)
	}
	if peer.Address != "10.10.0.2" {
		t.Errorf("address = %q, want the first free one", peer.Address)
	}
	// Read from the endpoint, not assumed: a client that guesses these does not
	// complete a handshake.
	if peer.ListenPort != 10863 || peer.MTU != 1200 {
		t.Errorf("port/mtu = %d/%d", peer.ListenPort, peer.MTU)
	}
	if peer.ServerPublicKey == "" || peer.ServerPublicKey == serverPrivate {
		t.Errorf("server public key = %q, want it derived from the private one", peer.ServerPublicKey)
	}
	if rl.count() != 1 {
		t.Errorf("reload requests = %d, want one for the new peer", rl.count())
	}

	// The peer carries a name, which is what attributes its traffic to the user.
	peers := api.peers(t, "awg-in")
	if len(peers) != 1 {
		t.Fatalf("peers = %d", len(peers))
	}
	if peers[0].PublicKey != peer.PublicKey {
		t.Error("the registered key is not the one handed to the client")
	}
	var named []struct{ Name string }
	encoded, _ := json.Marshal(api.endpoints["awg-in"]["peers"])
	_ = json.Unmarshal(encoded, &named)
	if named[0].Name != "42" {
		t.Errorf("peer name = %q, want the uid so stats attribute to it", named[0].Name)
	}

	if _, found, _ := store.Peer("42", "awg-in"); !found {
		t.Error("the peer was not recorded on disk")
	}
}

func TestEnsurePeerPreservesTheRestOfTheEndpoint(t *testing.T) {
	p, api, _, _ := newTestProvisioner(t)
	api.endpoints["awg-in"] = endpointWith(nil)
	api.endpoints["awg-in"]["awg"] = map[string]any{"jc": float64(4), "h1": float64(1)}

	if _, err := p.EnsurePeer(context.Background(), "awg-in", "42"); err != nil {
		t.Fatalf("EnsurePeer: %v", err)
	}
	stored := api.endpoints["awg-in"]
	// Fields this package does not model must come back: dropping the
	// obfuscation parameters would break every existing client on the endpoint.
	if _, ok := stored["awg"]; !ok {
		t.Error("the awg parameters were dropped by the write-back")
	}
	if stored["workers"] != float64(4) {
		t.Errorf("workers = %v, want it preserved", stored["workers"])
	}
	if stored["private_key"] != serverPrivate {
		t.Error("the server key was altered")
	}
}

func TestEnsurePeerIsIdempotent(t *testing.T) {
	p, api, rl, _ := newTestProvisioner(t)
	api.endpoints["awg-in"] = endpointWith(nil)

	first, err := p.EnsurePeer(context.Background(), "awg-in", "42")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := p.EnsurePeer(context.Background(), "awg-in", "42")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.PrivateKey != second.PrivateKey || first.Address != second.Address {
		t.Error("the second call re-keyed a working tunnel")
	}
	if api.puts != 1 {
		t.Errorf("endpoint written %d times, want 1", api.puts)
	}
	if rl.count() != 1 {
		t.Errorf("reload requests = %d, want 1", rl.count())
	}
}

// TestEnsurePeerRemintsWhatTheEndpointForgot covers a config restored from a
// backup or an endpoint recreated: the file says the user has a peer and the
// core has never heard of the key. Trusting the file hands the client a key
// that fails to handshake with no diagnostic beyond silence.
func TestEnsurePeerRemintsWhatTheEndpointForgot(t *testing.T) {
	p, api, _, store := newTestProvisioner(t)
	api.endpoints["awg-in"] = endpointWith(nil)
	if err := store.SetPeer("42", "awg-in", state.Peer{
		Priv: "stale-private", Pub: "stale-public", IP: "10.10.0.9",
	}); err != nil {
		t.Fatalf("SetPeer: %v", err)
	}

	peer, err := p.EnsurePeer(context.Background(), "awg-in", "42")
	if err != nil {
		t.Fatalf("EnsurePeer: %v", err)
	}
	if peer.PublicKey == "stale-public" {
		t.Error("a key the endpoint does not know was handed to the client")
	}
	if peers := api.peers(t, "awg-in"); len(peers) != 1 {
		t.Errorf("peers = %d, want the stale one replaced rather than added beside", len(peers))
	}
}

func TestEnsurePeerDoesNotRecordAFailedRegistration(t *testing.T) {
	p, api, rl, store := newTestProvisioner(t)
	api.endpoints["awg-in"] = endpointWith(nil)
	api.putErr = errors.New("endpoint rejected")

	if _, err := p.EnsurePeer(context.Background(), "awg-in", "42"); err == nil {
		t.Fatal("a rejected registration was reported as success")
	}
	// Nothing on disk and no apply: a recorded key the core never accepted
	// would be handed out as live by the next call.
	if _, found, _ := store.Peer("42", "awg-in"); found {
		t.Error("a key the core rejected was recorded on disk")
	}
	if rl.count() != 0 {
		t.Error("an apply was requested for a registration that failed")
	}
}

// TestEnsurePeerAvoidsAddressesInUse is the collision this guards: two tunnels
// with the same source address, and the core routing both users' return
// traffic to whichever peer handshook last.
func TestEnsurePeerAvoidsAddressesInUse(t *testing.T) {
	p, api, _, _ := newTestProvisioner(t)
	api.endpoints["awg-in"] = endpointWith([]any{
		map[string]any{"public_key": "someone", "allowed_ips": "10.10.0.2/32"},
		// The list form, which the installer and a hand-written config use.
		map[string]any{"public_key": "else", "allowed_ips": []any{"10.10.0.3/32"}},
	})

	peer, err := p.EnsurePeer(context.Background(), "awg-in", "42")
	if err != nil {
		t.Fatalf("EnsurePeer: %v", err)
	}
	if peer.Address != "10.10.0.4" {
		t.Errorf("address = %q, want 10.10.0.4: both forms of allowed_ips count", peer.Address)
	}
}

// TestConcurrentPeersGetDistinctAddresses is why the endpoint is locked. Both
// goroutines read the same peer list, and without serialization both compute
// the same free address and the second write drops the first one's peer.
func TestConcurrentPeersGetDistinctAddresses(t *testing.T) {
	p, api, _, _ := newTestProvisioner(t)
	api.endpoints["awg-in"] = endpointWith(nil)

	var wg sync.WaitGroup
	addresses := make([]string, 4)
	start := make(chan struct{})
	for i := range addresses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			peer, err := p.EnsurePeer(context.Background(), "awg-in", string(rune('a'+i)))
			if err != nil {
				t.Errorf("EnsurePeer: %v", err)
				return
			}
			addresses[i] = peer.Address
		}()
	}
	close(start)
	wg.Wait()

	seen := map[string]bool{}
	for _, address := range addresses {
		if address == "" {
			continue
		}
		if seen[address] {
			t.Errorf("address %s handed to two users", address)
		}
		seen[address] = true
	}
	if peers := api.peers(t, "awg-in"); len(peers) != 4 {
		t.Errorf("peers = %d, want 4: a concurrent write dropped one", len(peers))
	}
}

func TestEnsurePeerRejectsAnEndpointWithoutAKey(t *testing.T) {
	p, api, _, _ := newTestProvisioner(t)
	api.endpoints["awg-in"] = map[string]any{"type": "wireguard", "address": []any{"10.10.0.1/24"}}

	if _, err := p.EnsurePeer(context.Background(), "awg-in", "42"); err == nil {
		t.Fatal("an endpoint with no private key was accepted")
	}
}

func TestEnsureWDTTKeepsThePasswordAndTellsTheRelay(t *testing.T) {
	p, api, _, store := newTestProvisioner(t)
	api.endpoints["wg-wdtt-in"] = endpointWith(nil)
	// The relay's config directory is a mount that exists in the deployment.
	relayDir := filepath.Join(t.TempDir(), "wdtt")
	if err := os.MkdirAll(relayDir, 0o700); err != nil {
		t.Fatal(err)
	}
	passwords := filepath.Join(relayDir, "passwords.json")

	first, err := p.EnsureWDTT(context.Background(), "wg-wdtt-in", "42", passwords)
	if err != nil {
		t.Fatalf("EnsureWDTT: %v", err)
	}
	if first.Password == "" {
		t.Fatal("no password was issued")
	}
	second, err := p.EnsureWDTT(context.Background(), "wg-wdtt-in", "42", passwords)
	if err != nil {
		t.Fatalf("second EnsureWDTT: %v", err)
	}
	// A rotated password is a client that silently stops connecting: the config
	// they already imported carries the old one.
	if second.Password != first.Password {
		t.Error("the password changed between calls")
	}

	if _, ok := store.MarkerTime(WDTTReloadMarker); !ok {
		t.Error("the relay was never told to reload, so the password is inert")
	}

	// The relay's entry has to point at this user's tunnel, or the relay
	// decapsulates their traffic into somebody else's peer.
	var db struct {
		Passwords map[string]struct {
			WGPriv string `json:"wg_priv"`
			WGIP   string `json:"wg_ip"`
		} `json:"passwords"`
	}
	raw, err := os.ReadFile(passwords)
	if err != nil {
		t.Fatalf("read passwords: %v", err)
	}
	if err := json.Unmarshal(raw, &db); err != nil {
		t.Fatalf("passwords file does not parse: %v\n%s", err, raw)
	}
	entry, ok := db.Passwords[first.Password]
	if !ok {
		t.Fatalf("the issued password is not in the relay's file: %s", raw)
	}
	if entry.WGPriv != first.Peer.PrivateKey || entry.WGIP != first.Peer.Address {
		t.Errorf("relay entry = %+v, want this user's tunnel", entry)
	}
}

func TestEnsureWARPCachesTheAccount(t *testing.T) {
	p, _, _, _ := newTestProvisioner(t)
	registrations := 0
	registrar := registrarFunc(func(context.Context) (json.RawMessage, error) {
		registrations++
		return json.RawMessage(`{"private_key":"k","ipv4":"172.16.0.2"}`), nil
	})

	first, err := p.EnsureWARP(context.Background(), "42", registrar)
	if err != nil {
		t.Fatalf("EnsureWARP: %v", err)
	}
	second, err := p.EnsureWARP(context.Background(), "42", registrar)
	if err != nil {
		t.Fatalf("second EnsureWARP: %v", err)
	}
	// Registration is a network call to Cloudflare behind a button someone is
	// waiting on, and it creates state at their end.
	if registrations != 1 {
		t.Errorf("registered %d times, want 1", registrations)
	}
	if string(first) != string(second) {
		t.Error("the cached account differs from the registered one")
	}
}

func TestEnsureWARPReportsAFailedRegistration(t *testing.T) {
	p, _, _, store := newTestProvisioner(t)
	registrar := registrarFunc(func(context.Context) (json.RawMessage, error) {
		return nil, errors.New("cloudflare said no")
	})

	_, err := p.EnsureWARP(context.Background(), "42", registrar)
	if err == nil {
		t.Fatal("a failed registration was reported as success")
	}
	if !strings.Contains(err.Error(), "cloudflare") {
		t.Errorf("error should carry the cause: %v", err)
	}
	if _, found, _ := store.WARPAccount("42"); found {
		t.Error("an account was cached for a registration that failed")
	}
}

type registrarFunc func(context.Context) (json.RawMessage, error)

func (f registrarFunc) Register(ctx context.Context) (json.RawMessage, error) { return f(ctx) }

func TestAnMTProtoUserGetsTheirOwnSecretForTheInboundsFrontDomain(t *testing.T) {
	front := "ee" + strings.Repeat("ab", 16) + hex.EncodeToString([]byte("www.google.com"))
	account, err := mtprotoCredentials(json.RawMessage(`{"type":"mtproto","users":[{"name":"a","secret":"`+front+`"}]}`), "42")
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := account["secret"].(string)
	if account["name"] != "42" || secret == front {
		t.Fatalf("account = %#v", account)
	}
	if domain, ok := mtprotoFrontDomain(secret); !ok || domain != "www.google.com" {
		t.Fatalf("the new secret fronts %q", domain)
	}
	if _, err := mtprotoCredentials(json.RawMessage(`{"type":"mtproto","secret":"dd00"}`), "42"); err == nil {
		t.Fatal("a secret was minted without a fake-TLS front domain to copy")
	}
}
