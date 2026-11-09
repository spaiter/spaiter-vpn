package provision

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

// brokenAPI wraps the fake and fails or distorts chosen calls.
type brokenAPI struct {
	*fakeAPI
	inbound     json.RawMessage
	usersErr    error
	addErr      error
	endpointRaw json.RawMessage
}

func (b *brokenAPI) Inbound(ctx context.Context, tag string) (json.RawMessage, error) {
	if b.inbound != nil {
		return b.inbound, nil
	}
	return b.fakeAPI.Inbound(ctx, tag)
}

func (b *brokenAPI) Users(ctx context.Context, tag string) ([]json.RawMessage, error) {
	if b.usersErr != nil {
		return nil, b.usersErr
	}
	return b.fakeAPI.Users(ctx, tag)
}

func (b *brokenAPI) AddUser(ctx context.Context, tag string, user any) error {
	if b.addErr != nil {
		return b.addErr
	}
	return b.fakeAPI.AddUser(ctx, tag, user)
}

func (b *brokenAPI) Endpoint(ctx context.Context, tag string) (json.RawMessage, error) {
	if b.endpointRaw != nil {
		return b.endpointRaw, nil
	}
	return b.fakeAPI.Endpoint(ctx, tag)
}

func brokenProvisioner(t *testing.T) (*Provisioner, *brokenAPI, *countingReloader, *state.Store) {
	t.Helper()
	p, api, rl, store := newTestProvisioner(t)
	broken := &brokenAPI{fakeAPI: api}
	p.api = broken
	return p, broken, rl, store
}

func TestNewFallsBackToTheDefaultLogger(t *testing.T) {
	if p := New(newFakeAPI(), nil, &countingReloader{}, nil); p.log == nil {
		t.Error("no logger")
	}
	_ = slog.Default()
}

func TestEnsureUserNamesWhatWentWrong(t *testing.T) {
	ctx := context.Background()

	p, api, _, _ := brokenProvisioner(t)
	if _, err := p.EnsureUser(ctx, "missing", "42"); err == nil || !strings.Contains(err.Error(), "inbound missing") {
		t.Errorf("unknown inbound: %v", err)
	}

	api.inbound = json.RawMessage(`"not an object"`)
	if _, err := p.EnsureUser(ctx, "x", "42"); err == nil || !strings.Contains(err.Error(), "is not an object") {
		t.Errorf("inbound not an object: %v", err)
	}

	api.inbound = json.RawMessage(`{"type":"vless"}`)
	api.usersErr = errors.New("users down")
	if _, err := p.EnsureUser(ctx, "x", "42"); err == nil || !strings.Contains(err.Error(), "users of x") {
		t.Errorf("users failure: %v", err)
	}

	api.usersErr, api.addErr = nil, errors.New("add refused")
	if _, err := p.EnsureUser(ctx, "x", "42"); err == nil || !strings.Contains(err.Error(), "add 42 to x") {
		t.Errorf("add failure: %v", err)
	}

	// An mtproto inbound with no fake-TLS secret cannot mint anyone a secret.
	api.addErr = nil
	api.inbound = json.RawMessage(`{"type":"mtproto"}`)
	if _, err := p.EnsureUser(ctx, "x", "42"); err == nil || !strings.Contains(err.Error(), "credentials for mtproto") {
		t.Errorf("mtproto without a secret: %v", err)
	}

	// The account is added, but the apply that would serve it fails.
	p2, api2, rl, _ := brokenProvisioner(t)
	api2.inbound = json.RawMessage(`{"type":"trojan"}`)
	rl.requested = errors.New("apply refused")
	if _, err := p2.EnsureUser(ctx, "x", "42"); err == nil || !strings.Contains(err.Error(), "apply after adding") {
		t.Errorf("reload failure: %v", err)
	}
}

func TestMTProtoCredentialsRejectUnreadableInbounds(t *testing.T) {
	if _, err := mtprotoCredentials(json.RawMessage(`[1]`), "u"); err == nil {
		t.Error("an array inbound was accepted")
	}
	if _, ok := mtprotoFrontDomain("ee" + strings.Repeat("0", 32) + "zz"); ok {
		t.Error("a non-hex domain was accepted")
	}
	if _, ok := mtprotoFrontDomain("dd" + strings.Repeat("0", 40)); ok {
		t.Error("a secret without the ee prefix was accepted")
	}
}

func TestIsLastInPrefixLeavesTinySubnetsAlone(t *testing.T) {
	for _, prefix := range []string{"10.0.0.0/31", "10.0.0.1/32", "fd00::/127"} {
		network := netip.MustParsePrefix(prefix)
		if isLastInPrefix(network.Addr(), network) {
			t.Errorf("%s: its only addresses were reserved", prefix)
		}
	}
	network := netip.MustParsePrefix("10.0.0.0/24")
	if !isLastInPrefix(netip.MustParseAddr("10.0.0.255"), network) || isLastInPrefix(netip.MustParseAddr("10.0.0.254"), network) {
		t.Error("the broadcast address is not the one reserved")
	}
}

func TestEnsurePeerRefusesEndpointsItCannotAllocateFrom(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		raw  string
		want string
	}{
		"not an object":  {`[]`, "is not an object"},
		"wrong types":    {`{"private_key": 5}`, "read endpoint"},
		"no private key": {`{"address":["10.10.0.1/24"]}`, "no private key"},
		"bad private key": {`{"private_key":"not-base64!","address":["10.10.0.1/24"]}`,
			"private key"},
		"no address":       {`{"private_key":"` + serverPrivate + `"}`, "no address to allocate"},
		"unreadable peer":  {`{"private_key":"` + serverPrivate + `","address":["10.10.0.1/24"],"peers":[{"allowed_ips":"junk"}]}`, "unreadable"},
		"unreadable range": {`{"private_key":"` + serverPrivate + `","address":["nonsense"]}`, "endpoint address"},
	}
	for name, c := range cases {
		p, api, _, _ := brokenProvisioner(t)
		api.endpointRaw = json.RawMessage(c.raw)
		if _, err := p.EnsurePeer(ctx, "awg-in", "42"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}

	p, _, _, _ := brokenProvisioner(t)
	if _, err := p.EnsurePeer(ctx, "absent", "42"); err == nil || !strings.Contains(err.Error(), "endpoint absent") {
		t.Errorf("missing endpoint: %v", err)
	}
}

func TestEnsurePeerReportsStoreAndReloadFailures(t *testing.T) {
	ctx := context.Background()

	// A peer file that cannot be parsed stops the allocation.
	p, api, _, store := brokenProvisioner(t)
	api.endpoints["awg-in"] = endpointWith(nil)
	if err := os.WriteFile(store.Path("awg", "42.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.EnsurePeer(ctx, "awg-in", "42"); err == nil {
		t.Error("a corrupt peer file was ignored")
	}

	// The key cannot be stored: the endpoint has it, the disk does not.
	p, api, _, store = brokenProvisioner(t)
	api.endpoints["awg-in"] = endpointWith(nil)
	if err := os.Mkdir(store.Path("awg", "42.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := p.EnsurePeer(ctx, "awg-in", "42"); err == nil {
		t.Error("an unwritable peer file was reported as success")
	}

	// The apply that would bring the peer up is refused.
	p, api, rl, _ := brokenProvisioner(t)
	api.endpoints["awg-in"] = endpointWith(nil)
	rl.requested = errors.New("apply refused")
	if _, err := p.EnsurePeer(ctx, "awg-in", "42"); err == nil || !strings.Contains(err.Error(), "apply the new peer") {
		t.Errorf("reload failure: %v", err)
	}
}

func TestEnsureWDTTReportsEachSideThatFails(t *testing.T) {
	ctx := context.Background()
	ready := func(t *testing.T) (*Provisioner, *state.Store, string) {
		p, api, _, store := brokenProvisioner(t)
		api.endpoints["wg-wdtt-in"] = endpointWith(nil)
		dir := t.TempDir()
		passwords := filepath.Join(dir, "passwords.json")
		if err := os.WriteFile(passwords, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p, store, passwords
	}

	p, _, passwords := ready(t)
	if _, err := p.EnsureWDTT(ctx, "missing", "42", passwords); err == nil {
		t.Error("a missing endpoint was provisioned")
	}

	p, store, passwords := ready(t)
	if err := os.WriteFile(store.Path("wdtt", "42.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.EnsureWDTT(ctx, "wg-wdtt-in", "42", passwords); err == nil {
		t.Error("a corrupt password file was ignored")
	}

	p, store, passwords = ready(t)
	if err := os.Mkdir(store.Path("wdtt", "42.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := p.EnsureWDTT(ctx, "wg-wdtt-in", "42", passwords); err == nil {
		t.Error("a password that cannot be stored was reported as success")
	}

	p, _, _ = ready(t)
	missingDir := filepath.Join(t.TempDir(), "gone", "passwords.json")
	if _, err := p.EnsureWDTT(ctx, "wg-wdtt-in", "42", missingDir); err == nil || !strings.Contains(err.Error(), "relay config directory") {
		t.Errorf("relay directory missing: %v", err)
	}

	p, store, passwords = ready(t)
	if err := os.Mkdir(store.Path(WDTTReloadMarker), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := p.EnsureWDTT(ctx, "wg-wdtt-in", "42", passwords); err == nil || !strings.Contains(err.Error(), "signal the relay") {
		t.Errorf("marker failure: %v", err)
	}
}

type failingRegistrar struct{ err error }

func (f failingRegistrar) Register(context.Context) (json.RawMessage, error) { return nil, f.err }

func TestEnsureWARPReportsFailuresAndRegistersWhenTheCacheIsUnusable(t *testing.T) {
	ctx := context.Background()

	p, _, _, store := newTestProvisioner(t)
	if err := os.WriteFile(store.Path("warp", "42.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.EnsureWARP(ctx, "42", failingRegistrar{}); err == nil {
		t.Error("a corrupt cache was ignored")
	}

	p, _, _, _ = newTestProvisioner(t)
	if _, err := p.EnsureWARP(ctx, "42", failingRegistrar{errors.New("cloudflare says no")}); err == nil || !strings.Contains(err.Error(), "cloudflare says no") {
		t.Errorf("registration failure: %v", err)
	}

	p, _, _, store = newTestProvisioner(t)
	if err := os.Mkdir(store.Path("warp", "42.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A directory where the account should be cannot be read as a cache.
	if _, err := p.EnsureWARP(ctx, "42", failingRegistrar{}); err == nil {
		t.Error("an unreadable cache entry was ignored")
	}
}
