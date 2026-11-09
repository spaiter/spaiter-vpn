package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bot/provision"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

// fault is one injected failure: it fires on the call after skip successes.
type fault struct {
	err  error
	skip int
}

// faultAPI wraps the fake core and fails chosen calls. Keys are "Method" or
// "Method:tag"; the more specific one wins.
type faultAPI struct {
	*fakeAPI
	faults map[string]*fault
	// raw replaces what a read returns, to hand the service JSON it cannot parse.
	raw map[string]json.RawMessage
}

func (f *faultAPI) hit(method, tag string) error {
	for _, key := range []string{method + ":" + tag, method} {
		if fl, ok := f.faults[key]; ok {
			if fl.skip > 0 {
				fl.skip--
				return nil
			}
			return fl.err
		}
	}
	return nil
}

var errInjected = errors.New("injected failure")

func (f *faultAPI) Inbounds(ctx context.Context) ([]manage.InboundRef, error) {
	if err := f.hit("Inbounds", ""); err != nil {
		return nil, err
	}
	return f.fakeAPI.Inbounds(ctx)
}

func (f *faultAPI) Inbound(ctx context.Context, tag string) (json.RawMessage, error) {
	if err := f.hit("Inbound", tag); err != nil {
		return nil, err
	}
	if raw, ok := f.raw["Inbound:"+tag]; ok {
		return raw, nil
	}
	return f.fakeAPI.Inbound(ctx, tag)
}

func (f *faultAPI) Users(ctx context.Context, tag string) ([]json.RawMessage, error) {
	if err := f.hit("Users", tag); err != nil {
		return nil, err
	}
	return f.fakeAPI.Users(ctx, tag)
}

func (f *faultAPI) AddUser(ctx context.Context, tag string, user any) error {
	if err := f.hit("AddUser", tag); err != nil {
		return err
	}
	return f.fakeAPI.AddUser(ctx, tag, user)
}

func (f *faultAPI) Endpoints(ctx context.Context) ([]json.RawMessage, error) {
	if err := f.hit("Endpoints", ""); err != nil {
		return nil, err
	}
	if raw, ok := f.raw["Endpoints"]; ok {
		return []json.RawMessage{raw}, nil
	}
	return f.fakeAPI.Endpoints(ctx)
}

func (f *faultAPI) Endpoint(ctx context.Context, tag string) (json.RawMessage, error) {
	if err := f.hit("Endpoint", tag); err != nil {
		return nil, err
	}
	if raw, ok := f.raw["Endpoint:"+tag]; ok {
		return raw, nil
	}
	return f.fakeAPI.Endpoint(ctx, tag)
}

func (f *faultAPI) UserStats(ctx context.Context) ([]manage.UserStat, error) {
	if err := f.hit("UserStats", ""); err != nil {
		return nil, err
	}
	return f.fakeAPI.UserStats(ctx)
}

func (f *faultAPI) DeleteUser(ctx context.Context, tag, name string) error {
	return f.hit("DeleteUser", tag)
}

func (f *faultAPI) ResetUserStats(ctx context.Context, name string) error {
	return f.hit("ResetUserStats", "")
}

// faulty is a service whose core (and the provisioner talking to it) can be made to fail.
func faulty(t *testing.T) (*Service, *faultAPI) {
	t.Helper()
	s, api, batch, store, registrar := newService(t)
	fa := &faultAPI{fakeAPI: api, faults: map[string]*fault{}, raw: map[string]json.RawMessage{}}
	s.api = fa
	s.prov = provision.New(fa, store, batch, quiet())
	s.registrar = registrar
	return s, fa
}

func (f *faultAPI) fail(key string, skip ...int) {
	fl := &fault{err: errInjected}
	if len(skip) > 0 {
		fl.skip = skip[0]
	}
	f.faults[key] = fl
}

func TestListingFailuresAreNamed(t *testing.T) {
	ctx := context.Background()

	s, api := faulty(t)
	api.fail("Inbounds")
	if _, err := s.UserInbounds(ctx); !errors.Is(err, errInjected) || !strings.Contains(err.Error(), "list inbounds") {
		t.Errorf("Inbounds: %v", err)
	}
	if _, err := s.Accounts(ctx); !errors.Is(err, errInjected) {
		t.Errorf("Accounts over a failing listing: %v", err)
	}

	// MTProto is hidden only for the core's "does not support users"; any
	// other failure is the caller's to see.
	s, api = faulty(t)
	api.fail("Users:mtproto-in")
	if _, err := s.UserInbounds(ctx); !errors.Is(err, errInjected) || !strings.Contains(err.Error(), "users of mtproto-in") {
		t.Errorf("mtproto users: %v", err)
	}

	s, api = faulty(t)
	api.fail("Endpoints")
	if _, err := s.OfferedEndpoints(ctx); !errors.Is(err, errInjected) {
		t.Errorf("Endpoints: %v", err)
	}
	s, api = faulty(t)
	api.raw["Endpoints"] = json.RawMessage(`"junk"`)
	if _, err := s.OfferedEndpoints(ctx); err == nil || !strings.Contains(err.Error(), "parse endpoint") {
		t.Errorf("unparseable endpoint: %v", err)
	}

	s, api = faulty(t)
	api.fail("Users:vless-reality-in")
	if _, err := s.Accounts(ctx); !errors.Is(err, errInjected) || !strings.Contains(err.Error(), "users of vless-reality-in") {
		t.Errorf("Accounts users: %v", err)
	}

	s, api = faulty(t)
	api.fail("UserStats")
	if _, _, err := s.Stats(ctx, "42"); !errors.Is(err, errInjected) {
		t.Errorf("Stats: %v", err)
	}
	if _, err := s.AllStats(ctx); !errors.Is(err, errInjected) {
		t.Errorf("AllStats: %v", err)
	}

	s, api = faulty(t)
	api.fail("DeleteUser")
	if err := s.DeleteUser(ctx, "vless-reality-in", "42"); !errors.Is(err, errInjected) || !strings.Contains(err.Error(), "delete 42") {
		t.Errorf("DeleteUser: %v", err)
	}
	api.fail("ResetUserStats")
	if err := s.ResetStats(ctx, "42"); !errors.Is(err, errInjected) {
		t.Errorf("ResetStats: %v", err)
	}
}

func TestUnreadableCoreAnswersAreNamedNotSwallowed(t *testing.T) {
	ctx := context.Background()
	s, api := faulty(t)

	api.fail("Inbound:vless-reality-in")
	if _, err := s.inbound(ctx, "vless-reality-in"); !errors.Is(err, errInjected) || !strings.Contains(err.Error(), "inbound vless-reality-in") {
		t.Errorf("inbound fetch: %v", err)
	}
	delete(api.faults, "Inbound:vless-reality-in")
	api.raw["Inbound:vless-reality-in"] = json.RawMessage(`"junk"`)
	if _, err := s.inbound(ctx, "vless-reality-in"); err == nil || !strings.Contains(err.Error(), "parse inbound") {
		t.Errorf("inbound parse: %v", err)
	}

	api.fail("Endpoint:awg-in")
	if _, err := s.endpoint(ctx, "awg-in"); !errors.Is(err, errInjected) {
		t.Errorf("endpoint fetch: %v", err)
	}
	delete(api.faults, "Endpoint:awg-in")
	api.raw["Endpoint:awg-in"] = json.RawMessage(`"junk"`)
	if _, err := s.endpoint(ctx, "awg-in"); err == nil || !strings.Contains(err.Error(), "parse endpoint") {
		t.Errorf("endpoint parse: %v", err)
	}

	// existingUser: the core failing, and an account it cannot read.
	api.fail("Users:vless-reality-in")
	if _, _, err := s.existingUser(ctx, "vless-reality-in", "42"); !errors.Is(err, errInjected) {
		t.Errorf("existingUser users: %v", err)
	}
	delete(api.faults, "Users:vless-reality-in")
	api.users["vless-reality-in"] = []json.RawMessage{json.RawMessage(`{"name":"42","uuid":5}`)}
	if _, _, err := s.existingUser(ctx, "vless-reality-in", "42"); err == nil || !strings.Contains(err.Error(), "parse user") {
		t.Errorf("existingUser parse: %v", err)
	}
}

func TestConfigRenderersReportEachStepThatFails(t *testing.T) {
	ctx := context.Background()

	// Link and JSONConfig: the account cannot be provisioned.
	s, api := faulty(t)
	api.fail("AddUser:vless-reality-in")
	if _, err := s.Link(ctx, "vless-reality-in", "42"); !errors.Is(err, errInjected) {
		t.Errorf("Link: %v", err)
	}
	if _, err := s.JSONConfig(ctx, "vless-reality-in", "42"); !errors.Is(err, errInjected) {
		t.Errorf("JSONConfig: %v", err)
	}

	// ShadowTLS whose backend inbound has vanished.
	s, api = faulty(t)
	withShadowTLS(s, api.fakeAPI)
	api.fail("Inbound:ss-in")
	if _, err := s.JSONConfig(ctx, "shadowtls-in", "42"); !errors.Is(err, errInjected) {
		t.Errorf("JSONConfig shadowtls backend: %v", err)
	}

	// AWG: the peer cannot be provisioned, and the endpoint cannot be re-read.
	s, api = faulty(t)
	api.fail("Endpoint:awg-in")
	if _, err := s.AWGConf(ctx, "awg-in", "42"); !errors.Is(err, errInjected) {
		t.Errorf("AWGConf ensure: %v", err)
	}
	s, api = faulty(t)
	api.fail("Endpoint:awg-in", 1) // EnsurePeer's read succeeds, the service's own does not
	if _, err := s.AWGConf(ctx, "awg-in", "42"); !errors.Is(err, errInjected) {
		t.Errorf("AWGConf endpoint: %v", err)
	}

	// WARP: registration fails, then the inner account cannot be minted.
	s, api = faulty(t)
	s.registrar = &fakeRegistrar{err: errInjected}
	if _, err := s.WARPChainConfig(ctx, "42"); !errors.Is(err, errInjected) {
		t.Errorf("WARP registration: %v", err)
	}
	s, api = faulty(t)
	api.fail("AddUser:" + s.cfg.WARP.InnerTag)
	if _, err := s.WARPChainConfig(ctx, "42"); err == nil {
		t.Error("WARP with a failing inner account succeeded")
	}

	// WDTT: the peer fails; the hash pool is unreadable.
	s, api = faulty(t)
	api.fail("Endpoint:" + s.cfg.WDTT.Tag)
	if _, err := s.WDTTConfig(ctx, "42"); !errors.Is(err, errInjected) {
		t.Errorf("WDTT peer: %v", err)
	}
	s, _ = faulty(t)
	if err := os.WriteFile(s.store.Path("wdtt", "vk_hashes.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WDTTConfig(ctx, "42"); err == nil {
		t.Error("WDTT with an unreadable hash pool succeeded")
	}
}

func TestAccountsSkipNamelessUsersAndDeduplicate(t *testing.T) {
	s, api := faulty(t)
	api.users["vless-reality-in"] = []json.RawMessage{
		json.RawMessage(`{"name":"42"}`), json.RawMessage(`{"name":"42"}`), json.RawMessage(`{"uuid":"x"}`),
	}
	got, err := s.Accounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got["42"]) != 1 {
		t.Errorf("accounts = %v", got)
	}
}

func TestBundleBuildersReportBrokenPiecesInsteadOfDroppingThem(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name      string
		provision bool
		setup     func(s *Service, api *faultAPI)
	}{
		{"inbound detail", false, func(s *Service, api *faultAPI) {
			api.users["vless-reality-in"] = []json.RawMessage{json.RawMessage(`{"name":"42","uuid":"u"}`)}
			api.fail("Inbound:vless-reality-in")
		}},
		{"users lookup", false, func(s *Service, api *faultAPI) { api.fail("Users:hysteria-in") }},
		{"provision a user", true, func(s *Service, api *faultAPI) { api.fail("AddUser:hysteria-in") }},
		{"peer lookup", false, func(s *Service, api *faultAPI) {
			if err := s.store.SetPeer("42", s.cfg.Tags.AWG, peerFixture()); err != nil {
				t.Fatal(err)
			}
			api.fail("Endpoint:" + s.cfg.Tags.AWG)
		}},
		{"awg3 peer", true, func(s *Service, api *faultAPI) {
			s.cfg.Bundle.EnableAWG3 = true
			api.fail("Endpoint:" + s.cfg.Tags.AWG3)
		}},
		{"masque peer", true, func(s *Service, api *faultAPI) { api.fail("Endpoint:" + s.cfg.Tags.MASQUEWG) }},
		{"wdtt peer", true, func(s *Service, api *faultAPI) { api.fail("Endpoint:" + s.cfg.WDTT.Tag) }},
		{"corrupt peer file", false, func(s *Service, api *faultAPI) {
			if err := os.WriteFile(s.store.Path("awg", "42.json"), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"corrupt wdtt password", false, func(s *Service, api *faultAPI) {
			if err := os.WriteFile(s.store.Path("wdtt", "42.json"), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"chain backend", true, func(s *Service, api *faultAPI) {
			withShadowTLS(s, api.fakeAPI)
			api.fail("Inbound:ss-in")
		}},
		{"chain account", true, func(s *Service, api *faultAPI) {
			withShadowTLS(s, api.fakeAPI)
			api.fail("AddUser:shadowtls-in")
		}},
		{"corrupt warp cache", true, func(s *Service, api *faultAPI) {
			s.cfg.Bundle.EnableChains = true
			if err := os.WriteFile(s.store.Path("warp", "42.json"), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"warp inner account", true, func(s *Service, api *faultAPI) {
			s.cfg.Bundle.EnableChains = true
			api.fail("AddUser:" + s.cfg.WARP.InnerTag)
		}},
	}
	for _, c := range cases {
		s, api := faulty(t)
		c.setup(s, api)
		if _, err := s.Bundle(ctx, "42", c.provision); err == nil {
			t.Errorf("%s: the bundle was built from a broken piece", c.name)
		}
	}
}

func TestAFailedWARPRegistrationCostsOnlyThatNode(t *testing.T) {
	s, _ := faulty(t)
	s.cfg.Bundle.EnableChains = true
	s.registrar = &fakeRegistrar{err: errInjected}
	if _, err := s.Bundle(context.Background(), "42", true); err != nil {
		t.Errorf("a Cloudflare failure took the whole bundle with it: %v", err)
	}
}

func peerFixture() state.Peer {
	return state.Peer{Priv: "cHJpdg==", Pub: "cHVi", IP: "10.40.0.9"}
}

func TestNewFallsBackToTheDefaultLogger(t *testing.T) {
	s, _, batch, store, registrar := newService(t)
	rebuilt := New(s.Config(), s.api, s.prov, store, batch, registrar, nil)
	if rebuilt.log == nil {
		t.Error("no logger")
	}
}
