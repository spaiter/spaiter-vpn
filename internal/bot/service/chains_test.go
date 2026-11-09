package service

import (
	"context"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/manage"
)

// withShadowTLS adds the two inbounds the ShadowTLS chain needs to the fake core.
func withShadowTLS(s *Service, api *fakeAPI) {
	api.inbounds["shadowtls-in"] = map[string]any{
		"type": "shadowtls", "tag": "shadowtls-in", "listen_port": float64(10864),
		"detour": "ss-in", "handshake": map[string]any{"server": "www.example.org"},
	}
	api.inbounds["ss-in"] = map[string]any{
		"type": "shadowsocks", "tag": "ss-in", "listen_port": float64(0),
		"method": "2022-blake3-aes-128-gcm", "password": "backend-secret",
	}
	api.order = append(api.order, "shadowtls-in", "ss-in")
	s.cfg.Bundle.EnableChains = true
}

func TestChainsAreBuiltForAUserWhoHasBothAccounts(t *testing.T) {
	s, api, _, _, _ := newService(t)
	withShadowTLS(s, api)

	bundle, err := s.Bundle(context.Background(), "42", true)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	text := string(bundle)
	for _, needed := range []string{`"shadowtls"`, `"www.example.org"`, `backend-secret`, `"masque"`, s.cfg.NodeTags.ShadowTLS, s.cfg.NodeTags.WARP} {
		if !strings.Contains(text, needed) {
			t.Errorf("bundle is missing %s", needed)
		}
	}

	// A read-only rebuild now finds the same accounts and mints nothing.
	adds, puts := api.mutations()
	again, err := s.Bundle(context.Background(), "42", false)
	if err != nil {
		t.Fatalf("read-only Bundle: %v", err)
	}
	if a, p := api.mutations(); a != adds || p != puts {
		t.Errorf("a read-only rebuild changed the server: %d→%d accounts, %d→%d writes", adds, a, puts, p)
	}
	for _, needed := range []string{`"shadowtls"`, `"masque"`} {
		if !strings.Contains(string(again), needed) {
			t.Errorf("the read-only bundle lost %s", needed)
		}
	}
}

func TestChainsAreSkippedForAUserWithNoAccountsWhenNothingMayBeMinted(t *testing.T) {
	s, api, _, _, registrar := newService(t)
	withShadowTLS(s, api)
	bundle, err := s.Bundle(context.Background(), "nobody", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bundle), `"shadowtls"`) || strings.Contains(string(bundle), `"masque"`) {
		t.Errorf("a chain appeared for a user with nothing provisioned:\n%s", bundle)
	}
	if registrar.calls != 0 {
		t.Error("a read-only rebuild registered a WARP account")
	}
}

func TestAMissingShadowTLSBackendIsAnError(t *testing.T) {
	s, api, _, _, _ := newService(t)
	withShadowTLS(s, api)
	delete(api.inbounds, "ss-in")
	if _, err := s.Bundle(context.Background(), "42", true); err == nil {
		t.Fatal("a ShadowTLS front without its backend produced a bundle")
	}
}

func TestEndpointLabelsComeFromNodeTags(t *testing.T) {
	s, _, _, _, _ := newService(t)
	if got := s.endpointLabel(s.cfg.Tags.AWG3); got != s.cfg.NodeTags.AWG3 {
		t.Errorf("awg3 label = %q", got)
	}
	if got := s.endpointLabel(s.cfg.Tags.AWG); got != s.cfg.NodeTags.AWG {
		t.Errorf("awg label = %q", got)
	}
	if got := s.endpointLabel("something-else"); got != s.cfg.NodeTags.AWG {
		t.Errorf("unknown tag label = %q, want the AWG default", got)
	}
}

func TestUDPHostPrefersTheIPv4OnlyName(t *testing.T) {
	s, _, _, _, _ := newService(t)
	s.cfg.Public.Host, s.cfg.Public.IPv4Host = "vpn.example", ""
	if got := s.udpHost(); got != "vpn.example" {
		t.Errorf("udpHost = %q", got)
	}
	s.cfg.Public.IPv4Host = "v4.vpn.example"
	if got := s.udpHost(); got != "v4.vpn.example" {
		t.Errorf("udpHost = %q", got)
	}
}

func TestConfigStatsAndResetPassThrough(t *testing.T) {
	s, api, _, _, _ := newService(t)
	if s.Config().Public.Host != s.cfg.Public.Host {
		t.Error("Config() is not the service's configuration")
	}
	api.stats = []manage.UserStat{{User: "a", Upload: 1}, {User: "b", Download: 2}}
	all, err := s.AllStats(context.Background())
	if err != nil || len(all) != 2 {
		t.Fatalf("AllStats = %v, %v", all, err)
	}
	if err := s.ResetStats(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	if api.stats[0].Upload != 0 {
		t.Errorf("counters not reset: %+v", api.stats[0])
	}
	err = s.ResetStats(context.Background(), "ghost")
	if err == nil || !strings.Contains(err.Error(), "reset the counters of ghost") {
		t.Errorf("resetting an unknown user: %v", err)
	}
}
