package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withDDNS is a valid Tier A state that keeps bot.publicHost with a DDNS provider.
func withDDNS(provider, host string, mutate func(*DDNS)) State {
	s := Default([]string{"alice"})
	s.Bot.PublicHost = host
	d := &DDNS{Provider: provider, Token: "ddns-token"}
	if mutate != nil {
		mutate(d)
	}
	s.DDNS = d
	return s
}

func TestValidateDDNS(t *testing.T) {
	cases := []struct {
		name  string
		state State
		want  string // empty: valid; otherwise a substring of the error
	}{
		{"no ddns at all", Default([]string{"a"}), ""},
		{"cloudflare", withDDNS("cloudflare", "vpn.example.net", nil), ""},
		{"cloudflare with ipv6", withDDNS("cloudflare", "vpn.example.net", func(d *DDNS) { d.IPv6 = true }), ""},
		{"duckdns on its own domain", withDDNS("duckdns", "mine.duckdns.org", nil), ""},
		{"dyndns2 complete", withDDNS("dyndns2", "vpn.example.net", func(d *DDNS) {
			d.Username = "me"
			d.Server = "https://dyn.example.net/nic/update"
		}), ""},

		{"no public host", withDDNS("cloudflare", "", nil), "needs bot.publicHost"},
		{"public host is an ipv4 address", withDDNS("cloudflare", "203.0.113.7", nil), "is an address"},
		{"public host is an ipv6 address", withDDNS("cloudflare", "2001:db8::1", nil), "is an address"},
		{"token is not a logical name", withDDNS("cloudflare", "vpn.example.net", func(d *DDNS) { d.Token = "Not/A/Name" }), "ddns.token"},
		{"token missing", withDDNS("cloudflare", "vpn.example.net", func(d *DDNS) { d.Token = "" }), "ddns.token is empty"},
		{"duckdns on a foreign domain", withDDNS("duckdns", "vpn.example.net", nil), "duckdns keeps *.duckdns.org"},
		{"duckdns lookalike suffix", withDDNS("duckdns", "evilduckdns.org", nil), "duckdns keeps *.duckdns.org"},
		{"dyndns2 without a username", withDDNS("dyndns2", "vpn.example.net", func(d *DDNS) { d.Server = "https://dyn.example.net/" }), "needs ddns.username"},
		{"dyndns2 over plain http", withDDNS("dyndns2", "vpn.example.net", func(d *DDNS) {
			d.Username = "me"
			d.Server = "http://dyn.example.net/"
		}), "an https ddns.server"},
		{"dyndns2 asked for ipv6", withDDNS("dyndns2", "vpn.example.net", func(d *DDNS) {
			d.Username = "me"
			d.Server = "https://dyn.example.net/"
			d.IPv6 = true
		}), "IPv4 records only"},
		{"unknown provider", withDDNS("namecheap", "vpn.example.net", nil), `ddns.provider "namecheap"`},
		{"cloudflare given dyndns2 fields", withDDNS("cloudflare", "vpn.example.net", func(d *DDNS) { d.Username = "me" }), "are dyndns2's"},
		{"duckdns given a server", withDDNS("duckdns", "mine.duckdns.org", func(d *DDNS) { d.Server = "https://x/" }), "are dyndns2's"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDDNS(tc.state)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && err == nil:
				t.Fatalf("accepted; want an error containing %q", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// withWeb is a state with the web UI managed.
func withWeb(web *Web, manageControl bool) State {
	s := Default([]string{"alice"})
	s.Bootstrap.ManageWeb = true
	s.Bootstrap.ManageControl = manageControl
	s.Web = web
	return s
}

func TestValidateWeb(t *testing.T) {
	cases := []struct {
		name  string
		state State
		want  string
	}{
		{"unmanaged and unset", Default([]string{"a"}), ""},
		{"defaults: loopback, http", withWeb(nil, true), ""},
		{"explicit loopback port", withWeb(&Web{Listen: "127.0.0.1:9000"}, true), ""},
		{"ipv6 loopback", withWeb(&Web{Listen: "[::1]:9000"}, true), ""},
		{"public listen behind https", withWeb(&Web{Listen: "0.0.0.0:9000", PublicURL: "https://vpn.example.net/ui"}, true), ""},
		{"loopback with a public https url", withWeb(&Web{PublicURL: "https://vpn.example.net"}, true), ""},

		{"web set but not managed", func() State { s := Default([]string{"a"}); s.Web = &Web{}; return s }(), "manageWeb is false"},
		{"web needs the control daemon", withWeb(nil, false), "needs bootstrap.manageControl"},
		{"listen without a port", withWeb(&Web{Listen: "127.0.0.1"}, true), "is not host:port"},
		{"listen with an empty port", withWeb(&Web{Listen: "127.0.0.1:"}, true), "is not host:port"},
		{"public url with a bad scheme", withWeb(&Web{PublicURL: "ftp://vpn.example.net"}, true), "must be an http(s) URL"},
		{"public url without a host", withWeb(&Web{PublicURL: "https://"}, true), "must be an http(s) URL"},
		{"public url with credentials", withWeb(&Web{PublicURL: "https://user:pw@vpn.example.net"}, true), "must be an http(s) URL"},
		{"public url with a query", withWeb(&Web{PublicURL: "https://vpn.example.net/?token=1"}, true), "must be an http(s) URL"},
		{"exposed listen with the default url", withWeb(&Web{Listen: "0.0.0.0:9000"}, true), "must be an https:// address"},
		{"exposed listen with an http url", withWeb(&Web{Listen: "0.0.0.0:9000", PublicURL: "http://vpn.example.net"}, true), "must be an https:// address"},
		{"hostname listen counts as exposed", withWeb(&Web{Listen: "localhost:9000"}, true), "must be an https:// address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWeb(tc.state)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && err == nil:
				t.Fatalf("accepted; want an error containing %q", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestWebListenAndURLResolveTheirDefaults(t *testing.T) {
	var s State
	if got := s.WebListen(); got != DefaultWebListen {
		t.Fatalf("WebListen() = %q, want the loopback default %q", got, DefaultWebListen)
	}
	if got := s.WebURL(); got != "http://"+DefaultWebListen {
		t.Fatalf("WebURL() = %q", got)
	}
	// An empty Web block changes nothing.
	s.Web = &Web{}
	if s.WebListen() != DefaultWebListen || s.WebURL() != "http://"+DefaultWebListen {
		t.Fatalf("an empty Web block must keep the defaults: %q %q", s.WebListen(), s.WebURL())
	}
	s.Web = &Web{Listen: "127.0.0.1:9000"}
	if s.WebListen() != "127.0.0.1:9000" || s.WebURL() != "http://127.0.0.1:9000" {
		t.Fatalf("a custom listen must flow into the default URL: %q %q", s.WebListen(), s.WebURL())
	}
	s.Web.PublicURL = "https://vpn.example.net"
	if s.WebListen() != "127.0.0.1:9000" || s.WebURL() != "https://vpn.example.net" {
		t.Fatalf("publicUrl overrides only the URL: %q %q", s.WebListen(), s.WebURL())
	}
}

func TestLoadReadsADocumentFromDiskAndNamesAMissingFile(t *testing.T) {
	want := Default([]string{"alice", "bob"})
	data, err := want.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "desired.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, _ := want.Digest()
	if gotDigest, _ := got.Digest(); gotDigest != wantDigest {
		t.Fatalf("Load changed the document: %s != %s", gotDigest, wantDigest)
	}

	missing := filepath.Join(t.TempDir(), "absent.json")
	_, err = Load(missing)
	if err == nil || !strings.Contains(err.Error(), missing) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a missing file must be reported with its path and stay detectable: %v", err)
	}

	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("a malformed document was accepted")
	}
}

func TestSpecsRefuseWhatGenerationWouldGetWrong(t *testing.T) {
	s := Default([]string{"alice"})
	resolve := func(SecretRef) (string, error) { return "real-secret", nil }

	if _, err := s.DeploymentSpec(nil, nil); err == nil || !strings.Contains(err.Error(), "credential resolver") {
		t.Fatalf("DeploymentSpec without a resolver must be refused: %v", err)
	}
	spec, err := s.DeploymentSpec([]string{"eth0"}, resolve)
	if err != nil {
		t.Fatal(err)
	}
	// "auto" is replaced by what discovery found, so the blocker attaches to the
	// interface that carries traffic.
	if len(spec.XDPInterfaces) != 1 || spec.XDPInterfaces[0] != "eth0" {
		t.Fatalf("XDPInterfaces = %v, want [eth0]", spec.XDPInterfaces)
	}
	// An empty discovery result must leave it empty, not fall back to a guess.
	spec, err = s.PreflightSpec(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.XDPInterfaces) != 0 {
		t.Fatalf("XDPInterfaces = %v, want none when discovery found nothing", spec.XDPInterfaces)
	}
	spec, err = s.PreflightSpec([]string{"ens3"})
	if err != nil || len(spec.XDPInterfaces) != 1 || spec.XDPInterfaces[0] != "ens3" {
		t.Fatalf("PreflightSpec = %v, %v", spec.XDPInterfaces, err)
	}

	// An explicit interface list is the operator's word and is not replaced.
	s.Deployment.XDPInterfaces = []string{"eth9"}
	spec, err = s.DeploymentSpec([]string{"eth0"}, resolve)
	if err != nil || len(spec.XDPInterfaces) != 1 || spec.XDPInterfaces[0] != "eth9" {
		t.Fatalf("explicit XDP interface overridden: %v, %v", spec.XDPInterfaces, err)
	}
}

func TestCertificatesAreRefusedWhereNothingNeedsThem(t *testing.T) {
	resolve := func(SecretRef) (string, error) { return "x", nil }

	// Tier A runs no protocol that presents a certificate, so a domain or a
	// certificate block there is configuration that would silently do nothing.
	withDomain := Default([]string{"alice"})
	withDomain.Deployment.Domain = "vpn.example.net"
	if _, err := withDomain.DeploymentSpec(nil, resolve); err == nil || !strings.Contains(err.Error(), "deployment.domain is set but no enabled protocol needs a certificate") {
		t.Fatalf("a domain with nothing to certify must be refused, got: %v", err)
	}

	withCertificates := Default([]string{"alice"})
	withCertificates.Deployment.Certificates = &Certificates{}
	if _, err := withCertificates.DeploymentSpec(nil, resolve); err == nil || !strings.Contains(err.Error(), "deployment.certificates is set but no enabled protocol needs a certificate") {
		t.Fatalf("certificates with nothing to certify must be refused, got: %v", err)
	}
}
