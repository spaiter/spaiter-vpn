package profile

import (
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestCertificateSourcesNameEachMissingPrerequisite(t *testing.T) {
	cases := map[string]struct {
		certs  TLSCerts
		domain string
		want   string
	}{
		"acme-dns without its registration": {TLSCerts{Source: CertSourceACMEDNS, DNSProvider: C.DNSProviderACMEDNS, ACMEDNSUsername: "u"}, "example.net", "username, password and subdomain"},
		"alidns is not wired":               {TLSCerts{Source: CertSourceACMEDNS, DNSProvider: C.DNSProviderAliDNS}, "example.net", "not wired up"},
		"an unknown DNS provider":           {TLSCerts{Source: CertSourceACMEDNS, DNSProvider: "route53"}, "example.net", "unknown DNS-01 provider"},
		"an unknown source":                 {TLSCerts{Source: "carrier-pigeon"}, "example.net", "unknown certificate source"},
	}
	for name, tc := range cases {
		if err := tc.certs.validate(tc.domain); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	complete := TLSCerts{Source: CertSourceACMEDNS, DNSProvider: C.DNSProviderACMEDNS, ACMEDNSUsername: "u", ACMEDNSPassword: "p", ACMEDNSSubdomain: "s"}
	if err := complete.validate("example.net"); err != nil {
		t.Errorf("a complete acme-dns registration: %v", err)
	}
}

func TestACMEDNSProviderCarriesTheRegistrationAndDisablesReachabilityChallenges(t *testing.T) {
	certs := TLSCerts{
		Source: CertSourceACMEDNS, DNSProvider: C.DNSProviderACMEDNS,
		ACMEDNSUsername: "u", ACMEDNSPassword: "p", ACMEDNSSubdomain: "s", ACMEDNSServerURL: "https://acme-dns.example.net",
	}
	provider := certs.provider("vpn.example.net")
	if provider == nil {
		t.Fatal("no provider for an ACME source")
	}
	opts := provider.Options.(*option.ACMECertificateProviderOptions)
	dns := opts.DNS01Challenge
	if dns == nil || dns.ACMEDNSOptions.Username != "u" || dns.ACMEDNSOptions.Subdomain != "s" || dns.ACMEDNSOptions.ServerURL != "https://acme-dns.example.net" {
		t.Errorf("dns = %+v", dns)
	}
	if !opts.DisableHTTPChallenge || !opts.DisableTLSALPNChallenge {
		t.Error("a DNS-01 source left a reachability challenge on")
	}
}
