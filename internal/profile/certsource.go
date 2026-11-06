package profile

import (
	"fmt"
	"strings"

	"github.com/sagernet/sing/common/json/badoption"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/option"
)

// CertSource names where Tier B's certificates come from.
//
// This is the one genuinely non-portable decision in the whole product, which
// is why it is an explicit choice rather than a default. Tier A needs an IP and
// nothing else; Tier B needs a name that resolves to this host and a
// certificate for it, and every way of obtaining one has a prerequisite the
// installer cannot conjure.
type CertSource string

const (
	// CertSourceFiles points the inbounds at certificate files somebody else
	// maintains. This is what the deployment this was modelled on does:
	// nginx-proxy-manager renews into a directory that is bind-mounted
	// read-only. It is the only mode with no prerequisite at all beyond the
	// files existing — and the only one that silently stops working, because a
	// renewal the core never notices leaves it serving an expired chain.
	CertSourceFiles CertSource = "files"

	// CertSourceACMEHTTP has the core obtain its own certificate over the
	// HTTP-01 challenge. Portable on an ordinary VPS and needs no account
	// anywhere, but it requires inbound port 80 on this host, which a
	// carrier-grade NAT or DS-Lite line does not have.
	CertSourceACMEHTTP CertSource = "acme-http"

	// CertSourceACMEDNS has the core obtain its own certificate over DNS-01.
	// The only mode that works behind NAT, because nothing has to reach the
	// host — but it needs an API token for the zone, so it trades a networking
	// prerequisite for a credential one.
	CertSourceACMEDNS CertSource = "acme-dns"
)

// ACMEDefaultDataDirectory is where the core caches its account key and
// certificates. It must be persistent: a container that loses it re-registers
// and re-issues on every restart, which is the quickest route to a Let's
// Encrypt rate limit.
const ACMEDefaultDataDirectory = "/etc/sing-box/acme"

// certProviderTag is the tag of the single shared certificate provider.
//
// Shared on purpose. Five of the six Tier B inbounds need the same certificate
// for the same name, and an inline provider per inbound would mean five
// independent ACME clients racing for the same order — five accounts' worth of
// requests against a rate limit that counts per-domain, and five copies of the
// same key on disk.
const certProviderTag = "acme"

// TLSCerts is the operator's certificate configuration for Tier B.
type TLSCerts struct {
	// Source selects the mode. Empty is rejected rather than guessed: each
	// mode fails differently, and picking one for the operator means picking
	// which failure they get.
	Source CertSource

	// CertificatePath and KeyPath are used by CertSourceFiles only.
	CertificatePath string
	KeyPath         string

	// Email is the ACME account contact. Optional at the protocol level, but
	// without it there is no expiry warning if renewal breaks.
	Email string

	// Directory is the ACME endpoint. Empty means Let's Encrypt production.
	// Point it at the staging endpoint while testing — production refuses
	// about five failed authorisations per account per hour, and a misconfigured
	// challenge burns through that in one run.
	Directory string

	// DataDirectory persists the account key and issued certificates.
	DataDirectory string

	// AlternativeHTTPPort moves the HTTP-01 listener off port 80. Only useful
	// when something in front forwards 80 here; the challenge itself is always
	// fetched on 80 by the CA.
	AlternativeHTTPPort uint16

	// DNSProvider is the DNS-01 provider: cloudflare, alidns or acmedns.
	DNSProvider string

	// CloudflareAPIToken authorises the DNS-01 record. It is written into
	// config.json, which already holds every private key in the deployment and
	// is created 0600 — but it is a credential for an account rather than for
	// this host, so its blast radius is larger than anything else in that file.
	CloudflareAPIToken string

	// ACMEDNS* configure an acme-dns server, the option that delegates
	// `_acme-challenge` to a box that only ever answers challenges, so no
	// token for the real zone has to exist here.
	ACMEDNSUsername  string
	ACMEDNSPassword  string
	ACMEDNSSubdomain string
	ACMEDNSServerURL string
}

// LetsEncryptStaging is the endpoint to use while testing a challenge setup.
const LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"

// UsesACME reports whether the core obtains the certificate itself, and
// therefore whether it keeps state that has to persist across restarts.
func (c TLSCerts) UsesACME() bool {
	return c.Source == CertSourceACMEHTTP || c.Source == CertSourceACMEDNS
}

// Validate rejects a certificate configuration whose prerequisite is absent.
//
// Every check here is a prerequisite that produces a *silent* failure if it is
// missing, not a parse error: an ACME provider with no domain starts and never
// serves TLS, and a files source with no paths starts and refuses every
// handshake.
func (c TLSCerts) validate(domain string) error {
	if domain == "" {
		return fmt.Errorf("tier %q needs a domain: five of its six protocols present a certificate, and a certificate is issued for a name", TierB)
	}
	if strings.HasPrefix(domain, "*.") {
		return fmt.Errorf("domain %q is a wildcard; only the DNS-01 challenge can validate one, and the inbounds need a concrete name to present", domain)
	}

	switch c.Source {
	case CertSourceFiles:
		if c.CertificatePath == "" || c.KeyPath == "" {
			return fmt.Errorf("certificate source %q needs both a certificate and a key path", c.Source)
		}

	case CertSourceACMEHTTP:
		// Nothing more is required, and that is the point of this mode: no
		// credential anywhere. The prerequisite is reachability on port 80,
		// which cannot be established from the spec — preflight measures it.

	case CertSourceACMEDNS:
		switch c.DNSProvider {
		case C.DNSProviderCloudflare:
			if c.CloudflareAPIToken == "" {
				return fmt.Errorf("the cloudflare DNS-01 challenge needs an API token with Zone:DNS:Edit on the zone holding %q", domain)
			}
		case C.DNSProviderACMEDNS:
			if c.ACMEDNSUsername == "" || c.ACMEDNSPassword == "" || c.ACMEDNSSubdomain == "" {
				return fmt.Errorf("the acmedns DNS-01 challenge needs a username, password and subdomain from the acme-dns registration")
			}
		case C.DNSProviderAliDNS:
			return fmt.Errorf("the alidns provider is supported by the core but not wired up here; use %q or %q", C.DNSProviderCloudflare, C.DNSProviderACMEDNS)
		case "":
			return fmt.Errorf("certificate source %q needs a DNS provider (%q or %q)", c.Source, C.DNSProviderCloudflare, C.DNSProviderACMEDNS)
		default:
			return fmt.Errorf("unknown DNS-01 provider %q", c.DNSProvider)
		}

	case "":
		return fmt.Errorf("tier %q needs a certificate source: %q (somebody else renews them), %q (the core renews them, needs inbound port 80) or %q (the core renews them, needs a zone API token)",
			TierB, CertSourceFiles, CertSourceACMEHTTP, CertSourceACMEDNS)

	default:
		return fmt.Errorf("unknown certificate source %q", c.Source)
	}
	return nil
}

// provider builds the shared certificate_providers entry, or nil for the files
// source, which needs no provider at all.
func (c TLSCerts) provider(domain string) *option.CertificateProvider {
	if !c.UsesACME() {
		return nil
	}

	dataDir := c.DataDirectory
	if dataDir == "" {
		dataDir = ACMEDefaultDataDirectory
	}

	opts := &option.ACMECertificateProviderOptions{
		Domain:        badoption.Listable[string]{domain},
		DataDirectory: dataDir,
		Email:         c.Email,
		Provider:      c.Directory,
		// ED25519 keys: the smallest handshake, and every client here is
		// a current sing-box or a browser-grade TLS stack.
		KeyType: option.ACMEKeyTypeED25519,
	}

	switch c.Source {
	case CertSourceACMEHTTP:
		// TLS-ALPN-01 is disabled rather than left on. It would have to own
		// port 443, and nothing here listens on 443 — the Tier B inbounds are
		// all on high ports. Leaving it enabled means the CA tries a challenge
		// that cannot succeed before falling back, so every issuance carries a
		// guaranteed failed authorisation against the rate limit.
		opts.DisableTLSALPNChallenge = true
		opts.AlternativeHTTPPort = c.AlternativeHTTPPort

	case CertSourceACMEDNS:
		// Both reachability challenges off: with DNS-01 configured the core
		// would otherwise still offer them, and on a NAT'd host both fail.
		opts.DisableHTTPChallenge = true
		opts.DisableTLSALPNChallenge = true

		dns := &option.ACMEProviderDNS01ChallengeOptions{Provider: c.DNSProvider}
		switch c.DNSProvider {
		case C.DNSProviderCloudflare:
			dns.CloudflareOptions = option.ACMEDNS01CloudflareOptions{APIToken: c.CloudflareAPIToken}
		case C.DNSProviderACMEDNS:
			dns.ACMEDNSOptions = option.ACMEDNS01ACMEDNSOptions{
				Username:  c.ACMEDNSUsername,
				Password:  c.ACMEDNSPassword,
				Subdomain: c.ACMEDNSSubdomain,
				ServerURL: c.ACMEDNSServerURL,
			}
		}
		opts.DNS01Challenge = dns
	}

	return &option.CertificateProvider{
		Type:    C.TypeACME,
		Tag:     certProviderTag,
		Options: opts,
	}
}

// inboundTLS builds the TLS block every certificate-bearing Tier B inbound
// shares.
//
// One function rather than a block per inbound, because five inbounds that each
// spell out their own certificate source are five places for one to be left
// behind — and an inbound still pointing at a stale path does not fail at
// startup, it fails per connection.
func (c TLSCerts) inboundTLS(domain string, alpn []string) *option.InboundTLSOptions {
	tls := &option.InboundTLSOptions{
		Enabled:    true,
		ServerName: domain,
	}
	if len(alpn) > 0 {
		tls.ALPN = alpn
	}
	if c.UsesACME() {
		// Referenced by tag, not inlined: see certProviderTag.
		tls.CertificateProvider = &option.CertificateProviderOptions{Tag: certProviderTag}
		return tls
	}
	tls.CertificatePath = c.CertificatePath
	tls.KeyPath = c.KeyPath
	return tls
}
