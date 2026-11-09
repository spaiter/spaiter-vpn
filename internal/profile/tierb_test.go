package profile_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/config"
	"github.com/spaiter/spaiter-vpn/internal/profile"
	"github.com/spaiter/spaiter-vpn/internal/singbox"
)

// tierBSpec builds a Tier B spec for the given certificate source.
func tierBSpec(source profile.CertSource) profile.Spec {
	spec := profile.Defaults([]string{"alice", "bob", "carol"})
	spec.Tier = profile.TierB
	spec.XDPInterfaces = []string{"eth0"}
	spec.Domain = "vpn.example.com"
	spec.Certs.Source = source
	switch source {
	case profile.CertSourceFiles:
		spec.Certs.CertificatePath = "/etc/certs/live/example/fullchain.pem"
		spec.Certs.KeyPath = "/etc/certs/live/example/privkey.pem"
	case profile.CertSourceACMEHTTP:
		spec.Certs.Email = "ops@example.com"
	case profile.CertSourceACMEDNS:
		spec.Certs.Email = "ops@example.com"
		spec.Certs.DNSProvider = "cloudflare"
		spec.Certs.CloudflareAPIToken = "test-token-not-a-real-credential"
	}
	return spec
}

// TestTierBPassesSingBoxCheck is the only thing that actually proves the Tier B
// shapes are right. Three sources, because they produce three different
// configs: one with certificate paths, and two with a certificate provider
// whose challenge options differ.
//
// ACME is checked, not exercised. `sing-box check` parses and validates without
// opening a listener or contacting a CA, which is exactly the property wanted
// here — a test that performed real issuance would burn a rate limit per run.
func TestTierBPassesSingBoxCheck(t *testing.T) {
	ctx := context.Background()

	checker, err := singbox.Detect(ctx, "", "")
	if err != nil {
		if errors.Is(err, singbox.ErrUnavailable) {
			t.Skipf("no sing-box checker available (%v)", err)
		}
		t.Fatalf("detect checker: %v", err)
	}
	t.Logf("checking with: %s", checker.Describe())

	// The ACME sources are checkable outright: `check` validates the options
	// without opening a listener or contacting a CA.
	for _, source := range []profile.CertSource{
		profile.CertSourceACMEHTTP,
		profile.CertSourceACMEDNS,
	} {
		t.Run(string(source), func(t *testing.T) {
			bundle, err := profile.Generate(tierBSpec(source))
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			data, err := config.Marshal(ctx, bundle.Options)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := checker.Check(ctx, data); err != nil {
				t.Fatalf("sing-box check rejected a Tier B config with source %q: %v\n\nconfig:\n%s", source, err, data)
			}
		})
	}

	// The files source is different, and the difference is the point.
	//
	// `check` does not merely parse the paths — it reads the certificate. So a
	// generated files-mode config cannot be validated before the certificate
	// exists where the config says it does, and the failure names the missing
	// file. That is a property worth depending on rather than working around:
	// it is what lets preflight tell an operator their bind mount is wrong
	// before the service is started, instead of after every handshake fails.
	t.Run("files is rejected while the certificate is absent", func(t *testing.T) {
		bundle, err := profile.Generate(tierBSpec(profile.CertSourceFiles))
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		data, err := config.Marshal(ctx, bundle.Options)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		err = checker.Check(ctx, data)
		if err == nil {
			t.Fatal("check accepted a config pointing at a certificate that does not exist; preflight's file checks are then the only thing catching a bad mount")
		}
		var checkErr *singbox.CheckError
		if !errors.As(err, &checkErr) {
			t.Fatalf("expected the checker to run and refuse, got: %v", err)
		}
		if !strings.Contains(checkErr.Output, "fullchain.pem") {
			t.Errorf("the refusal does not name the missing file, so it does not help an operator:\n%s", checkErr.Output)
		}
	})
}

// TestTierBGeneratesEverySixAndOneSharedProvider checks the structure without
// the binary.
func TestTierBGeneratesEveryProtocolAndOneSharedProvider(t *testing.T) {
	bundle, err := profile.Generate(tierBSpec(profile.CertSourceACMEDNS))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	tags := map[string]bool{}
	for _, in := range bundle.Options.Inbounds {
		tags[in.Tag] = true
	}
	for _, p := range profile.TierBProtocols {
		if !tags[string(p)] {
			t.Errorf("tier B protocol %s was not generated", p)
		}
	}
	// Tier B is additive: Tier A must still be there in full.
	for _, p := range profile.TierAProtocols {
		if p.IsWireGuard() {
			continue
		}
		if !tags[string(p)] {
			t.Errorf("tier A protocol %s went missing when tier B was selected", p)
		}
	}

	// One provider, not five. Five would mean five ACME clients racing for the
	// same order against a per-domain rate limit.
	if len(bundle.Options.CertificateProviders) != 1 {
		t.Fatalf("got %d certificate providers, want exactly 1 shared one", len(bundle.Options.CertificateProviders))
	}
	if bundle.Options.CertificateProviders[0].Type != "acme" {
		t.Errorf("provider type is %q, want acme", bundle.Options.CertificateProviders[0].Type)
	}
}

// TestTierBInboundsReferenceTheProviderRatherThanInliningIt inspects the
// marshalled JSON, because the agreement being checked is a tag reference
// resolving to a declared provider — something the Go structs cannot express
// and only the serialised form shows.
//
// This test is the *only* pre-start guard on that reference, which is why it
// asserts the resolution rather than merely the presence of a tag. Measured:
// `sing-box check` accepts a config whose inbounds all point at a provider tag
// nobody declared, and exits 0. The core resolves the tag in Start(), where a
// miss is a loud `certificate provider not found: <tag>` — so the deployment
// fails at startup rather than silently, but no amount of checking catches it
// beforehand. The generator's defence is structural: every reference and the
// declaration come from the one certProviderTag constant.
func TestTierBInboundsReferenceTheProviderRatherThanInliningIt(t *testing.T) {
	ctx := context.Background()
	bundle, err := profile.Generate(tierBSpec(profile.CertSourceACMEHTTP))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	data, err := config.Marshal(ctx, bundle.Options)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var doc struct {
		CertificateProviders []struct {
			Tag  string `json:"tag"`
			Type string `json:"type"`
		} `json:"certificate_providers"`
		Inbounds []struct {
			Tag string `json:"tag"`
			TLS *struct {
				ServerName          string          `json:"server_name"`
				CertificateProvider json.RawMessage `json:"certificate_provider"`
				CertificatePath     string          `json:"certificate_path"`
				Reality             json.RawMessage `json:"reality"`
				// Raw, because a single-element Listable marshals as a bare
				// string rather than an array.
				ALPN json.RawMessage `json:"alpn"`
			} `json:"tls"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.CertificateProviders) != 1 {
		t.Fatalf("want one declared provider, got %d", len(doc.CertificateProviders))
	}
	declared := doc.CertificateProviders[0].Tag

	seen := 0
	for _, in := range doc.Inbounds {
		p := profile.Protocol(in.Tag)
		if !p.NeedsCertificate() {
			continue
		}
		seen++
		if in.TLS == nil {
			t.Errorf("%s needs a certificate but has no tls block", in.Tag)
			continue
		}
		var tag string
		if err := json.Unmarshal(in.TLS.CertificateProvider, &tag); err != nil {
			t.Errorf("%s: certificate_provider is not a tag reference: %s", in.Tag, in.TLS.CertificateProvider)
			continue
		}
		if tag != declared {
			t.Errorf("%s references provider %q, but the declared one is %q", in.Tag, tag, declared)
		}
		if in.TLS.ServerName != "vpn.example.com" {
			t.Errorf("%s presents server_name %q, want the domain", in.Tag, in.TLS.ServerName)
		}
		if in.TLS.CertificatePath != "" {
			t.Errorf("%s carries both a provider and a certificate path", in.Tag)
		}
	}
	if seen != 5 {
		t.Errorf("checked %d certificate-bearing inbounds, want 5", seen)
	}

	// And the sixth: vless-xhttp must have Reality and no certificate at all.
	for _, in := range doc.Inbounds {
		if in.Tag != string(profile.VLESSXHTTP) {
			continue
		}
		if in.TLS == nil || len(in.TLS.Reality) == 0 {
			t.Errorf("%s has no reality block; it has no certificate, so reality is the only thing securing it", in.Tag)
		}
		if in.TLS != nil && len(in.TLS.CertificateProvider) > 0 {
			t.Errorf("%s consumes the ACME certificate it does not need", in.Tag)
		}
		if in.TLS != nil && in.TLS.ServerName == "vpn.example.com" {
			t.Errorf("%s presents the real domain as SNI; Reality must present the borrowed host instead, or the forwarded handshake goes to the wrong place", in.Tag)
		}
	}
}

// TestXHTTPRealityKeyDiffersFromTheOtherReality guards against the convenient
// shortcut of reusing one keypair. Two inbounds sharing a Reality private key
// means one leak deanonymises both.
func TestXHTTPRealityKeyDiffersFromTheOtherReality(t *testing.T) {
	bundle, err := profile.Generate(tierBSpec(profile.CertSourceFiles))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	a := bundle.Secrets.Reality
	b := bundle.Secrets.TierB.XHTTPReality
	if a.PrivateKey == "" || b.PrivateKey == "" {
		t.Fatal("one of the two Reality keypairs was never generated")
	}
	if a.PrivateKey == b.PrivateKey {
		t.Error("vless-reality and vless-xhttp share a Reality private key")
	}
	if a.ShortID == b.ShortID {
		t.Error("the two Reality inbounds share a short_id")
	}
}

// TestTierBSecretsCoverEveryUser catches a per-user loop that generated one
// credential and handed it to everybody — which would authenticate fine and
// make the per-user traffic accounting meaningless.
func TestTierBSecretsCoverEveryUser(t *testing.T) {
	bundle, err := profile.Generate(tierBSpec(profile.CertSourceFiles))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	seen := map[string]string{}
	for _, u := range bundle.Secrets.Users {
		for field, value := range map[string]string{
			"hysteria2": u.Hysteria2Password,
			"tuic-uuid": u.TUICUUID,
			"tuic-pass": u.TUICPassword,
			"anytls":    u.AnyTLSPassword,
			"naive":     u.NaivePassword,
			"xhttp":     u.VLESSXHTTPUUID,
		} {
			if value == "" {
				t.Errorf("%s has no %s credential", u.Name, field)
				continue
			}
			key := field + "\x00" + value
			if other, dup := seen[key]; dup {
				t.Errorf("%s and %s share the same %s credential", other, u.Name, field)
			}
			seen[key] = u.Name
		}
	}
}

// TestTierBValidationRefusesMissingPrerequisites. Each of these produces a
// config the core accepts and that then fails per-connection, which is the
// class of mistake Validate exists for.
func TestTierBValidationRefusesMissingPrerequisites(t *testing.T) {
	cases := map[string]struct {
		mutate func(*profile.Spec)
		want   string
	}{
		"no certificate source": {
			func(s *profile.Spec) { s.Certs.Source = "" },
			"certificate source",
		},
		"no domain": {
			func(s *profile.Spec) { s.Domain = "" },
			"needs a domain",
		},
		"wildcard domain": {
			func(s *profile.Spec) { s.Domain = "*.example.com" },
			"wildcard",
		},
		"files with no paths": {
			func(s *profile.Spec) {
				s.Certs.Source = profile.CertSourceFiles
				s.Certs.CertificatePath, s.Certs.KeyPath = "", ""
			},
			"certificate and a key path",
		},
		"dns-01 with no provider": {
			func(s *profile.Spec) {
				s.Certs.Source = profile.CertSourceACMEDNS
				s.Certs.DNSProvider = ""
			},
			"DNS provider",
		},
		"cloudflare with no token": {
			func(s *profile.Spec) {
				s.Certs.Source = profile.CertSourceACMEDNS
				s.Certs.DNSProvider = "cloudflare"
				s.Certs.CloudflareAPIToken = ""
			},
			"API token",
		},
		"masque front without its endpoint": {
			func(s *profile.Spec) {
				s.Enabled = map[profile.Protocol]bool{}
				for _, p := range s.TierProtocols() {
					s.Enabled[p] = true
				}
				s.Enabled[profile.WGMasque] = false
			},
			"forwards into",
		},
		"tier B protocol selected under tier A": {
			func(s *profile.Spec) {
				s.Tier = profile.TierA
				s.Enabled = map[profile.Protocol]bool{profile.Hysteria2: true}
			},
			"belongs to tier",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			spec := tierBSpec(profile.CertSourceACMEDNS)
			tc.mutate(&spec)
			err := spec.Validate()
			if err == nil {
				t.Fatalf("Validate accepted a spec with %s", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}

	// The baselines must pass, or every case above is vacuous.
	for _, source := range []profile.CertSource{
		profile.CertSourceFiles, profile.CertSourceACMEHTTP, profile.CertSourceACMEDNS,
	} {
		if err := tierBSpec(source).Validate(); err != nil {
			t.Fatalf("the baseline %q spec does not validate: %v", source, err)
		}
	}
}

// TestXHTTPAloneNeedsNoDomain is the consequence of drawing the line at
// NeedsCertificate rather than at the tier. The plan lists vless-xhttp under
// "needs a domain and ACME", but it runs Reality and needs neither — so an
// operator with only an IP can still have it.
func TestXHTTPAloneNeedsNoDomain(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	spec.Enabled = map[profile.Protocol]bool{profile.VLESSXHTTP: true}
	if err := spec.Validate(); err != nil {
		t.Fatalf("vless-xhttp was refused without a domain, but it presents no certificate: %v", err)
	}

	bundle, err := profile.Generate(spec)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(bundle.Options.CertificateProviders) != 0 {
		t.Error("an ACME provider was declared for a config that needs no certificate")
	}
}

// A server without a domain gets XHTTP, and lists it first: clients that pick
// by hand, or take the first node, take the one that survives Russian mobile
// networks rather than Reality over h2, whose long streams are cut there.
func TestTierALeadsWithXHTTP(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	spec.XDPInterfaces = []string{"eth0"}
	if spec.Tier != profile.TierA {
		t.Fatalf("defaults are tier %q", spec.Tier)
	}
	bundle, err := profile.Generate(spec)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if got := bundle.Options.Inbounds[0].Tag; got != string(profile.VLESSXHTTP) {
		t.Fatalf("first inbound is %s, want %s", got, profile.VLESSXHTTP)
	}

	// Its path in the secrets must not bring the deployment back as Tier B:
	// that would make every certificate protocol a candidate again.
	recovered, err := profile.SpecFromSecrets(bundle.Secrets)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if recovered.Tier != profile.TierA {
		t.Errorf("recovered as tier %q", recovered.Tier)
	}
	if !slices.Contains(recovered.EnabledProtocols(), profile.VLESSXHTTP) {
		t.Error("vless-xhttp is not among the recovered deployment's protocols")
	}
}
