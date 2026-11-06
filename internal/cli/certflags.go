package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// CloudflareTokenEnv is where the DNS-01 token is read from when no file is
// given.
const CloudflareTokenEnv = "CLOUDFLARE_API_TOKEN"

// applyCertFlags fills in the Tier B certificate configuration.
//
// Tier A ignores all of it, and says so rather than silently accepting flags it
// will not use: a run with -domain and -cert-source but no -tier=ab would
// otherwise generate a config with no TLS protocols at all and report success.
func applyCertFlags(f initFlags, spec *profile.Spec) error {
	given := f.domain != "" || f.certSource != "" || f.certFile != "" || f.keyFile != "" ||
		f.acmeEmail != "" || f.dnsProvider != "" || f.cfTokenFile != "" || f.acmeStaging

	if spec.Tier != profile.TierB {
		if given {
			return fmt.Errorf("%w: the certificate flags apply to tier %q only; pass -tier=%s to generate the protocols that use them",
				ErrUsage, profile.TierB, profile.TierB)
		}
		return nil
	}

	spec.Domain = strings.TrimSpace(f.domain)
	spec.Certs = profile.TLSCerts{
		Source:              profile.CertSource(f.certSource),
		CertificatePath:     f.certFile,
		KeyPath:             f.keyFile,
		Email:               f.acmeEmail,
		Directory:           f.acmeDirectory,
		DataDirectory:       f.acmeDataDir,
		AlternativeHTTPPort: uint16(f.acmeHTTPPort),
		DNSProvider:         f.dnsProvider,
	}

	if f.acmeStaging {
		if f.acmeDirectory != "" {
			return fmt.Errorf("%w: -acme-staging and -acme-directory both set the endpoint; pass one", ErrUsage)
		}
		spec.Certs.Directory = profile.LetsEncryptStaging
	}

	if spec.Certs.Source == profile.CertSourceACMEDNS && spec.Certs.DNSProvider == "cloudflare" {
		token, err := readCloudflareToken(f.cfTokenFile)
		if err != nil {
			// preflight asks whether this host *could* run the deployment, and
			// that question does not need the credential. Demanding it here
			// would mean the operator has to produce a zone token before they
			// can find out whether the host is suitable at all.
			if f.checkOnly {
				spec.Certs.CloudflareAPIToken = checkOnlyTokenPlaceholder
				return nil
			}
			return err
		}
		spec.Certs.CloudflareAPIToken = token
	}
	return nil
}

// checkOnlyTokenPlaceholder stands in for the token during preflight so the
// spec validates. It is never written anywhere: preflight generates no config.
const checkOnlyTokenPlaceholder = "preflight-placeholder-not-a-token"

// readCloudflareToken reads the token from a file or the environment.
//
// Never from a flag value. A token passed on the command line is readable in
// `ps` by every user on the host and is written to the shell history, and this
// one can rewrite DNS for a whole zone — which is enough to issue certificates
// for every name in it.
func readCloudflareToken(path string) (string, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read -cf-token-file: %w", err)
		}
		token := strings.TrimSpace(string(data))
		if token == "" {
			return "", fmt.Errorf("%w: %s is empty", ErrUsage, path)
		}
		return token, nil
	}

	token := strings.TrimSpace(os.Getenv(CloudflareTokenEnv))
	if token == "" {
		return "", fmt.Errorf("%w: the cloudflare DNS-01 challenge needs an API token.\n\n"+
			"Set %s in the environment, or pass -cf-token-file pointing at a file holding it.\n"+
			"It is not a command-line flag on purpose: a token in argv is visible in `ps` to every\n"+
			"user on this host and is recorded in the shell history.\n\n"+
			"The token needs Zone:DNS:Edit on the zone holding the domain, and nothing else.\n"+
			"It is written into config.json, which is mode 0600 and already holds every private key\n"+
			"in the deployment — but unlike those, this credential is for an account rather than for\n"+
			"this host, so consider a token scoped to a single zone.",
			ErrUsage, CloudflareTokenEnv)
	}
	return token, nil
}
