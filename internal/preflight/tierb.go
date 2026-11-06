package preflight

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// certExpiryWarning is how close to expiry a certificate may be before it is
// worth saying something. Let's Encrypt renews at 30 days, so anything inside
// that window means renewal has already missed at least one attempt.
const certExpiryWarning = 20 * 24 * time.Hour

// resolveHost is indirected so the domain check can be tested. Like the IPv6
// checks, its whole value is catching a condition that leaves no other trace,
// so a version that only ever passes on this host proves nothing.
var resolveHost = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// checkTierB adds the checks that only a Tier B deployment needs.
//
// Every one of these guards a failure that is invisible from the logs. A domain
// that does not resolve, a challenge whose port is unreachable, a certificate
// that expired last week: in all three cases the core starts, reports nothing
// unusual, and refuses every TLS handshake. Tier A has no equivalent, which is
// why it is the honest one-click tier.
func checkTierB(ctx context.Context, opts Options) []Check {
	spec := opts.Spec
	if spec.Tier != profile.TierB {
		return nil
	}

	var needsCert bool
	for _, p := range spec.EnabledProtocols() {
		if p.NeedsCertificate() {
			needsCert = true
			break
		}
	}
	if !needsCert {
		// Legitimate: vless-xhttp runs Reality and presents no certificate, so
		// a Tier B deployment of it alone has none of these prerequisites.
		return []Check{{
			Name:     "tier B certificates",
			Severity: Pass,
			Detail:   "no enabled protocol presents a certificate, so no domain is needed",
		}}
	}

	checks := []Check{checkDomainResolves(ctx, spec.Domain)}

	switch spec.Certs.Source {
	case profile.CertSourceFiles:
		checks = append(checks, checkCertificateFile(spec.Certs.CertificatePath, spec.Domain))
		checks = append(checks, checkKeyFile(spec.Certs.KeyPath))
		checks = append(checks, Check{
			Name:     "certificate renewal",
			Severity: Warn,
			Detail:   "certificates come from files this deployment does not manage",
			Remedy: "Whatever renews them must also make the core reload: it caches the chain it read at startup, " +
				"so a renewal it never hears about leaves it serving the old one until expiry. " +
				"Either reload after renewal, or switch to --cert-source=" + string(profile.CertSourceACMEDNS) + ".",
		})

	case profile.CertSourceACMEHTTP:
		checks = append(checks, checkHTTPChallengePort(spec))

	case profile.CertSourceACMEDNS:
		checks = append(checks, Check{
			Name:     "ACME challenge",
			Severity: Pass,
			Detail:   fmt.Sprintf("DNS-01 via %s; nothing has to reach this host", spec.Certs.DNSProvider),
		})
	}

	if spec.Certs.UsesACME() {
		checks = append(checks, checkACMEDataDirectory(spec))
	}
	return checks
}

// checkDomainResolves is the first thing to get wrong and the last thing anyone
// suspects.
func checkDomainResolves(ctx context.Context, domain string) Check {
	const name = "domain resolves"
	if domain == "" {
		return Check{Name: name, Severity: Fail, Detail: "no domain configured", Remedy: "Pass --domain."}
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	addrs, err := resolveHost(ctx, domain)
	if err != nil {
		return Check{
			Name:     name,
			Severity: Fail,
			Detail:   fmt.Sprintf("%s does not resolve: %v", domain, err),
			Remedy: "Create an A or AAAA record for " + domain + " pointing at this host. " +
				"ACME validates the name, and even with external certificates a client that cannot resolve it cannot connect.",
		}
	}
	if len(addrs) == 0 {
		return Check{Name: name, Severity: Fail, Detail: domain + " resolves to no addresses", Remedy: "Create an A or AAAA record for " + domain + "."}
	}

	// Deliberately not compared against this host's addresses. Behind NAT the
	// public address is not on any local interface, so a mismatch is the normal
	// case here and reporting it as a problem would be noise — which is how a
	// check teaches people to ignore it.
	texts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		texts = append(texts, a.String())
	}
	return Check{Name: name, Severity: Pass, Detail: fmt.Sprintf("%s → %s", domain, strings.Join(texts, ", "))}
}

// checkHTTPChallengePort tests the one prerequisite of HTTP-01 that cannot be
// read from the spec.
//
// It binds rather than probes from outside. A successful bind proves only that
// nothing local holds the port — it says nothing about whether the CA can reach
// it — so the result is Unknown rather than Pass. Claiming Pass here would be
// the worst outcome: a green check in front of the exact failure this mode has
// on a NAT'd line.
func checkHTTPChallengePort(spec profile.Spec) Check {
	const name = "HTTP-01 challenge port"
	port := spec.Certs.AlternativeHTTPPort
	if port == 0 {
		port = 80
	}

	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return Check{
			Name:     name,
			Severity: Fail,
			Detail:   fmt.Sprintf("cannot bind port %d: %v", port, err),
			Remedy: fmt.Sprintf("Free port %d, or move the challenge with --acme-http-port and forward %d to it, "+
				"or use --cert-source=%s instead.", port, port, profile.CertSourceACMEDNS),
		}
	}
	ln.Close()

	return Check{
		Name:     name,
		Severity: Unknown,
		Detail:   fmt.Sprintf("port %d is free locally, but whether the CA can reach it from the internet cannot be tested from here", port),
		Remedy: "The CA always fetches the challenge on port 80 of the domain, following redirects. " +
			"Behind carrier-grade NAT or DS-Lite there is no inbound 80 and HTTP-01 cannot work — use --cert-source=" +
			string(profile.CertSourceACMEDNS) + ". Test against " + profile.LetsEncryptStaging +
			" first: production refuses roughly five failed authorisations per account per hour.",
	}
}

// checkCertificateFile reads the certificate the way the core will.
func checkCertificateFile(path, domain string) Check {
	const name = "certificate file"
	if path == "" {
		return Check{Name: name, Severity: Fail, Detail: "no certificate path configured", Remedy: "Pass --cert-file."}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Check{
			Name:     name,
			Severity: Fail,
			Detail:   fmt.Sprintf("cannot read %s: %v", path, err),
			Remedy: "The core reads this file at startup and refuses to start without it. " +
				"If it exists on the host, check that the bind mount puts it at this path inside the container.",
		}
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return Check{Name: name, Severity: Fail, Detail: path + " is not PEM", Remedy: "Point --cert-file at a PEM certificate chain (fullchain.pem)."}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Check{Name: name, Severity: Fail, Detail: fmt.Sprintf("cannot parse %s: %v", path, err)}
	}

	if err := cert.VerifyHostname(domain); err != nil {
		return Check{
			Name:     name,
			Severity: Fail,
			Detail:   fmt.Sprintf("%s is not valid for %s (subject %s)", path, domain, cert.Subject.CommonName),
			Remedy: "The inbounds present this certificate for " + domain + ", so a client validating the name will reject it. " +
				"Issue a certificate covering " + domain + ", or set --domain to a name this certificate covers.",
		}
	}

	left := time.Until(cert.NotAfter)
	switch {
	case left <= 0:
		return Check{
			Name:     name,
			Severity: Fail,
			Detail:   fmt.Sprintf("%s expired %s ago", path, (-left).Round(time.Hour)),
			Remedy:   "Renew it. Every TLS client will refuse this certificate, and the core logs nothing about why handshakes fail.",
		}
	case left < certExpiryWarning:
		return Check{
			Name:     name,
			Severity: Warn,
			Detail:   fmt.Sprintf("%s expires in %s", path, left.Round(time.Hour)),
			Remedy:   "Renewal normally happens 30 days out, so being inside this window means it has already failed at least once.",
		}
	}
	return Check{
		Name:     name,
		Severity: Pass,
		Detail:   fmt.Sprintf("valid for %s until %s", domain, cert.NotAfter.Format("2006-01-02")),
	}
}

// checkKeyFile checks readability and permissions, not content: parsing a
// private key to confirm it matches would mean loading it, and this process has
// no reason to hold one.
func checkKeyFile(path string) Check {
	const name = "certificate key"
	if path == "" {
		return Check{Name: name, Severity: Fail, Detail: "no key path configured", Remedy: "Pass --key-file."}
	}
	info, err := os.Stat(path)
	if err != nil {
		return Check{
			Name:     name,
			Severity: Fail,
			Detail:   fmt.Sprintf("cannot stat %s: %v", path, err),
			Remedy:   "The core reads this at startup and refuses to start without it.",
		}
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		// Whether the permissive mode is actually exploitable depends on
		// whether an unprivileged user can traverse to the file at all, and
		// saying "anyone on this host can impersonate your server" when a
		// parent directory forbids the path is how a report gets ignored.
		// Measured on the deployment this was modelled on: the key is mode
		// 0654, every directory under it is world-traversable, and it is still
		// unreadable because one ancestor is 0750.
		detail := fmt.Sprintf("%s is mode %04o", path, mode)
		remedy := "chmod 600. certbot writes 0600 by default, so a wider mode here was set by something else and will be set again."
		if blocker := firstUntraversableAncestor(path); blocker != "" {
			detail += fmt.Sprintf(", though %s currently blocks other users from reaching it", blocker)
			remedy = "Not reachable by other users today, but the file mode is the only thing that would protect it if " +
				blocker + " were ever widened. " + remedy
		} else {
			detail += ", and every directory above it is traversable, so other local users can read it"
			remedy = "A local user can read this key and impersonate the server with it. " + remedy
		}
		return Check{Name: name, Severity: Warn, Detail: detail, Remedy: remedy}
	}
	return Check{Name: name, Severity: Pass, Detail: fmt.Sprintf("%s is readable and mode %04o", path, info.Mode().Perm())}
}

// checkACMEDataDirectory guards the mistake with the longest consequence.
func checkACMEDataDirectory(spec profile.Spec) Check {
	const name = "ACME data directory"
	dir := spec.Certs.DataDirectory
	if dir == "" {
		dir = profile.ACMEDefaultDataDirectory
	}

	switch info, err := os.Stat(dir); {
	case err == nil && !info.IsDir():
		return Check{Name: name, Severity: Fail, Detail: dir + " exists and is not a directory"}
	case err == nil:
		return Check{Name: name, Severity: Pass, Detail: dir + " exists"}
	case os.IsNotExist(err):
		// Not a failure: the core creates it. The point of the check is the
		// remedy, because the directory being created is not the same as it
		// surviving.
		return Check{
			Name:     name,
			Severity: Warn,
			Detail:   dir + " does not exist yet; the core will create it",
			Remedy: "It must be on a persistent volume. A container that loses it re-registers an ACME account and " +
				"re-issues on every restart, which reaches Let's Encrypt's duplicate-certificate limit (5 per week) " +
				"after five restarts — and then there is no certificate at all until the window rolls over.",
		}
	default:
		return Check{Name: name, Severity: Unknown, Detail: fmt.Sprintf("cannot stat %s: %v", dir, err)}
	}
}

// firstUntraversableAncestor returns the nearest directory above path that
// other users cannot enter, or "" if the whole path is traversable by anyone.
//
// Only the "other" execute bit is considered. Group permissions would need the
// group membership of whoever we are worried about, which is not knowable here
// — so this errs towards reporting the file mode as exposed, which is the safe
// direction for a warning.
func firstUntraversableAncestor(path string) string {
	dir := filepath.Dir(path)
	for {
		info, err := os.Stat(dir)
		if err != nil {
			// Cannot tell; treat it as no protection rather than claim some.
			return ""
		}
		if info.Mode().Perm()&0o001 == 0 {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}
