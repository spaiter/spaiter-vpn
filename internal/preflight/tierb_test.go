package preflight

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/profile"
)

// writeCert writes a self-signed certificate and key, valid for the given name
// over the given window.
func writeCert(t *testing.T, dir, name string, notBefore, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}

	certPath = filepath.Join(dir, "fullchain.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// stubResolver replaces the resolver for one test.
func stubResolver(t *testing.T, addrs []netip.Addr, err error) {
	t.Helper()
	saved := resolveHost
	resolveHost = func(context.Context, string) ([]netip.Addr, error) { return addrs, err }
	t.Cleanup(func() { resolveHost = saved })
}

func tierBSpec(source profile.CertSource) profile.Spec {
	spec := profile.Defaults([]string{"alice"})
	spec.Tier = profile.TierB
	spec.Domain = "vpn.example.com"
	spec.Certs.Source = source
	return spec
}

// TestCheckDomainResolves exercises the indirection, because a check that only
// ever runs against a name that happens to resolve on this host proves nothing
// about what it does when the name does not.
func TestCheckDomainResolves(t *testing.T) {
	ctx := context.Background()

	t.Run("resolves", func(t *testing.T) {
		stubResolver(t, []netip.Addr{netip.MustParseAddr("203.0.113.5")}, nil)
		c := checkDomainResolves(ctx, "vpn.example.com")
		if c.Severity != Pass {
			t.Errorf("severity %v, want Pass: %s", c.Severity, c.Detail)
		}
	})

	t.Run("does not resolve", func(t *testing.T) {
		stubResolver(t, nil, errors.New("no such host"))
		c := checkDomainResolves(ctx, "vpn.example.com")
		if c.Severity != Fail {
			t.Errorf("severity %v, want Fail", c.Severity)
		}
		if c.Remedy == "" {
			t.Error("a Fail with no remedy leaves the operator nowhere to go")
		}
	})

	t.Run("resolves to nothing", func(t *testing.T) {
		stubResolver(t, nil, nil)
		if c := checkDomainResolves(ctx, "vpn.example.com"); c.Severity != Fail {
			t.Errorf("an empty answer was graded %v, want Fail", c.Severity)
		}
	})

	t.Run("no domain", func(t *testing.T) {
		if c := checkDomainResolves(ctx, ""); c.Severity != Fail {
			t.Errorf("severity %v, want Fail", c.Severity)
		}
	})
}

func TestCheckCertificateFile(t *testing.T) {
	const domain = "vpn.example.com"
	now := time.Now()

	t.Run("valid", func(t *testing.T) {
		cert, _ := writeCert(t, t.TempDir(), domain, now.Add(-time.Hour), now.Add(90*24*time.Hour))
		if c := checkCertificateFile(cert, domain); c.Severity != Pass {
			t.Errorf("severity %v, want Pass: %s", c.Severity, c.Detail)
		}
	})

	t.Run("expired", func(t *testing.T) {
		cert, _ := writeCert(t, t.TempDir(), domain, now.Add(-90*24*time.Hour), now.Add(-24*time.Hour))
		c := checkCertificateFile(cert, domain)
		if c.Severity != Fail {
			t.Errorf("an expired certificate was graded %v, want Fail: %s", c.Severity, c.Detail)
		}
	})

	t.Run("expiring soon", func(t *testing.T) {
		cert, _ := writeCert(t, t.TempDir(), domain, now.Add(-time.Hour), now.Add(5*24*time.Hour))
		if c := checkCertificateFile(cert, domain); c.Severity != Warn {
			t.Errorf("severity %v, want Warn: %s", c.Severity, c.Detail)
		}
	})

	// The mistake with no other symptom: a certificate that is perfectly valid
	// for a name the inbounds do not present.
	t.Run("wrong name", func(t *testing.T) {
		cert, _ := writeCert(t, t.TempDir(), "other.example.com", now.Add(-time.Hour), now.Add(90*24*time.Hour))
		c := checkCertificateFile(cert, domain)
		if c.Severity != Fail {
			t.Errorf("a certificate for the wrong name was graded %v, want Fail: %s", c.Severity, c.Detail)
		}
	})

	t.Run("missing", func(t *testing.T) {
		if c := checkCertificateFile(filepath.Join(t.TempDir(), "nope.pem"), domain); c.Severity != Fail {
			t.Errorf("severity %v, want Fail", c.Severity)
		}
	})

	t.Run("not PEM", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "junk.pem")
		if err := os.WriteFile(path, []byte("not a certificate"), 0o644); err != nil {
			t.Fatal(err)
		}
		if c := checkCertificateFile(path, domain); c.Severity != Fail {
			t.Errorf("severity %v, want Fail", c.Severity)
		}
	})
}

func TestCheckKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	_, key := writeCert(t, dir, "vpn.example.com", time.Now(), time.Now().Add(time.Hour))

	if c := checkKeyFile(key); c.Severity != Pass {
		t.Errorf("a 0600 key was graded %v: %s", c.Severity, c.Detail)
	}

	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	c := checkKeyFile(key)
	if c.Severity != Warn {
		t.Errorf("a world-readable private key was graded %v, want Warn", c.Severity)
	}
}

// TestCheckHTTPChallengePortNeverClaimsPass is the important one. A green check
// in front of HTTP-01 on a NAT'd line would be worse than no check: it would
// assert the one thing that cannot be established from here.
func TestCheckHTTPChallengePortNeverClaimsPass(t *testing.T) {
	spec := tierBSpec(profile.CertSourceACMEHTTP)
	// A port the kernel just said was free, not a fixed one. This hardcoded
	// 38080, which sits inside ip_local_port_range (32768-60999 here), so any
	// outbound connection could be holding it as an ephemeral source port --
	// and one was, which graded the check Fail and left the test unable to bind
	// either. A port the kernel offers cannot collide that way.
	port, err := freeTestPort()
	if err != nil {
		t.Fatalf("cannot find a free port: %v", err)
	}
	spec.Certs.AlternativeHTTPPort = port

	c := checkHTTPChallengePort(spec)
	if c.Severity == Pass {
		t.Error("the challenge port check reported Pass; reachability from the CA is not testable from this host")
	}
	if c.Severity != Unknown {
		t.Errorf("severity %v, want Unknown (the port was bindable)", c.Severity)
	}

	// And when the port is taken it must be a hard failure, not Unknown.
	ln, err := netListen(spec.Certs.AlternativeHTTPPort)
	if err != nil {
		t.Fatalf("cannot bind the port the kernel just offered: %v", err)
	}
	defer ln.Close()
	if c := checkHTTPChallengePort(spec); c.Severity != Fail {
		t.Errorf("an occupied challenge port was graded %v, want Fail", c.Severity)
	}
}

// TestTierBChecksAreSkippedWithoutCertificates covers the vless-xhttp-only
// case: Reality presents no certificate, so none of the prerequisites apply and
// demanding a domain would be a requirement invented here.
func TestTierBChecksAreSkippedWithoutCertificates(t *testing.T) {
	spec := tierBSpec(profile.CertSourceACMEDNS)
	spec.Domain = ""
	spec.Enabled = map[profile.Protocol]bool{profile.VLESSXHTTP: true}

	checks := checkTierB(context.Background(), Options{Spec: spec})
	for _, c := range checks {
		if c.Severity == Fail {
			t.Errorf("a certificate-free Tier B deployment failed on %q: %s", c.Name, c.Detail)
		}
	}
}

// TestTierBChecksAreAbsentForTierA guards against Tier A paying Tier B's costs.
func TestTierBChecksAreAbsentForTierA(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	if checks := checkTierB(context.Background(), Options{Spec: spec}); len(checks) != 0 {
		t.Errorf("Tier A produced %d Tier B checks", len(checks))
	}
}

// TestFilesSourceWarnsAboutReload records the failure mode this source has and
// the others do not: the core caches the chain it read at startup.
func TestFilesSourceWarnsAboutReload(t *testing.T) {
	stubResolver(t, []netip.Addr{netip.MustParseAddr("203.0.113.5")}, nil)
	dir := t.TempDir()
	cert, key := writeCert(t, dir, "vpn.example.com", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	spec := tierBSpec(profile.CertSourceFiles)
	spec.Certs.CertificatePath, spec.Certs.KeyPath = cert, key

	var found bool
	for _, c := range checkTierB(context.Background(), Options{Spec: spec}) {
		if c.Name == "certificate renewal" {
			found = true
			if c.Severity != Warn {
				t.Errorf("severity %v, want Warn", c.Severity)
			}
		}
	}
	if !found {
		t.Error("no warning that an unmanaged renewal will not be picked up")
	}
}

// TestACMEDataDirectoryWarnsWhenAbsent guards the mistake with the longest
// consequence: a non-persistent directory re-issues on every restart and hits
// the duplicate-certificate limit.
func TestACMEDataDirectoryWarnsWhenAbsent(t *testing.T) {
	spec := tierBSpec(profile.CertSourceACMEDNS)
	spec.Certs.DataDirectory = filepath.Join(t.TempDir(), "does-not-exist")
	if c := checkACMEDataDirectory(spec); c.Severity != Warn {
		t.Errorf("severity %v, want Warn: %s", c.Severity, c.Detail)
	}

	spec.Certs.DataDirectory = t.TempDir()
	if c := checkACMEDataDirectory(spec); c.Severity != Pass {
		t.Errorf("an existing directory was graded %v: %s", c.Severity, c.Detail)
	}
}

// netListen is a helper so the occupied-port case needs no import juggling.
func netListen(port uint16) (interface{ Close() error }, error) {
	return net.Listen("tcp", fmt.Sprintf(":%d", port))
}

// freeTestPort asks the kernel for an unused port and gives it back. There is a
// window between the close and the caller's bind, but it beats a constant from
// the ephemeral range, which is occupied at random by whatever the host dialled
// out to last.
func freeTestPort() (uint16, error) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port), nil
}

// TestKeyPermissionWarningDistinguishesReachability guards against the
// inaccuracy this check originally had: it claimed any local user could read a
// permissive key, when a single untraversable ancestor makes that false. A
// check that overstates its finding is one people learn to skip.
func TestKeyPermissionWarningDistinguishesReachability(t *testing.T) {
	// A traversable path: the warning must say the key is actually readable.
	//
	// Built directly under /tmp rather than with t.TempDir, because that helper
	// creates its root 0700 — so a key inside it is never reachable by others
	// and this half of the test would pass without testing anything.
	open, err := os.MkdirTemp("/tmp", "spaiter-open-*")
	if err != nil {
		t.Skipf("cannot create a world-traversable directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(open) })
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if blocker := firstUntraversableAncestor(filepath.Join(open, "x")); blocker != "" {
		t.Skipf("%s is not world-traversable on this host, so the reachable case cannot be built", blocker)
	}
	_, key := writeCert(t, open, "vpn.example.com", time.Now(), time.Now().Add(time.Hour))
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	c := checkKeyFile(key)
	if c.Severity != Warn {
		t.Fatalf("severity %v, want Warn", c.Severity)
	}
	if strings.Contains(c.Detail, "blocks other users") {
		t.Errorf("a reachable key was reported as protected by a directory: %s", c.Detail)
	}

	// Now block traversal one level up. Same file mode, different conclusion.
	blocked := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(blocked, 0o750); err != nil {
		t.Fatal(err)
	}
	_, key2 := writeCert(t, blocked, "vpn.example.com", time.Now(), time.Now().Add(time.Hour))
	if err := os.Chmod(key2, 0o644); err != nil {
		t.Fatal(err)
	}
	c2 := checkKeyFile(key2)
	if c2.Severity != Warn {
		t.Fatalf("severity %v, want Warn", c2.Severity)
	}
	if !strings.Contains(c2.Detail, "blocks other users") {
		t.Errorf("a key behind a 0750 directory was reported as readable by anyone: %s", c2.Detail)
	}
	if !strings.Contains(c2.Detail, blocked) {
		t.Errorf("the detail does not name the directory doing the protecting: %s", c2.Detail)
	}
}
