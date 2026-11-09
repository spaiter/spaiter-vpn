package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"github.com/spaiter/spaiter-vpn/internal/profile"
)

func TestRunDispatchesAndSeparatesMistypingFromFailure(t *testing.T) {
	var out bytes.Buffer
	if err := Run(context.Background(), &out, nil); !errors.Is(err, ErrUsage) {
		t.Errorf("no arguments: %v, want ErrUsage", err)
	}
	err := Run(context.Background(), &out, []string{"frobnicate"})
	if !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), `"frobnicate"`) {
		t.Errorf("unknown command: %v", err)
	}

	out.Reset()
	old := Version
	Version = "v9.9.9-test"
	defer func() { Version = old }()
	if err := Run(context.Background(), &out, []string{"version"}); err != nil || strings.TrimSpace(out.String()) != "v9.9.9-test" {
		t.Errorf("version: %q, %v", out.String(), err)
	}

	// -h is a request, not a failure: it must not become a non-zero exit.
	out.Reset()
	if err := Run(context.Background(), &out, []string{"version", "-h"}); err != nil {
		t.Errorf("a command asked for help and Run returned %v", err)
	}
	out.Reset()
	if err := Run(context.Background(), &out, []string{"check", "-h"}); err != nil {
		t.Errorf("check -h: %v", err)
	}
	if !strings.Contains(out.String(), "-") {
		t.Errorf("check -h printed no flags: %q", out.String())
	}
}

func TestCommandsAreUniqueDocumentedAndListedInUsage(t *testing.T) {
	seen := map[string]bool{}
	var out bytes.Buffer
	Usage(&out)
	for _, c := range commands() {
		if seen[c.name] {
			t.Errorf("command %q registered twice: the first would shadow the second", c.name)
		}
		seen[c.name] = true
		if c.summary == "" || c.run == nil {
			t.Errorf("command %q has no summary or no handler", c.name)
		}
		if !strings.Contains(out.String(), c.name) || !strings.Contains(out.String(), c.summary) {
			t.Errorf("usage omits %q", c.name)
		}
	}
	for _, must := range []string{"bootstrap", "backup", "restore", "control", "bot"} {
		if !seen[must] {
			t.Errorf("command %q is missing", must)
		}
	}
	if !strings.Contains(out.String(), "bootstrap -h") {
		t.Error("usage no longer points a new operator at bootstrap")
	}
}

func TestNewFlagSetReportsInsteadOfExiting(t *testing.T) {
	var out bytes.Buffer
	fs := newFlagSet("x", &out)
	fs.Bool("known", false, "")
	if err := fs.Parse([]string{"-nope"}); err == nil {
		t.Fatal("an unknown flag parsed")
	}
	if !strings.Contains(out.String(), "nope") {
		t.Errorf("the flag error went nowhere: %q", out.String())
	}
}

func TestReleaseTagRejectsAnythingThatIsNotATag(t *testing.T) {
	for in, want := range map[string]string{
		"v0.1.0":          "v0.1.0",
		"v0.1.0+299c2118": "v0.1.0",
		"v1.2.3-rc.1":     "v1.2.3-rc.1",
		"dev":             "",
		"":                "",
		"299c2118":        "",
		"0.1.0":           "",
		"v1.2":            "",
		"v1.2.3; rm -rf":  "", // the tag is pasted into a URL and a script
	} {
		if got := releaseTag(in); got != want {
			t.Errorf("releaseTag(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCertFlagsRefuseToBeSilentlyIgnoredInTierA(t *testing.T) {
	for name, f := range map[string]initFlags{
		"domain":      {domain: "vpn.example.org"},
		"cert source": {certSource: "files"},
		"cert file":   {certFile: "/c"},
		"key file":    {keyFile: "/k"},
		"email":       {acmeEmail: "a@b"},
		"dns":         {dnsProvider: "cloudflare"},
		"token file":  {cfTokenFile: "/t"},
		"staging":     {acmeStaging: true},
	} {
		spec := profile.Defaults([]string{"alice"})
		spec.Tier = profile.TierA
		if err := applyCertFlags(f, &spec); !errors.Is(err, ErrUsage) {
			t.Errorf("%s in tier a was accepted (%v): the run would report success with no TLS protocols", name, err)
		}
	}
	spec := profile.Defaults([]string{"alice"})
	spec.Tier = profile.TierA
	if err := applyCertFlags(initFlags{}, &spec); err != nil {
		t.Errorf("tier a with no certificate flags: %v", err)
	}
}

func TestCertFlagsFillTierB(t *testing.T) {
	spec := profile.Defaults([]string{"alice"})
	spec.Tier = profile.TierB
	f := initFlags{
		domain: "  vpn.example.org ", certSource: string(profile.CertSourceFiles),
		certFile: "/c.pem", keyFile: "/k.pem", acmeEmail: "ops@example.org", acmeHTTPPort: 8080,
	}
	if err := applyCertFlags(f, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Domain != "vpn.example.org" {
		t.Errorf("domain = %q (whitespace must be trimmed)", spec.Domain)
	}
	c := spec.Certs
	if c.Source != profile.CertSourceFiles || c.CertificatePath != "/c.pem" || c.KeyPath != "/k.pem" || c.Email != "ops@example.org" || c.AlternativeHTTPPort != 8080 {
		t.Errorf("certs = %+v", c)
	}

	spec = profile.Defaults([]string{"alice"})
	spec.Tier = profile.TierB
	if err := applyCertFlags(initFlags{acmeStaging: true}, &spec); err != nil || spec.Certs.Directory != profile.LetsEncryptStaging {
		t.Errorf("staging: %v, directory %q", err, spec.Certs.Directory)
	}
	spec = profile.Defaults([]string{"alice"})
	spec.Tier = profile.TierB
	if err := applyCertFlags(initFlags{acmeStaging: true, acmeDirectory: "https://ca.example/dir"}, &spec); !errors.Is(err, ErrUsage) {
		t.Errorf("two endpoints were accepted: %v", err)
	}
}

func TestCloudflareTokenComesFromAFileOrTheEnvironmentNeverAFlag(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "tok")
	os.WriteFile(good, []byte("  s3cr3t-token\n"), 0o600)
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, []byte(" \n"), 0o600)

	t.Setenv(CloudflareTokenEnv, "from-env")
	if tok, err := readCloudflareToken(good); err != nil || tok != "s3cr3t-token" {
		t.Errorf("file wins over the environment and is trimmed: %q %v", tok, err)
	}
	if _, err := readCloudflareToken(empty); !errors.Is(err, ErrUsage) {
		t.Errorf("an empty token file: %v", err)
	}
	if _, err := readCloudflareToken(filepath.Join(dir, "absent")); err == nil || strings.Contains(err.Error(), "from-env") {
		t.Errorf("a missing file: %v", err)
	}
	if tok, err := readCloudflareToken(""); err != nil || tok != "from-env" {
		t.Errorf("env: %q %v", tok, err)
	}
	t.Setenv(CloudflareTokenEnv, " ")
	_, err := readCloudflareToken("")
	if !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), CloudflareTokenEnv) {
		t.Errorf("no token anywhere must say where to put one: %v", err)
	}
}

func TestDNS01NeedsTheTokenExceptForAPreflightRun(t *testing.T) {
	t.Setenv(CloudflareTokenEnv, "")
	mk := func() profile.Spec {
		s := profile.Defaults([]string{"alice"})
		s.Tier = profile.TierB
		return s
	}
	f := initFlags{domain: "vpn.example.org", certSource: string(profile.CertSourceACMEDNS), dnsProvider: "cloudflare"}

	spec := mk()
	if err := applyCertFlags(f, &spec); !errors.Is(err, ErrUsage) {
		t.Fatalf("generating without the token: %v", err)
	}
	f.checkOnly = true
	spec = mk()
	if err := applyCertFlags(f, &spec); err != nil || spec.Certs.CloudflareAPIToken != checkOnlyTokenPlaceholder {
		t.Fatalf("preflight must not demand the credential: %v %q", err, spec.Certs.CloudflareAPIToken)
	}

	t.Setenv(CloudflareTokenEnv, "real")
	f.checkOnly = false
	spec = mk()
	if err := applyCertFlags(f, &spec); err != nil || spec.Certs.CloudflareAPIToken != "real" {
		t.Fatalf("%v %q", err, spec.Certs.CloudflareAPIToken)
	}
}

const bundleA = `{"outbounds":[{"tag":"reality","server":"h","port":1,"vk_hashes":["a"],"workers":3},{"tag":"mieru","port":2},{"type":"direct"}]}`

func TestNodesByTagIsCanonicalAndIgnoresRotatingFields(t *testing.T) {
	nodes, err := nodesByTag([]byte(bundleA))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 || nodes["<untagged 2>"] != `{"type":"direct"}` {
		t.Fatalf("nodes = %v", nodes)
	}
	if strings.Contains(nodes["reality"], "vk_hashes") || strings.Contains(nodes["reality"], "workers") {
		t.Errorf("hourly-rotating fields leaked into the comparison: %s", nodes["reality"])
	}
	// Key order is not a difference.
	reordered := `{"outbounds":[{"port":1,"server":"h","tag":"reality"}]}`
	other, _ := nodesByTag([]byte(reordered))
	if other["reality"] != nodes["reality"] {
		t.Errorf("key order changed the canonical form:\n%s\n%s", other["reality"], nodes["reality"])
	}
	if _, err := nodesByTag([]byte("{")); err == nil {
		t.Error("garbage parsed")
	}
	if countOutbounds([]byte(bundleA)) != 3 || countOutbounds([]byte("x")) != 0 {
		t.Error("countOutbounds")
	}
}

func TestDiffBundlesNamesTheNodeThatChanged(t *testing.T) {
	same, err := diffBundles([]byte(bundleA), []byte(`{"outbounds":[{"workers":9,"vk_hashes":["z"],"tag":"reality","server":"h","port":1},{"port":2,"tag":"mieru"},{"type":"direct"}]}`))
	if err != nil || same != "" {
		t.Fatalf("rotation alone is not a change: %q %v", same, err)
	}
	after := `{"outbounds":[{"tag":"reality","server":"h","port":2},{"tag":"warp","port":3},{"type":"direct"}]}`
	diff, err := diffBundles([]byte(bundleA), []byte(after))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"- mieru is gone", "+ warp is new", "~ reality changed", "was ", "now "} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff lacks %q:\n%s", want, diff)
		}
	}
	if strings.Contains(diff, "untagged") {
		t.Errorf("an unchanged node was reported:\n%s", diff)
	}
	if strings.Index(diff, "mieru") > strings.Index(diff, "reality") || strings.Index(diff, "reality") > strings.Index(diff, "warp") {
		t.Errorf("report is not sorted by tag:\n%s", diff)
	}
	if _, err := diffBundles([]byte("{"), []byte(bundleA)); err == nil || !strings.Contains(err.Error(), "cached") {
		t.Errorf("bad cache: %v", err)
	}
	if _, err := diffBundles([]byte(bundleA), []byte("{")); err == nil || !strings.Contains(err.Error(), "rebuilt") {
		t.Errorf("bad rebuild: %v", err)
	}
}

func TestJoinHashesOnePerLineAsCode(t *testing.T) {
	if got := joinHashes([]string{"a", "b"}); got != "  `a`\n  `b`\n" {
		t.Errorf("%q", got)
	}
	if joinHashes(nil) != "" {
		t.Error("nil")
	}
}

func TestCanonicalJSONIsStableAndNewlineTerminated(t *testing.T) {
	desired := state.Default([]string{"alice"})
	a, err := canonicalJSON(desired)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := canonicalJSON(desired)
	if !bytes.Equal(a, b) || !bytes.HasSuffix(a, []byte("}\n")) || !json.Valid(a) {
		t.Errorf("not stable canonical JSON: %q", a)
	}
}
