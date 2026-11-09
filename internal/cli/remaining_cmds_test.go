package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func desiredDoc(t *testing.T, extra ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "desired.json")
	args := append([]string{"-users", "alice", "-o", path, "-public-host", "203.0.113.7"}, extra...)
	if err := runBootstrapState(context.Background(), &bytes.Buffer{}, args); err != nil {
		t.Fatal(err)
	}
	return path
}

func withDocker(t *testing.T, path string) {
	t.Helper()
	data, _ := os.ReadFile(path)
	changed := strings.Replace(string(data), `"installDocker": false`, `"installDocker": true`, 1)
	if changed == string(data) {
		t.Fatalf("no installDocker field to switch on in:\n%s", data)
	}
	os.WriteFile(path, []byte(changed), 0o600)
}

func withBot(t *testing.T, path string) {
	t.Helper()
	data, _ := os.ReadFile(path)
	changed := strings.Replace(string(data), "\"bot\": {\n    \"enabled\": false,", "\"bot\": {\n    \"enabled\": true,\n    \"telegramToken\": \"telegram-token\",", 1)
	if changed == string(data) {
		t.Fatalf("no bot section to switch on in:\n%s", data)
	}
	os.WriteFile(path, []byte(changed), 0o600)
}

func TestCloudInitRendersVerifiedFirstBootUserData(t *testing.T) {
	doc := desiredDoc(t)
	withDocker(t, doc)
	var out bytes.Buffer
	if err := runBootstrapCloudInit(context.Background(), &out, []string{"-f", doc, "-version", "v1.2.3"}); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.HasPrefix(text, "#cloud-config") {
		t.Errorf("not cloud-config:\n%.200s", text)
	}
	for _, want := range []string{"v1.2.3", "SHA256SUMS", "desired.json"} {
		if !strings.Contains(text, want) {
			t.Errorf("user-data lacks %q", want)
		}
	}
}

func TestCloudInitWritesAPrivateFileAndWarnsAboutCredentials(t *testing.T) {
	doc := desiredDoc(t)
	withDocker(t, doc)
	withBot(t, doc)
	creds := t.TempDir()
	// Whatever the document names must be supplied.
	var out bytes.Buffer
	err := runBootstrapCloudInit(context.Background(), &out, []string{"-f", doc, "-version", "v1.2.3"})
	if err == nil || !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), "-credentials") {
		t.Fatalf("missing credentials: %v", err)
	}
	if err := runBootstrapCloudInit(context.Background(), &out, []string{"-f", doc, "-version", "v1.2.3", "-credentials", creds}); err == nil ||
		!strings.Contains(err.Error(), "read credential") {
		t.Fatalf("absent credential file: %v", err)
	}
	os.WriteFile(filepath.Join(creds, "telegram-token"), []byte("123:abc"), 0o600)

	target := filepath.Join(t.TempDir(), "user-data")
	out.Reset()
	if err := runBootstrapCloudInit(context.Background(), &out, []string{"-f", doc, "-version", "v1.2.3", "-credentials", creds, "-o", target}); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, target); m != 0o600 {
		t.Errorf("user-data is %v", m)
	}
	data, _ := os.ReadFile(target)
	if !strings.Contains(string(data), "123:abc") && !strings.Contains(string(data), "telegram-token") {
		t.Error("the credential did not reach the user-data")
	}
	if !strings.Contains(out.String(), "mode 0600") || !strings.Contains(out.String(), "provider can read user-data") {
		t.Errorf("out = %q", out.String())
	}
}

func TestCloudInitPrintsAClaimCodeOnlyForABotNobodyAdministers(t *testing.T) {
	doc := desiredDoc(t)
	withDocker(t, doc)
	withBot(t, doc)
	creds := t.TempDir()
	os.WriteFile(filepath.Join(creds, "telegram-token"), []byte("123:abc"), 0o600)
	render := func(path string) string {
		var out bytes.Buffer
		if err := runBootstrapCloudInit(context.Background(), &out, []string{"-f", path, "-version", "v1.2.3", "-credentials", creds}); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	if !strings.Contains(render(doc), "bot claim-code") {
		t.Error("a bot with no admin gets no claim code on first boot")
	}
	data, _ := os.ReadFile(doc)
	administered := strings.Replace(string(data), `"adminIds": []`, `"adminIds": [42]`, 1)
	if administered == string(data) {
		t.Fatal("no adminIds to fill")
	}
	os.WriteFile(doc, []byte(administered), 0o600)
	if strings.Contains(render(doc), "bot claim-code") {
		t.Error("a claim code is printed for a bot that already has an admin")
	}
}

func TestCloudInitRefusesWhatCannotWork(t *testing.T) {
	ctx := context.Background()
	var out bytes.Buffer
	if err := runBootstrapCloudInit(ctx, &out, nil); !errors.Is(err, ErrUsage) {
		t.Errorf("no -f: %v", err)
	}
	doc := desiredDoc(t)
	// A dev build has no release to point at.
	old := Version
	Version = "dev"
	t.Cleanup(func() { Version = old })
	if err := runBootstrapCloudInit(ctx, &out, []string{"-f", doc}); !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), "-version") {
		t.Errorf("dev build: %v", err)
	}
	// A fresh VPS has no Docker to run the core with.
	if err := runBootstrapCloudInit(ctx, &out, []string{"-f", doc, "-version", "v1.2.3"}); !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), "installDocker") {
		t.Errorf("no docker: %v", err)
	}
	if err := runBootstrapCloudInit(ctx, &out, []string{"-f", filepath.Join(t.TempDir(), "none"), "-version", "v1.2.3"}); err == nil {
		t.Error("a missing document was fine")
	}
	withDocker(t, doc)
	if err := runBootstrapCloudInit(ctx, &out, []string{"-f", doc, "-version", "nonsense"}); err == nil {
		t.Error("a non-tag version was fine")
	}
	if err := runBootstrapCloudInit(ctx, &out, []string{"-f", doc, "-version", "v1.2.3", "-release", "ftp://x"}); err == nil {
		t.Error("a non-http release base was fine")
	}
	if err := runBootstrapCloudInit(ctx, &out, []string{"-f", doc, "-version", "v1.2.3", "-signing-key", filepath.Join(t.TempDir(), "none")}); err == nil {
		t.Error("a missing signing key was fine")
	}
	key := filepath.Join(t.TempDir(), "key.asc")
	os.WriteFile(key, []byte("key"), 0o600)
	if err := runBootstrapCloudInit(ctx, &out, []string{"-f", doc, "-version", "v1.2.3", "-signing-key", key, "-fingerprint", "abc"}); err == nil ||
		!strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("bad fingerprint: %v", err)
	}
}

func TestReleaseTagOfABuildVersion(t *testing.T) {
	for in, want := range map[string]string{
		"v0.1.0": "v0.1.0", "v0.1.0+299c2118": "v0.1.0", "v1.2.3-rc.1": "v1.2.3-rc.1",
		"dev": "", "299c2118": "", "": "", "0.1.0": "", "v1.2": "",
	} {
		if got := releaseTag(in); got != want {
			t.Errorf("releaseTag(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPreflightPrintsAReportAndHonoursItsFlags(t *testing.T) {
	sb := fakeSingBox(t, "exit 0")
	dir := filepath.Join(t.TempDir(), "etc", "sing-box")
	var out bytes.Buffer
	args := []string{"-out", dir, "-sing-box", sb, "-xdp-interface", "none", "-users", "a"}
	err := runPreflight(context.Background(), &out, args)
	_ = err // the verdict depends on the machine; the report must not
	if strings.TrimSpace(out.String()) == "" {
		t.Fatal("no report was written")
	}
	if _, statErr := os.Stat(dir); statErr == nil {
		t.Error("preflight created the deployment directory")
	}
	for _, bad := range [][]string{
		{"-tier", "z"}, {"-ports", "nonsense"}, {"-disable", "no-such-protocol"}, {"-xdp-interface", ""},
	} {
		o := bytes.Buffer{}
		got := runPreflight(context.Background(), &o, append([]string{"-sing-box", sb, "-xdp-interface", "none"}, bad...))
		if bad[0] == "-xdp-interface" {
			continue // empty means the default route, which is legal
		}
		if got == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}

func TestResolveCacheDirMirrorsInit(t *testing.T) {
	if got := resolveCacheDir("/etc/sing-box", ""); got != "/etc/cache" {
		t.Errorf("default = %q", got)
	}
	if got := resolveCacheDir("/etc/sing-box/", ""); got != "/etc/cache" {
		t.Errorf("trailing slash = %q", got)
	}
	if got := resolveCacheDir("/etc/sing-box", "/var/c"); got != "/var/c" {
		t.Errorf("explicit = %q", got)
	}
}

func TestSelftestArgumentGuards(t *testing.T) {
	ctx := context.Background()
	var out bytes.Buffer
	for _, args := range [][]string{{"-port", "0"}, {"-port", "70000"}, {"-subnet", "nonsense"}} {
		if err := runSelftest(ctx, &out, args); !errors.Is(err, ErrUsage) {
			t.Errorf("%v: %v", args, err)
		}
	}
	// With nothing to test against it fails instead of passing.
	err := runSelftest(ctx, &out, []string{"-config", filepath.Join(t.TempDir(), "none.json")})
	if err == nil || strings.Contains(out.String(), "PASS") {
		t.Errorf("a selftest with no config passed: %v\n%s", err, out.String())
	}
}

func TestVerifyGuards(t *testing.T) {
	ctx := context.Background()
	var out bytes.Buffer
	if err := runVerify(ctx, &out, nil); !errors.Is(err, ErrUsage) {
		t.Errorf("no bundle: %v", err)
	}
	if err := runVerify(ctx, &out, []string{"-bundle", "b", "stray"}); !errors.Is(err, ErrUsage) {
		t.Errorf("stray: %v", err)
	}
	if err := runVerify(ctx, &out, []string{"-bundle", filepath.Join(t.TempDir(), "none")}); err == nil {
		t.Error("a missing bundle was fine")
	}
	bundle := filepath.Join(t.TempDir(), "bundle.json")
	os.WriteFile(bundle, []byte("{"), 0o600)
	if err := runVerify(ctx, &out, []string{"-bundle", bundle, "-sing-box", "/nonexistent"}); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("bad bundle: %v", err)
	}
	// A bundle holding only what a server core cannot run as a client has
	// nothing to prove, which is an error rather than a pass.
	os.WriteFile(bundle, []byte(`{"outbounds":[{"type":"wdtt","tag":"w"}]}`), 0o600)
	if err := runVerify(ctx, &out, []string{"-bundle", bundle, "-sing-box", "/nonexistent"}); err == nil || !strings.Contains(err.Error(), "no nodes") {
		t.Errorf("untestable bundle: %v", err)
	}
	if strings.Contains(out.String(), "every node") {
		t.Error("verify claimed success")
	}
}
