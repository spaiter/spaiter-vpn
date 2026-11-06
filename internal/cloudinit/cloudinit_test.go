package cloudinit

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type document struct {
	WriteFiles []struct {
		Path        string `yaml:"path"`
		Permissions string `yaml:"permissions"`
		Content     string `yaml:"content"`
	} `yaml:"write_files"`
	RunCmd [][]string `yaml:"runcmd"`
}

func render(t *testing.T, o Options) document {
	t.Helper()
	data, err := Render(o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "#cloud-config\n") {
		t.Fatal("not a cloud-config document")
	}
	var doc document
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("user-data is not valid YAML: %v\n%s", err, data)
	}
	return doc
}

func (d document) file(path string) string {
	for _, f := range d.WriteFiles {
		if f.Path == path {
			return f.Content
		}
	}
	return ""
}

func TestUserDataCarriesTheDocumentKeyAndCredentialsVerbatim(t *testing.T) {
	desired := "{\n  \"apiVersion\": \"spaiter-vpn/v1alpha1\"\n}\n"
	doc := render(t, Options{Desired: []byte(desired), ReleaseBase: "https://releases.example/v0.1.0", Version: "v0.1.0",
		Credentials: map[string][]byte{"telegram-token": []byte("123:abc\n")}, ClaimBot: true})
	if got := doc.file("/run/spaiter-vpn-firstboot/desired.json"); got != desired {
		t.Fatalf("desired = %q", got)
	}
	if got := doc.file("/run/spaiter-vpn-firstboot/credentials/telegram-token"); got != "123:abc\n" {
		t.Fatalf("credential = %q", got)
	}
	if !strings.Contains(doc.file("/run/spaiter-vpn-firstboot/release-signing.asc"), "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatal("the release key is missing")
	}
	script := doc.file("/run/spaiter-vpn-firstboot/firstboot.sh")
	for _, want := range []string{"VALIDSIG " + ReleaseFingerprint, "sha256sum --check --strict", "bootstrap credential telegram-token", "bot claim-code"} {
		if !strings.Contains(script, want) {
			t.Errorf("firstboot lacks %q", want)
		}
	}
	if len(doc.RunCmd) != 1 || doc.RunCmd[0][1] != "/run/spaiter-vpn-firstboot/firstboot.sh" {
		t.Fatalf("runcmd = %v", doc.RunCmd)
	}
}

func TestUnsafeInputsAreRefused(t *testing.T) {
	for name, o := range map[string]Options{
		"version":    {ReleaseBase: "https://r.example", Version: "latest"},
		"scheme":     {ReleaseBase: "file:///tmp", Version: "v1"},
		"shell":      {ReleaseBase: "https://r.example/$(reboot)", Version: "v1"},
		"credential": {ReleaseBase: "https://r.example", Version: "v1", Credentials: map[string][]byte{"../etc": nil}},
	} {
		if _, err := Render(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// release builds a signed release in dir with a key in its own keyring and
// returns that key's armored public half and fingerprint.
func release(t *testing.T, dir, version, binary string, gnupg string) (string, string) {
	t.Helper()
	gpg := func(args ...string) []byte {
		cmd := exec.Command("gpg", append([]string{"--batch", "--quiet", "--pinentry-mode", "loopback", "--passphrase", ""}, args...)...)
		cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupg)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("gpg %v: %v", args, err)
		}
		return out
	}
	gpg("--quick-gen-key", "test-release-"+filepath.Base(gnupg), "ed25519", "sign", "1d")
	colons := string(gpg("--list-keys", "--with-colons"))
	fingerprint := regexp.MustCompile(`(?m)^fpr:+([0-9A-F]{40}):`).FindStringSubmatch(colons)[1]
	name := "spaiter-vpn-" + version + "-linux-amd64"
	tarball := filepath.Join(dir, name+".tar.gz")
	file, _ := os.Create(tarball)
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: name + "/spaiter-vpn", Mode: 0o755, Size: int64(len(binary))})
	tw.Write([]byte(binary))
	tw.Close()
	gz.Close()
	file.Close()
	data, _ := os.ReadFile(tarball)
	sum := sha256.Sum256(data)
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(hex.EncodeToString(sum[:])+"  "+name+".tar.gz\n"), 0o644)
	gpg("--local-user", fingerprint, "--armor", "--detach-sign", "--output", filepath.Join(dir, "SHA256SUMS.asc"), filepath.Join(dir, "SHA256SUMS"))
	return string(gpg("--armor", "--export", fingerprint)), fingerprint
}

// runFirstboot executes the rendered script with its fixed paths redirected
// into a temporary root, and a fake binary that records what it was asked.
func runFirstboot(t *testing.T, doc document, root string) error {
	t.Helper()
	stage := filepath.Join(root, "stage")
	os.MkdirAll(filepath.Join(stage, "credentials"), 0o700)
	for _, f := range doc.WriteFiles {
		target := filepath.Join(stage, strings.TrimPrefix(f.Path, "/run/spaiter-vpn-firstboot/"))
		os.WriteFile(target, []byte(f.Content), 0o600)
	}
	script := doc.file("/run/spaiter-vpn-firstboot/firstboot.sh")
	script = strings.ReplaceAll(script, "/run/spaiter-vpn-firstboot", stage)
	script = strings.ReplaceAll(script, "/usr/local/bin/spaiter-vpn", filepath.Join(root, "bin", "spaiter-vpn"))
	script = strings.ReplaceAll(script, "/var/log/spaiter-vpn-firstboot.log", filepath.Join(root, "firstboot.log"))
	os.MkdirAll(filepath.Join(root, "bin"), 0o755)
	path := filepath.Join(root, "firstboot.sh")
	os.WriteFile(path, []byte(script), 0o700)
	return exec.Command("/bin/sh", path).Run()
}

func TestFirstBootInstallsOnlyARelaseSignedByThePinnedKey(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg is not installed")
	}
	fake := "#!/bin/sh\necho \"$@\" >>\"$(dirname \"$0\")/calls\"\n"
	releaseDir := t.TempDir()
	key, fingerprint := release(t, releaseDir, "v0.0.1", fake, t.TempDir())
	server := httptest.NewServer(http.FileServer(http.Dir(releaseDir)))
	defer server.Close()
	options := Options{Desired: []byte("{}\n"), ReleaseBase: server.URL, Version: "v0.0.1", SigningKey: []byte(key), Fingerprint: fingerprint,
		Credentials: map[string][]byte{"telegram-token": []byte("t\n")}}

	root := t.TempDir()
	if err := runFirstboot(t, render(t, options), root); err != nil {
		log, _ := os.ReadFile(filepath.Join(root, "firstboot.log"))
		t.Fatalf("a genuine release failed: %v\n%s", err, log)
	}
	calls, _ := os.ReadFile(filepath.Join(root, "bin", "calls"))
	if !strings.Contains(string(calls), "bootstrap credential telegram-token") || !strings.Contains(string(calls), "bootstrap apply -yes") {
		t.Fatalf("the installed binary was asked %q", calls)
	}

	// The same release with another binary in the tarball: SHA256SUMS no
	// longer matches, so nothing is installed.
	tampered := t.TempDir()
	if err := os.WriteFile(filepath.Join(releaseDir, "spaiter-vpn-v0.0.1-linux-amd64.tar.gz"), []byte("evil"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runFirstboot(t, render(t, options), tampered); err == nil {
		t.Fatal("a tampered tarball was installed")
	}
	if _, err := os.Stat(filepath.Join(tampered, "bin", "spaiter-vpn")); !os.IsNotExist(err) {
		t.Fatal("a binary was installed from a tampered release")
	}

	// A release signed by another key, even a valid signature, is refused.
	otherDir := t.TempDir()
	otherKey, _ := release(t, otherDir, "v0.0.1", fake, t.TempDir())
	otherServer := httptest.NewServer(http.FileServer(http.Dir(otherDir)))
	defer otherServer.Close()
	impostor := options
	impostor.ReleaseBase, impostor.SigningKey = otherServer.URL, []byte(otherKey)
	if err := runFirstboot(t, render(t, impostor), t.TempDir()); err == nil {
		t.Fatal("a release signed by a key other than the pinned one was installed")
	}
}
