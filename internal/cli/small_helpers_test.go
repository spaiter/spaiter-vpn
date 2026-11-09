package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/backup"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
)

func TestBootstrapUsageListsEverySubcommand(t *testing.T) {
	var out bytes.Buffer
	writeBootstrapUsage(&out)
	for _, name := range []string{"state", "credential", "plan", "apply", "status", "rollback", "rotate", "prune", "cloud-init"} {
		if !strings.Contains(out.String(), "  "+name) {
			t.Errorf("usage does not mention %s:\n%s", name, out.String())
		}
	}
}

func TestSelfPathNamesTheRunningBinary(t *testing.T) {
	if selfPathOrName() == "" {
		t.Error("empty")
	}
}

func TestInterfaceAddressesAreOnlyPubliclyReachableOnes(t *testing.T) {
	for _, addr := range interfaceAddrs() {
		if addr.IsPrivate() || addr.IsLoopback() || cgnat.Contains(addr) {
			t.Errorf("%v is not a public address", addr)
		}
	}
}

func TestCredentialLookupHelpers(t *testing.T) {
	layout := discover.DefaultLayout()
	if got := credentialPath(layout, "ddns-token"); !strings.HasSuffix(got, "/ddns-token") || !strings.HasPrefix(got, layout.CredentialDir()) {
		t.Errorf("path = %q", got)
	}
	if !snapHasNoCredential(&backup.Snapshot{}, "ddns-token") {
		t.Error("an empty snapshot claims to hold a credential")
	}
}

func TestSecretsComeFromAPipeWhenStdinIsNotATerminal(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = reader
	defer func() { os.Stdin = old }()
	go func() {
		writer.WriteString("  s3cret \n")
		writer.Close()
	}()
	got, err := readSecretFromStdin(&bytes.Buffer{})
	if err != nil || got != "s3cret" {
		t.Errorf("secret = %q, %v", got, err)
	}
}

func TestOpeningABackupFailsOnEachUnusableInput(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "absent")
	if _, err := openBackup(filepath.Join(dir, "b.age"), missing, ""); err == nil {
		t.Error("a missing identity file was accepted")
	}
	garbage := filepath.Join(dir, "id")
	os.WriteFile(garbage, []byte("not an identity\n"), 0o600)
	if _, err := openBackup(filepath.Join(dir, "b.age"), garbage, ""); err == nil || !strings.Contains(err.Error(), "read "+garbage) {
		t.Errorf("garbage identity: %v", err)
	}
	if _, err := openBackup(filepath.Join(dir, "b.age"), "", missing); err == nil {
		t.Error("a missing passphrase file was accepted")
	}
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, []byte("\n"), 0o600)
	if _, err := openBackup(filepath.Join(dir, "b.age"), "", empty); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Errorf("empty passphrase file: %v", err)
	}
	pass := filepath.Join(dir, "pass")
	os.WriteFile(pass, []byte("correct horse battery staple\n"), 0o600)
	if _, err := openBackup(filepath.Join(dir, "absent.age"), "", pass); err == nil {
		t.Error("a missing archive was accepted")
	}
}
