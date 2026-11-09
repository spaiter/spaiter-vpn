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

// stdinFrom replaces os.Stdin with a pipe holding text.
func stdinFrom(t *testing.T, text string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(text); err != nil {
		t.Fatal(err)
	}
	w.Close()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; r.Close() })
}

func pretendRoot(t *testing.T, root bool) {
	t.Helper()
	old := runningAsRoot
	runningAsRoot = func() bool { return root }
	t.Cleanup(func() { runningAsRoot = old })
}

func credentialArgs(root string, extra ...string) []string {
	return append([]string{"-config-root", root, "-data-root", root + "-data"}, extra...)
}

func TestCredentialNeedsRootAndAName(t *testing.T) {
	var out bytes.Buffer
	pretendRoot(t, false)
	root := filepath.Join(t.TempDir(), "etc")
	err := runBootstrapCredential(context.Background(), &out, credentialArgs(root, "telegram-token"))
	if err == nil || !strings.Contains(err.Error(), "needs root") {
		t.Errorf("non-root: %v", err)
	}
	if _, statErr := os.Stat(root); statErr == nil {
		t.Error("a refused credential still created the directory")
	}
	pretendRoot(t, true)
	if err := runBootstrapCredential(context.Background(), &out, credentialArgs(root)); !errors.Is(err, ErrUsage) {
		t.Errorf("no name: %v", err)
	}
	if err := runBootstrapCredential(context.Background(), &out, credentialArgs(root, "a", "b")); !errors.Is(err, ErrUsage) {
		t.Errorf("two names: %v", err)
	}
	if err := runBootstrapCredential(context.Background(), &out, []string{"-h"}); err == nil {
		t.Error("-h should stop with the usage error")
	}
	if !strings.Contains(out.String(), "usage: spaiter-vpn bootstrap credential") {
		t.Errorf("no usage text:\n%s", out.String())
	}
}

func TestCredentialRefusesEmptyInputWithoutWriting(t *testing.T) {
	pretendRoot(t, true)
	stdinFrom(t, "  \n")
	root := filepath.Join(t.TempDir(), "etc")
	var out bytes.Buffer
	err := runBootstrapCredential(context.Background(), &out, credentialArgs(root, "telegram-token"))
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "credentials", "telegram-token")); statErr == nil {
		t.Error("an empty credential was written")
	}
}

func TestCredentialIsWrittenPrivatelyAndReadBackThroughTheStore(t *testing.T) {
	pretendRoot(t, true)
	stdinFrom(t, "  s3cret-value \n")
	root := filepath.Join(t.TempDir(), "etc")
	var out bytes.Buffer
	err := runBootstrapCredential(context.Background(), &out, credentialArgs(root, "telegram-token"))
	path := filepath.Join(root, "credentials", "telegram-token")
	if os.Geteuid() != 0 {
		// The store insists the file belongs to root; a test user cannot own
		// it as root, so the final check is expected to refuse.
		if err == nil || !strings.Contains(err.Error(), "not usable") {
			t.Fatalf("err = %v, want the store's refusal for a file root does not own", err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || string(data) != "s3cret-value\n" {
		t.Fatalf("file = %q, %v; want the trimmed value and a newline", data, readErr)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode().Perm())
	}
	if info, _ := os.Stat(filepath.Dir(path)); info.Mode().Perm() != 0o700 {
		t.Errorf("directory mode = %v", info.Mode().Perm())
	}
	if strings.Contains(out.String(), "s3cret-value") {
		t.Error("the value was echoed")
	}
	if err == nil && !strings.Contains(out.String(), "stored credential telegram-token (12 bytes, mode 0600)") {
		t.Errorf("output: %s", out.String())
	}
}

func TestCredentialDoesNotFollowASymlinkPlantedAtItsPath(t *testing.T) {
	pretendRoot(t, true)
	root := filepath.Join(t.TempDir(), "etc")
	dir := filepath.Join(root, "credentials")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "telegram-token")); err != nil {
		t.Fatal(err)
	}
	stdinFrom(t, "value\n")
	var out bytes.Buffer
	err := runBootstrapCredential(context.Background(), &out, credentialArgs(root, "telegram-token"))
	if err == nil || !strings.Contains(err.Error(), "open ") {
		t.Errorf("err = %v, want the open to be refused", err)
	}
	if data, _ := os.ReadFile(victim); string(data) != "untouched" {
		t.Errorf("the symlink target was written: %q", data)
	}
}
