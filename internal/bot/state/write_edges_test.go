package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicWritesNameWhatFailed(t *testing.T) {
	dir := t.TempDir()
	if err := writeAtomic(filepath.Join(dir, "absent", "f"), []byte("x"), 0o600); err == nil || !strings.Contains(err.Error(), "temp file beside") {
		t.Errorf("missing directory: %v", err)
	}
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(target, []byte("x"), 0o600); err == nil || !strings.Contains(err.Error(), "rename onto") {
		t.Errorf("rename over a directory: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("a temporary file was left behind: %v", entries)
	}
	if err := writeJSON(filepath.Join(dir, "j.json"), make(chan int), 0o600); err == nil {
		t.Error("an unmarshalable value was written")
	}
}

func TestSharedFilesFallBackToRewritingInPlaceWhenTheDirectoryIsReadOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	if err := writeShared(path, []byte("new contents")); err != nil {
		t.Fatalf("in-place rewrite: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "new contents" {
		t.Errorf("file = %q", got)
	}
	// The file itself unwritable as well: both ways are reported.
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := writeShared(path, []byte("x")); err == nil || !strings.Contains(err.Error(), "rewrite") {
		t.Errorf("fully read-only: %v", err)
	}
}

func TestClaimRemovalToleratesAnAlreadyRemovedFile(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.removeClaim(); err != nil {
		t.Errorf("no claim: %v", err)
	}
	// A directory in the way cannot be removed as a file.
	if err := os.MkdirAll(filepath.Join(s.claimPath(), "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.removeClaim(); err == nil {
		t.Error("a non-removable claim was ignored")
	}
}
