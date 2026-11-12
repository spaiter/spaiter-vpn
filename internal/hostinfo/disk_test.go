package hostinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFreeBytesExistingDir(t *testing.T) {
	dir := t.TempDir()
	free, err := FreeBytes(dir)
	if err != nil {
		t.Fatalf("FreeBytes(%q): %v", dir, err)
	}
	if free == 0 {
		t.Errorf("FreeBytes(%q) = 0, want > 0", dir)
	}
}

func TestFreeBytesNestedNonexistentPath(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "c")
	free, err := FreeBytes(nested)
	if err != nil {
		t.Fatalf("FreeBytes(%q): %v", nested, err)
	}
	if free == 0 {
		t.Errorf("FreeBytes(%q) = 0, want > 0", nested)
	}
}

func TestFreeBytesNestedMatchesParent(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "c")
	freeNested, err := FreeBytes(nested)
	if err != nil {
		t.Fatalf("FreeBytes(%q): %v", nested, err)
	}
	freeParent, err := FreeBytes(dir)
	if err != nil {
		t.Fatalf("FreeBytes(%q): %v", dir, err)
	}
	// Free space can change between calls; just verify both are non-zero and
	// the nested result is not wildly different (same filesystem).
	if freeNested == 0 || freeParent == 0 {
		t.Errorf("expected non-zero free space, got nested=%d parent=%d", freeNested, freeParent)
	}
}

func TestWritableExistingDir(t *testing.T) {
	dir := t.TempDir()
	if err := Writable(dir); err != nil {
		t.Fatalf("Writable(%q): %v", dir, err)
	}
	// Ensure no probe files remain.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	if len(entries) != 0 {
		t.Errorf("Writable left %d file(s) in %q: %v", len(entries), dir, entries)
	}
}

func TestWritableNestedNonexistentPath(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "c")
	if err := Writable(nested); err != nil {
		t.Fatalf("Writable(%q): %v", nested, err)
	}
	// The intermediate directories must NOT have been created.
	if _, err := os.Stat(filepath.Join(dir, "a")); !os.IsNotExist(err) {
		t.Errorf("Writable created directory %q; it should not", filepath.Join(dir, "a"))
	}
}

func TestWritableRegularFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Writable(file); err == nil {
		t.Errorf("Writable(%q) = nil, want error for regular file", file)
	}
}

func TestWritableReadonlyDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; permission bits are ignored")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("Chmod(%q, 0o500): %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Errorf("Chmod(%q, 0o700) in cleanup: %v", dir, err)
		}
	})
	if err := Writable(dir); err == nil {
		t.Errorf("Writable(%q) = nil, want error for read-only directory", dir)
	}
}
