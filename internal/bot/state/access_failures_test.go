package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// spoil replaces a state file with something that is not valid JSON, or, with
// asDir, with a directory so that even reading it fails.
func spoil(t *testing.T, s *Store, name string, asDir bool) {
	t.Helper()
	path := s.Path(name)
	os.RemoveAll(path)
	if asDir {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAccessOperationsReportUnreadableFilesInsteadOfOverwritingThem(t *testing.T) {
	for _, asDir := range []bool{false, true} {
		s, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		spoil(t, s, "users.json", asDir)
		spoil(t, s, "whitelist.json", asDir)
		spoil(t, s, "admins.json", asDir)
		spoil(t, s, "pending.json", asDir)
		for name, call := range map[string]func() error{
			"Register":   func() error { return s.Register(User{ID: 1}) },
			"Deny":       func() error { return s.Deny(1) },
			"Allow":      func() error { return s.Allow(1) },
			"AddAdmin":   func() error { return s.AddAdmin(1) },
			"AddPending": func() error { return s.AddPending(1) },
			"PopPending": func() error { return s.PopPending(1) },
		} {
			if err := call(); err == nil {
				t.Errorf("asDir=%v %s: a spoiled file was accepted", asDir, name)
			}
		}
	}
}

func TestClaimSurfacesStorageFailures(t *testing.T) {
	now := time.Now()
	s, _ := New(t.TempDir())
	code, err := s.IssueClaim(time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	// The claim is right but the admin list cannot be updated.
	spoil(t, s, "admins.json", false)
	if ok, err := s.Claim(code, 7, now); ok || err == nil {
		t.Errorf("claim with a broken admin list = %v, %v", ok, err)
	}

	// The claim file cannot be written: a directory sits where it goes.
	s2, _ := New(t.TempDir())
	if err := os.MkdirAll(filepath.Join(s2.claimPath(), "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.IssueClaim(time.Hour, now); err == nil {
		t.Error("a claim was issued over a directory")
	}
}

func TestWARPAccountRefusesAnAccountThatIsNotAnObject(t *testing.T) {
	s, _ := New(t.TempDir())
	if err := os.MkdirAll(s.Path("warp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Path("warp", "u.json"), []byte(`[1]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.WARPAccount("u"); err == nil || found {
		t.Errorf("array account = %v, %v", found, err)
	}
}

func TestReadJSONNamesUnreadablePaths(t *testing.T) {
	dir := t.TempDir()
	var v any
	if found, err := readJSON(dir, &v); found || err == nil {
		t.Errorf("directory read = %v, %v", found, err)
	}
}
