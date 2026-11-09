package corelog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMissingOrUnreadableLogsAreNamed(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent.log")
	if _, err := Offset(absent); err == nil || !strings.Contains(err.Error(), "stat") {
		t.Errorf("Offset: %v", err)
	}
	if _, err := ReadSince(absent, 0); err == nil || !strings.Contains(err.Error(), "open") {
		t.Errorf("ReadSince: %v", err)
	}
	if _, err := ReadAll(absent); err == nil {
		t.Errorf("ReadAll of an absent file succeeded")
	}
	// A directory opens but cannot be read.
	if _, err := ReadSince(t.TempDir(), 0); err == nil || !strings.Contains(err.Error(), "read") {
		t.Errorf("a directory was read as a log: %v", err)
	}
}

func TestReadAllAndContainsCoverTheWholeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core.log")
	if err := os.WriteFile(path, []byte("first\nsecond marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	slice, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slice.Contains("marker") || slice.Contains("absent") || slice.Lines() != 2 {
		t.Errorf("slice = %+v", slice)
	}
}

func TestSourceAddrKeepsABareHostAsIs(t *testing.T) {
	if sourceAddr("10.0.0.1:5000") != "10.0.0.1" || sourceAddr("nohost") != "nohost" || sourceAddr(":80") != ":80" {
		t.Error("sourceAddr")
	}
}
