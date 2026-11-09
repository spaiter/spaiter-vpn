package singbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDescribeNamesHowTheCheckRuns(t *testing.T) {
	if got := (&Checker{Binary: "/usr/bin/sing-box"}).Describe(); got != "/usr/bin/sing-box check" {
		t.Errorf("binary = %q", got)
	}
	got := (&Checker{Docker: []string{"sudo", "docker"}, Image: "img:1"}).Describe()
	if got != "sudo docker run --rm img:1 check" {
		t.Errorf("docker = %q", got)
	}
}

func TestACheckErrorWithoutOutputStillSaysWhatHappened(t *testing.T) {
	if got := (&CheckError{ExitCode: 3}).Error(); !strings.Contains(got, "exit 3") || !strings.Contains(got, "without explaining") {
		t.Errorf("silent rejection = %q", got)
	}
	if got := (&CheckError{ExitCode: 1, Output: "bad field"}).Error(); !strings.HasSuffix(got, "bad field") {
		t.Errorf("explained rejection = %q", got)
	}
}

func TestScratchDirectoryFailuresAreReportedByStep(t *testing.T) {
	ctx := context.Background()
	c := &Checker{Binary: "/bin/true"}

	// With TMPDIR somewhere that cannot be written, no scratch can be made.
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
	if err := c.Check(ctx, []byte("{}")); err == nil || !strings.Contains(err.Error(), "create temporary directory") {
		t.Errorf("Check: %v", err)
	}
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "a.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckDirectory(ctx, source); err == nil || !strings.Contains(err.Error(), "create temporary directory") {
		t.Errorf("CheckDirectory: %v", err)
	}
}

func TestAnUnreadableJSONFileStopsTheDirectoryCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.json")
	if err := os.WriteFile(path, []byte("{}"), 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads anything")
	}
	if err := (&Checker{Binary: "/bin/true"}).CheckDirectory(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "read a.json") {
		t.Errorf("unreadable file: %v", err)
	}
}
