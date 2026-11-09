package dockerinstall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPreconditionsReportAptSourcesTheyCannotInspect(t *testing.T) {
	installer := newInstaller(t, &fakeRunner{})
	dir := filepath.Join(installer.Root, "etc/apt/sources.list.d")
	os.RemoveAll(dir)
	if err := os.WriteFile(dir, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := installer.Preconditions(context.Background()); err == nil || !strings.Contains(err.Error(), "inspect apt sources") {
		t.Errorf("sources.list.d is a file: %v", err)
	}

	installer = newInstaller(t, &fakeRunner{})
	if err := os.Mkdir(filepath.Join(installer.Root, "etc/apt/sources.list"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := installer.Preconditions(context.Background()); err == nil || !strings.Contains(err.Error(), "read apt source") {
		t.Errorf("sources.list is a directory: %v", err)
	}
}

func TestInstallWithoutAClockUsesTheSystemOne(t *testing.T) {
	release, _ := For("ubuntu", "24.04")
	installer := newInstaller(t, &fakeRunner{engine: release.EngineVersion, compose: release.ComposeVersion})
	installer.Now = nil
	record, err := installer.Install(context.Background(), release, false)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(record.InstalledAt) > time.Minute {
		t.Errorf("installed at %v", record.InstalledAt)
	}
}

func TestInstallStopsWhenItsRepositoryFileBelongsToSomeoneElse(t *testing.T) {
	release, _ := For("ubuntu", "24.04")
	installer := newInstaller(t, &fakeRunner{engine: release.EngineVersion, compose: release.ComposeVersion})
	path := filepath.Join(installer.Root, SourcesPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("other"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Install(context.Background(), release, false); err == nil || !strings.Contains(err.Error(), "not ours to replace") {
		t.Errorf("foreign sources file: %v", err)
	}
}

func TestInstallReportsADaemonThatNeverAnswersWhenTheContextEnds(t *testing.T) {
	release, _ := For("ubuntu", "24.04")
	runner := &fakeRunner{compose: release.ComposeVersion, fail: map[string]error{"docker version": exitOne{}}}
	installer := newInstaller(t, runner)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	record, err := installer.Install(ctx, release, false)
	if err == nil {
		t.Fatal("an install without a daemon succeeded")
	}
	if record.Release == "" {
		t.Error("the partial record was dropped, so the cleanup cannot know what was installed")
	}
}

func TestWriteOwnedFailsCleanlyInAnUnwritableTree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "etc")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(locked, 0o700)
	installer := Installer{Root: root}
	// The directory to create does not exist and cannot be made.
	if err := installer.writeOwned("/etc/apt/key", []byte("k")); err == nil {
		t.Error("a directory was created in a read-only tree")
	}
	// The directory exists but a temporary file cannot be created in it.
	if err := installer.writeOwned("/etc/key", []byte("k")); err == nil {
		t.Error("a file was created in a read-only directory")
	}
}

func TestRecordFilesFailWithTheirPathNamed(t *testing.T) {
	dir := t.TempDir()
	if err := WriteRecord(dir, Record{}); err == nil {
		t.Error("a record was written over a directory")
	}
	if _, err := ReadRecord(dir); err == nil {
		t.Error("a directory was read as a record")
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRecord(bad); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("corrupt record: %v", err)
	}
	// A corrupt earlier record is replaced rather than merged.
	if err := WriteRecord(bad, Record{Engine: "1"}); err != nil {
		t.Errorf("replacing a corrupt record: %v", err)
	}

	if os.Geteuid() == 0 {
		return
	}
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(locked, 0o700)
	if err := WriteRecord(filepath.Join(locked, "sub", "r.json"), Record{}); err == nil {
		t.Error("a directory was created in a read-only directory")
	}
	if err := WriteRecord(filepath.Join(locked, "r.json"), Record{}); err == nil {
		t.Error("a record was written into a read-only directory")
	}
}
