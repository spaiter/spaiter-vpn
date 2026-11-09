package backup

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
)

func TestReadNamesEachWayAnArchiveCanBeUnusable(t *testing.T) {
	sound := `{"format":"` + Format + `","files":[{"root":"config","path":"a","mode":384,"size":1,"sha256":"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}]}`
	cases := map[string]struct {
		build func(tw *tar.Writer)
		want  string
	}{
		"empty archive":     {func(tw *tar.Writer) {}, "read the manifest"},
		"manifest not json": {func(tw *tar.Writer) { put(tw, manifestName, "{") }, "parse the manifest"},
		"other format":      {func(tw *tar.Writer) { put(tw, manifestName, `{"format":"other/v9","files":[]}`) }, "unsupported backup format"},
		"unknown root": {func(tw *tar.Writer) {
			put(tw, manifestName, `{"format":"`+Format+`","files":[{"root":"elsewhere","path":"a","size":1}]}`)
		}, "unknown backup root"},
		"size mismatch": {func(tw *tar.Writer) {
			put(tw, manifestName, sound)
			put(tw, "config/a", "aa")
		}, "does not match its manifest entry"},
		"not a regular file": {func(tw *tar.Writer) {
			put(tw, manifestName, sound)
			tw.WriteHeader(&tar.Header{Name: "config/a", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
		}, "does not match"},
		"entry named twice": {func(tw *tar.Writer) {
			put(tw, manifestName, sound)
			put(tw, "config/a", "a")
			put(tw, "config/a", "a")
		}, "does not name"},
	}
	for name, c := range cases {
		data, identity := encryptTar(t, c.build)
		if _, err := Read(bytes.NewReader(data), identity); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}

	// Not an age file at all, and a key that does not open it.
	if _, err := Read(strings.NewReader("plain text"), mustIdentity(t)); err == nil || errors.Is(err, ErrWrongKey) {
		t.Errorf("plain text: %v", err)
	}
	data, _ := encryptTar(t, func(tw *tar.Writer) { put(tw, manifestName, sound) })
	if _, err := Read(bytes.NewReader(data), mustIdentity(t)); !errors.Is(err, ErrWrongKey) {
		t.Errorf("wrong key: %v", err)
	}
}

func mustIdentity(t *testing.T) age.Identity {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func TestAnArchiveCutShortIsNotMistakenForACompleteOne(t *testing.T) {
	snap := sampleSnapshot(t)
	identity := mustIdentity(t).(*age.X25519Identity)
	var full bytes.Buffer
	if err := snap.Write(&full, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	for _, cut := range []int{full.Len() / 2, full.Len() - 40} {
		if _, err := Read(bytes.NewReader(full.Bytes()[:cut]), identity); err == nil {
			t.Errorf("an archive cut at %d of %d was accepted", cut, full.Len())
		}
	}
}

type failingWriter struct{ after int }

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.after <= 0 {
		return 0, errors.New("disk full")
	}
	f.after -= len(p)
	return len(p), nil
}

func TestWriteReportsAWriterThatFailsAtAnyPoint(t *testing.T) {
	snap := sampleSnapshot(t)
	identity := mustIdentity(t).(*age.X25519Identity)
	var failures int
	for after := 0; after < 4000; after += 150 {
		if err := snap.Write(&failingWriter{after: after}, identity.Recipient()); err != nil {
			failures++
		}
	}
	if failures == 0 {
		t.Error("a failing writer never failed the write")
	}
	if err := snap.Write(io.Discard); err == nil {
		t.Error("a write with no recipient succeeded")
	}
}

func TestAddAndAddTreeSkipWhatIsNotAFileAndReportWhatIsUnreadable(t *testing.T) {
	dir := t.TempDir()
	s := &Snapshot{}
	if err := s.Add(RootConfig, "a", filepath.Join(dir, "absent")); err != nil || len(s.Files) != 0 {
		t.Errorf("absent: %v, %d files", err, len(s.Files))
	}
	if err := s.Add(RootConfig, "d", dir); err != nil || len(s.Files) != 0 {
		t.Errorf("directory: %v, %d files", err, len(s.Files))
	}
	if err := s.AddTree(RootConfig, "x", filepath.Join(dir, "absent"), nil); err != nil {
		t.Errorf("absent tree: %v", err)
	}

	if os.Geteuid() != 0 {
		secret := filepath.Join(dir, "secret")
		if err := os.WriteFile(secret, []byte("s"), 0o000); err != nil {
			t.Fatal(err)
		}
		if err := s.Add(RootConfig, "secret", secret); err == nil {
			t.Error("an unreadable file was skipped silently")
		}
		if err := s.AddTree(RootConfig, "tree", dir, nil); err == nil {
			t.Error("an unreadable file in a tree was skipped silently")
		}
		os.Chmod(secret, 0o600)
		locked := filepath.Join(dir, "locked")
		if err := os.Mkdir(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		if err := s.AddTree(RootConfig, "tree", dir, nil); err == nil {
			t.Error("an unreadable directory was skipped silently")
		}
		os.Chmod(locked, 0o700)
	}

	// An unsafe relative path is refused even for a real file.
	file := filepath.Join(dir, "real")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(RootConfig, "../escape", file); err == nil {
		t.Error("an escaping path was accepted")
	}
	if _, ok := s.Lookup(RootConfig, "nothing"); ok {
		t.Error("Lookup found a file that was never added")
	}
}

func TestCollectReportsEachPartThatCannotBeRead(t *testing.T) {
	// A statistics database that is not a database.
	layout, _ := makeDeployment(t)
	putFile(t, filepath.Join(layout.DeploymentDir(), "user_stats.db"), 0o600, "this is not sqlite")
	if _, err := Collect(layout, "dev"); err == nil || !strings.Contains(err.Error(), "traffic accounting") {
		t.Errorf("corrupt database: %v", err)
	}

	if os.Geteuid() == 0 {
		return
	}
	for name, dir := range map[string]func(l discover.Layout) string{
		"credentials": func(l discover.Layout) string { return l.CredentialDir() },
		"bot state":   func(l discover.Layout) string { return l.BotDataDir() },
		"core cache":  func(l discover.Layout) string { return l.CacheDir() },
	} {
		layout, _ := makeDeployment(t)
		locked := dir(layout)
		if err := os.MkdirAll(filepath.Join(locked, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		_, err := Collect(layout, "dev")
		os.Chmod(locked, 0o755)
		if err == nil {
			t.Errorf("%s: an unreadable directory was skipped", name)
		}
	}
}

func TestWriteFileReportsADirectoryItCannotCreate(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	putFile(t, blocker, 0o600, "x")
	if err := writeFile(filepath.Join(blocker, "sub", "f"), []byte("x"), 0o600); err == nil {
		t.Error("a path under a file was written")
	}
	dir := t.TempDir()
	if err := writeFile(filepath.Join(dir, "target"), []byte("data"), 0o640); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(dir, "target")); err != nil || info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, %v", info, err)
	}
}
