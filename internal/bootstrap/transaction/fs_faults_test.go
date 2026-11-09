package transaction

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type faultyTemp struct {
	*os.File
	fail   string
	closes int
}

func (f *faultyTemp) boom(step string) error {
	if f.fail == step {
		return errors.New("injected " + step + " failure")
	}
	return nil
}
func (f *faultyTemp) Chmod(m os.FileMode) error {
	if err := f.boom("chmod"); err != nil {
		return err
	}
	return f.File.Chmod(m)
}
func (f *faultyTemp) Chown(u, g int) error {
	if err := f.boom("chown"); err != nil {
		return err
	}
	return f.File.Chown(u, g)
}
func (f *faultyTemp) Write(p []byte) (int, error) {
	if err := f.boom("write"); err != nil {
		return 0, err
	}
	return f.File.Write(p)
}
func (f *faultyTemp) Sync() error {
	if err := f.boom("sync"); err != nil {
		return err
	}
	return f.File.Sync()
}
func (f *faultyTemp) Close() error {
	f.closes++
	err := f.File.Close()
	if bad := f.boom("close"); bad != nil {
		return bad
	}
	return err
}

func owned(t *testing.T) (dir string, uid, gid uint32) {
	t.Helper()
	dir = t.TempDir()
	// A group-writable temp dir (umask 002) is itself refused as a parent.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid, err = owner(info)
	if err != nil {
		t.Fatal(err)
	}
	return dir, uid, gid
}

func TestEachAtomicWriteStepFailsByNameAndLeavesTheTargetAndNoTemporary(t *testing.T) {
	for _, step := range []string{"chmod", "chown", "write", "sync", "close"} {
		t.Run(step, func(t *testing.T) {
			dir, uid, gid := owned(t)
			target := filepath.Join(dir, "managed.json")
			if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			var made *faultyTemp
			old := openTemporary
			openTemporary = func(name string, mode os.FileMode) (writableFile, error) {
				f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
				if err != nil {
					return nil, err
				}
				made = &faultyTemp{File: f, fail: step}
				return made, nil
			}
			t.Cleanup(func() { openTemporary = old })

			err := atomicWrite(target, []byte("new"), 0o600, uid, gid)
			if err == nil || !strings.Contains(err.Error(), step) || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("err = %v, want it to name %q and carry the cause", err, step)
			}
			if got, _ := os.ReadFile(target); string(got) != "original" {
				t.Errorf("a failed write changed the target: %q", got)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 1 {
				t.Errorf("a temporary file leaked: %v", entries)
			}
			if made.closes == 0 {
				t.Error("the temporary file was never closed")
			}
		})
	}
}

func TestAtomicWriteRefusesAnUnsafeOrMissingParent(t *testing.T) {
	dir, uid, gid := owned(t)
	if err := atomicWrite(filepath.Join(dir, "missing", "f"), []byte("x"), 0o600, uid, gid); err == nil || !strings.Contains(err.Error(), "inspect parent") {
		t.Errorf("missing parent: %v", err)
	}
	file := filepath.Join(dir, "file")
	os.WriteFile(file, nil, 0o600)
	if err := atomicWrite(filepath.Join(file, "f"), []byte("x"), 0o600, uid, gid); err == nil {
		t.Error("a parent that is a regular file was accepted")
	}
	loose := filepath.Join(dir, "loose")
	os.Mkdir(loose, 0o755)
	os.Chmod(loose, 0o777)
	if err := atomicWrite(filepath.Join(loose, "f"), []byte("x"), 0o600, uid, gid); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("a world-writable parent: %v", err)
	}
	if err := atomicWrite("relative/f", []byte("x"), 0o600, uid, gid); err == nil {
		t.Error("a relative path was accepted")
	}
}

func TestAtomicWriteReportsATemporaryItCannotCreateAndARenameThatFails(t *testing.T) {
	dir, uid, gid := owned(t)
	old := openTemporary
	openTemporary = func(string, os.FileMode) (writableFile, error) { return nil, errors.New("disk full") }
	if err := atomicWrite(filepath.Join(dir, "f"), []byte("x"), 0o600, uid, gid); err == nil || !strings.Contains(err.Error(), "create temporary file") {
		t.Errorf("create failure: %v", err)
	}
	openTemporary = old

	// Renaming a file over a non-empty directory fails.
	target := filepath.Join(dir, "d")
	os.MkdirAll(filepath.Join(target, "child"), 0o755)
	if err := atomicWrite(target, []byte("x"), 0o600, uid, gid); err == nil || !strings.Contains(err.Error(), "replace") {
		t.Errorf("rename failure: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("a temporary file leaked: %v", entries)
	}
}

func TestDurableRemoveCoversEveryOutcome(t *testing.T) {
	dir, _, _ := owned(t)
	file := filepath.Join(dir, "f")
	os.WriteFile(file, []byte("x"), 0o600)
	if err := durableRemove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); err == nil {
		t.Error("the file is still there")
	}
	// Already gone, parent present: still synced, no error.
	if err := durableRemove(file); err != nil {
		t.Errorf("removing an absent file: %v", err)
	}
	// Parent gone as well: nothing to do.
	if err := durableRemove(filepath.Join(dir, "no-dir", "f")); err != nil {
		t.Errorf("removing under an absent parent: %v", err)
	}
	// A non-empty directory cannot be removed as a file.
	full := filepath.Join(dir, "full")
	os.MkdirAll(filepath.Join(full, "child"), 0o755)
	if err := durableRemove(full); err == nil || !strings.Contains(err.Error(), "remove") {
		t.Errorf("non-empty directory: %v", err)
	}
	if err := durableRemove("relative"); err == nil {
		t.Error("a relative path was accepted")
	}
	link := filepath.Join(dir, "link")
	os.Symlink(dir, link)
	if err := durableRemove(filepath.Join(link, "f")); err == nil {
		t.Error("a path through a symlink was accepted")
	}
}

func TestSyncDirNamesWhatFailed(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := syncDir(filepath.Join(t.TempDir(), "absent")); err == nil || !strings.Contains(err.Error(), "open directory") {
		t.Errorf("absent directory: %v", err)
	}
	// procfs refuses fsync on a directory, which reaches the sync error.
	if err := syncDir("/proc/self"); err == nil {
		t.Skip("this kernel lets procfs directories be synced")
	} else if !strings.Contains(err.Error(), "sync directory") {
		t.Errorf("procfs: %v", err)
	}
}

func TestReadRegularRefusesWhatIsNotAPlainFile(t *testing.T) {
	dir, _, _ := owned(t)
	if snap, err := readRegular(filepath.Join(dir, "absent")); snap != nil || err != nil {
		t.Errorf("absent: %v %v", snap, err)
	}
	if _, err := readRegular(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("directory: %v", err)
	}
	target := filepath.Join(dir, "t")
	os.WriteFile(target, []byte("x"), 0o600)
	link := filepath.Join(dir, "l")
	os.Symlink(target, link)
	if _, err := readRegular(link); err == nil {
		t.Error("a symlink was read as a file")
	}
	snap, err := readRegular(target)
	if err != nil || string(snap.data) != "x" || snap.mode != 0o600 || snap.digest == "" {
		t.Errorf("plain file: %+v %v", snap, err)
	}
}

func TestEnsureDirOwnedCreatesRefusesAndChecksOwnership(t *testing.T) {
	dir, uid, gid := owned(t)
	nested := filepath.Join(dir, "a", "b")
	if err := ensureDirOwned(nested, 0o700, uid, gid, nil); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(nested); info.Mode().Perm() != 0o700 {
		t.Errorf("mode = %v", info.Mode().Perm())
	}
	if err := ensureDirOwned(nested, 0o700, uid+1, gid, nil); err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Errorf("wrong owner: %v", err)
	}
	if err := ensureDirOwned(nested, 0o700, uid+1, gid, func(string, uint32, uint32) bool { return true }); err != nil {
		t.Errorf("an allowed owner was refused: %v", err)
	}
	file := filepath.Join(dir, "file")
	os.WriteFile(file, nil, 0o600)
	if err := ensureDirOwned(file, 0o700, uid, gid, nil); err == nil || !strings.Contains(err.Error(), "not a") {
		t.Errorf("a file as a directory: %v", err)
	}
	loose := filepath.Join(dir, "loose")
	os.Mkdir(loose, 0o700)
	os.Chmod(loose, 0o770)
	if err := ensureDirOwned(loose, 0o700, uid, gid, nil); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("group-writable: %v", err)
	}
	if err := ensurePrivateDir(filepath.Join(dir, "priv"), uid, gid); err != nil {
		t.Fatal(err)
	}
	open := filepath.Join(dir, "open")
	os.Mkdir(open, 0o755)
	if err := ensurePrivateDir(open, uid, gid); err == nil || !strings.Contains(err.Error(), "exposes") {
		t.Errorf("a readable private dir: %v", err)
	}
}
