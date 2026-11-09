package transaction

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type fileSnapshot struct {
	data   []byte
	mode   os.FileMode
	uid    uint32
	gid    uint32
	digest string
}

func readRegular(path string) (*fileSnapshot, error) {
	if err := rejectSymlinkParents(path); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lstat %s: %w", path, err)
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s without following symlinks: %w", path, err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat open %s: %w", path, err)
	}
	if !os.SameFile(before, after) {
		return nil, fmt.Errorf("%s changed while it was being inspected", path)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	uid, gid, err := owner(after)
	if err != nil {
		return nil, fmt.Errorf("owner of %s: %w", path, err)
	}
	return &fileSnapshot{data: data, mode: after.Mode().Perm(), uid: uid, gid: gid, digest: digest(data)}, nil
}

func owner(info os.FileInfo) (uint32, uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("unsupported file metadata type %T", info.Sys())
	}
	return stat.Uid, stat.Gid, nil
}

func rejectSymlinkParents(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path {
		return fmt.Errorf("path %q is not a clean absolute path", path)
	}
	parent := filepath.Dir(clean)
	parts := strings.Split(strings.TrimPrefix(parent, string(filepath.Separator)), string(filepath.Separator))
	current := string(filepath.Separator)
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("lstat parent %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("parent %s is a symlink", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("parent %s is not a directory", current)
		}
	}
	return nil
}

func ensureDir(path string, mode os.FileMode, uid, gid uint32) error {
	return ensureDirOwned(path, mode, uid, gid, nil)
}

// ensureDirOwned is ensureDir with a wider set of acceptable owners for an
// existing directory; created directories still get uid:gid.
func ensureDirOwned(path string, mode os.FileMode, uid, gid uint32, allowed func(dir string, uid, gid uint32) bool) error {
	if err := rejectSymlinkParents(filepath.Join(path, ".target")); err != nil {
		return err
	}
	var missing []string
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%s is not a real directory", current)
			}
			break
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("inspect directory %s: %w", current, err)
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("no existing ancestor for directory %s", path)
		}
	}
	for index := len(missing) - 1; index >= 0; index-- {
		current := missing[index]
		if err := os.Mkdir(current, mode); err != nil {
			return fmt.Errorf("create directory %s: %w", current, err)
		}
		if err := os.Chown(current, int(uid), int(gid)); err != nil {
			return fmt.Errorf("own directory %s: %w", current, err)
		}
		if err := os.Chmod(current, mode); err != nil {
			return fmt.Errorf("chmod directory %s: %w", current, err)
		}
		if err := syncDir(filepath.Dir(current)); err != nil {
			return err
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect directory %s: %w", path, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real directory", path)
	}
	actualUID, actualGID, err := owner(info)
	if err != nil {
		return err
	}
	if (actualUID != uid || actualGID != gid) && (allowed == nil || !allowed(path, actualUID, actualGID)) {
		return fmt.Errorf("directory %s is owned by %d:%d, want %d:%d", path, actualUID, actualGID, uid, gid)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("directory %s mode %04o is group/other writable", path, info.Mode().Perm())
	}
	return nil
}

func ensurePrivateDir(path string, uid, gid uint32) error {
	if err := ensureDir(path, 0o700, uid, gid); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private directory %s mode %04o exposes transaction data", path, info.Mode().Perm())
	}
	return nil
}

// writableFile is the part of *os.File atomicWrite uses; a seam so tests can
// make each step fail, which a real file system will not do on request.
type writableFile interface {
	Chmod(os.FileMode) error
	Chown(uid, gid int) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

var openTemporary = func(name string, mode os.FileMode) (writableFile, error) {
	return os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
}

func atomicWrite(path string, data []byte, mode os.FileMode, uid, gid uint32) error {
	if err := rejectSymlinkParents(path); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect parent directory %s: %w", parent, err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("parent %s is not a real directory", parent)
	}
	if parentInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("parent %s mode %04o is group/other writable", parent, parentInfo.Mode().Perm())
	}
	suffix, err := randomHex(8)
	if err != nil {
		return err
	}
	temporary := filepath.Join(parent, "."+filepath.Base(path)+".tmp-"+suffix)
	file, err := openTemporary(temporary, mode)
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	cleanup := true
	defer func() {
		file.Close()
		if cleanup {
			os.Remove(temporary)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("chmod temporary file for %s: %w", path, err)
	}
	if err := file.Chown(int(uid), int(gid)); err != nil {
		return fmt.Errorf("chown temporary file for %s: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write temporary file for %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary file for %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary file for %s: %w", path, err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	cleanup = false
	return syncDir(parent)
}

func durableRemove(path string) error {
	if err := rejectSymlinkParents(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			if _, parentErr := os.Stat(filepath.Dir(path)); os.IsNotExist(parentErr) {
				return nil
			}
		} else {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory %s for sync: %w", path, err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync directory %s: %w", path, err)
	}
	return nil
}

func randomHex(bytes int) (string, error) {
	data := make([]byte, bytes)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate random identifier: %w", err)
	}
	return hex.EncodeToString(data), nil
}
