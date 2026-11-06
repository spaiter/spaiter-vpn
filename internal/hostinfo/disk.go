package hostinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// FreeBytes returns the space available to an unprivileged writer at path. If
// path does not exist yet, the nearest existing ancestor is measured, since
// that is the filesystem the directory will be created on.
//
// Bavail rather than Bfree: the difference is the reserved blocks only root
// may use, and reporting those as available would promise space an
// unprivileged process cannot have.
func FreeBytes(path string) (uint64, error) {
	target := path
	for {
		if _, err := os.Stat(target); err == nil {
			break
		}
		parent := filepath.Dir(target)
		if parent == target {
			return 0, fmt.Errorf("no existing ancestor of %s", path)
		}
		target = parent
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(target, &stat); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", target, err)
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}

// HumanBytes formats a byte count the way an operator reads it.
func HumanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n)
	for _, suffix := range []string{"KiB", "MiB", "GiB", "TiB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f PiB", value)
}

// Writable reports whether a directory can be written to, creating nothing
// permanent. If the directory does not exist, the nearest existing ancestor is
// tested, because that is where creation will be attempted.
func Writable(dir string) error {
	target := dir
	for {
		info, err := os.Stat(target)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", target)
			}
			break
		}
		parent := filepath.Dir(target)
		if parent == target {
			return fmt.Errorf("no existing ancestor of %s", dir)
		}
		target = parent
	}

	file, err := os.CreateTemp(target, ".spaiter-vpn-write-probe-*")
	if err != nil {
		return fmt.Errorf("cannot write in %s: %w", target, err)
	}
	name := file.Name()
	file.Close()
	return os.Remove(name)
}
