// Package secret reads the fixed-name credentials bootstrap needs and keeps
// their values out of everything that gets printed, journalled or stored.
package secret

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
	"golang.org/x/sys/unix"
)

// Store resolves a logical credential name to its value.
//
// Logical names rather than paths, because desired state is reviewable and
// stored in the clear: a path there would let a document choose which file root
// reads, and "credentials" would become an arbitrary-read primitive the moment
// a remote control plane could write that document.
type Store struct {
	// Dir is the credential directory, normally <configRoot>/credentials.
	Dir string
	// UID is the owner every credential must have. Zero for a real install;
	// tests point it at their own uid because they cannot create root files.
	UID uint32
}

// Read returns the credential's value with surrounding whitespace removed.
//
// The checks are the same ones discovery reports in a plan, repeated here on
// purpose: discovery runs before apply and the file could change in between,
// and a credential is the one input where reading a file that became
// world-readable is worse than failing.
func (s Store) Read(reference state.SecretRef) (string, error) {
	if err := reference.Validate("credential reference"); err != nil {
		return "", err
	}
	if s.Dir == "" || !filepath.IsAbs(s.Dir) || filepath.Clean(s.Dir) != s.Dir {
		return "", fmt.Errorf("credential directory must be a clean absolute path")
	}

	path := filepath.Join(s.Dir, string(reference))
	// O_NOFOLLOW so a symlink planted in the credential directory cannot
	// redirect the read, and the open itself carries the type check.
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", fmt.Errorf("open credential %s: %w", reference, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect credential %s: %w", reference, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("credential %s is not a regular file", reference)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("credential %s has mode %04o, which exposes it to group or other", reference, info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("cannot determine the owner of credential %s", reference)
	}
	if stat.Uid != s.UID {
		return "", fmt.Errorf("credential %s is owned by uid %d, want %d", reference, stat.Uid, s.UID)
	}

	// Bounded: a credential is a token, and a multi-megabyte "credential" is a
	// mistake worth refusing rather than loading into memory and interpolating
	// into a config.
	const maxSize = 16 << 10
	if info.Size() > maxSize {
		return "", fmt.Errorf("credential %s is larger than %d bytes", reference, maxSize)
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return "", fmt.Errorf("read credential %s: %w", reference, err)
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", fmt.Errorf("credential %s is empty", reference)
	}
	if strings.ContainsAny(value, "\n\r") {
		return "", fmt.Errorf("credential %s contains more than one line", reference)
	}
	return value, nil
}

// Resolver returns the lookup function the generators take, so a caller that
// must not touch credentials can pass one that refuses instead.
func (s Store) Resolver() func(state.SecretRef) (string, error) {
	return s.Read
}

// Refuse is the resolver for code paths that are not allowed to read
// credentials, such as planning and validation.
func Refuse(reference state.SecretRef) (string, error) {
	return "", fmt.Errorf("credential %s cannot be read here: this operation must not resolve secrets", reference)
}

// Redact replaces every known secret value in text with a fixed marker.
//
// For diagnostics only. It is a last line of defence, not a licence to pass
// secrets through log paths: command output is captured and shown on failure,
// and a token that reaches a container's startup error would otherwise be
// printed with it.
func Redact(text string, values ...string) string {
	for _, value := range values {
		if len(value) < 8 {
			continue
		}
		text = strings.ReplaceAll(text, value, "[redacted]")
	}
	return text
}
