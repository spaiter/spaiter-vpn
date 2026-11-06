package backup

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/discover"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

// Deployment returns what bootstrap renders the new host from: the desired
// state, and the configuration and handover holding every key and user.
func (s *Snapshot) Deployment() (state.State, []byte, []byte, error) {
	var parts [3][]byte
	for i, rel := range []string{DesiredPath, ConfigPath, SecretsPath} {
		f, ok := s.Lookup(RootConfig, rel)
		if !ok {
			return state.State{}, nil, nil, fmt.Errorf("the archive has no %s", rel)
		}
		parts[i] = f.Data
	}
	desired, err := state.Parse(parts[0])
	if err != nil {
		return state.State{}, nil, nil, fmt.Errorf("parse the archived desired state: %w", err)
	}
	return desired, parts[1], parts[2], nil
}

// rendered names the files bootstrap writes itself from Deployment, so Place
// leaves them alone.
func rendered(f File) bool {
	return f.Root == RootConfig && (f.Path == DesiredPath || f.Path == ConfigPath || f.Path == SecretsPath)
}

// target resolves where a file goes on this host.
func target(layout discover.Layout, relayDir string, f File) (string, error) {
	var base string
	switch f.Root {
	case RootConfig:
		base = layout.ConfigRoot
	case RootData:
		base = layout.DataRoot
	case RootRelay:
		if relayDir == "" {
			return "", fmt.Errorf("the archive holds relay files but the desired state names no relay directory")
		}
		base = relayDir
	default:
		return "", fmt.Errorf("unknown backup root %q", f.Root)
	}
	if err := checkRel(f.Path); err != nil {
		return "", err
	}
	return filepath.Join(base, filepath.FromSlash(f.Path)), nil
}

// ErrNotFresh says the host already has a deployment, which a restore would
// silently replace.
var ErrNotFresh = errors.New("this server already has a deployment")

// CheckFresh refuses a host that already runs a deployment.
//
// A file the archive would place is allowed to exist only with the archive's
// own content, which is what an interrupted restore leaves behind: running it
// again then continues instead of demanding a clean-up first.
func CheckFresh(s *Snapshot, layout discover.Layout, relayDir string) error {
	for _, p := range []string{layout.DesiredPath(), layout.ConfigPath(), layout.SecretsPath(), layout.CurrentReceiptPath()} {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("%w: %s exists. Restore onto a new server, or remove the deployment first", ErrNotFresh, p)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	for _, f := range s.Files {
		if rendered(f) {
			continue
		}
		p, err := target(layout, relayDir, f)
		if err != nil {
			return err
		}
		existing, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, f.Data) {
			return fmt.Errorf("%w: %s exists with other contents", ErrNotFresh, p)
		}
	}
	return nil
}

// Place writes the files that are state rather than rendered output: stored
// credentials, the traffic accounting, the bot's state, the core's cache and
// the relay's passwords. Everything is written as root with the archived mode;
// bootstrap hands the bot's files to its account when it creates it.
//
// It returns the paths written.
func Place(s *Snapshot, layout discover.Layout, relayDir string) ([]string, error) {
	var written []string
	for _, f := range s.Files {
		if rendered(f) {
			continue
		}
		p, err := target(layout, relayDir, f)
		if err != nil {
			return written, err
		}
		if err := writeFile(p, f.Data, fs.FileMode(f.Mode)); err != nil {
			return written, err
		}
		written = append(written, p)
	}
	return written, nil
}

func writeFile(p string, data []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".restore-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode.Perm()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, p)
}
