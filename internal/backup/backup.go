// Package backup writes and reads a deployment's encrypted backup: everything
// a new server needs to come up with the same keys, users and subscriptions.
//
// The point is to keep a copy away from the provider. A Russian hoster's
// management plane was breached in 2026 and its block-level copies wiped, so a
// snapshot the provider holds is not a backup. The archive is therefore written
// to stdout, to be piped over ssh to somewhere else without a copy staying on
// the server, and it is encrypted, because it holds every private key of the
// deployment.
//
// The format is a tar stream inside age (age-encryption.org/v1). A manifest
// comes first and carries the SHA-256 of every file; reading verifies each one
// and refuses an archive with a file the manifest does not name. age is used
// rather than a construction of our own because it is reviewed, small, and an
// operator can open the archive with the stock `age -d` when this binary is
// not at hand.
package backup

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
)

// Format names this layout of the archive.
const Format = "spaiter-vpn-backup/v1"

const manifestName = "manifest.json"

// Root is where a file lives, named rather than given as an absolute path so a
// backup restores into whatever layout the new server has, and so a name in an
// archive can never point outside the directories a restore writes to.
type Root string

const (
	// RootConfig is the configuration root (/etc/spaiter-vpn).
	RootConfig Root = "config"
	// RootData is the data root (/var/lib/spaiter-vpn).
	RootData Root = "data"
	// RootRelay is the WG-over-VK relay's directory, outside both.
	RootRelay Root = "relay"
)

// Entry is one file in the manifest.
type Entry struct {
	Root   Root   `json:"root"`
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest describes an archive.
type Manifest struct {
	Format   string    `json:"format"`
	Created  time.Time `json:"created"`
	Hostname string    `json:"hostname"`
	Version  string    `json:"version"`
	// PublicHost is the address clients were given, so a restore onto a server
	// with another address can say what changes for them.
	PublicHost string  `json:"publicHost"`
	Files      []Entry `json:"files"`
}

// File is one file to back up or one restored from an archive.
type File struct {
	Entry
	Data []byte
}

// Snapshot is a full set of files, ready to write.
type Snapshot struct {
	Manifest Manifest
	Files    []File
}

// Add reads one file into the snapshot. A missing file is not an error: what
// exists depends on which features the deployment runs.
func (s *Snapshot) Add(root Root, rel, source string) error {
	info, err := os.Lstat(source)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return s.AddData(root, rel, info.Mode().Perm(), data)
}

// AddData adds a file whose contents were produced rather than read, such as a
// consistent copy of a live database.
func (s *Snapshot) AddData(root Root, rel string, mode fs.FileMode, data []byte) error {
	if err := checkRel(rel); err != nil {
		return err
	}
	for _, f := range s.Files {
		if f.Root == root && f.Path == rel {
			return fmt.Errorf("%s/%s added twice", root, rel)
		}
	}
	sum := sha256.Sum256(data)
	s.Files = append(s.Files, File{
		Entry: Entry{Root: root, Path: rel, Mode: uint32(mode.Perm()), Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])},
		Data:  data,
	})
	return nil
}

// AddTree adds every regular file under dir. skip, when set, leaves a path
// (relative to dir) out.
func (s *Snapshot) AddTree(root Root, prefix, dir string, skip func(rel string) bool) error {
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && p == dir {
				return fs.SkipDir
			}
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if skip != nil && skip(rel) {
			return nil
		}
		return s.Add(root, path.Join(prefix, rel), p)
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Write encrypts the snapshot to w for the given recipients.
func (s *Snapshot) Write(w io.Writer, recipients ...age.Recipient) error {
	if len(recipients) == 0 {
		return errors.New("no recipient: an unencrypted backup of private keys is not offered")
	}
	sort.Slice(s.Files, func(i, j int) bool {
		if s.Files[i].Root != s.Files[j].Root {
			return s.Files[i].Root < s.Files[j].Root
		}
		return s.Files[i].Path < s.Files[j].Path
	})
	manifest := s.Manifest
	manifest.Format = Format
	manifest.Files = make([]Entry, len(s.Files))
	for i, f := range s.Files {
		manifest.Files[i] = f.Entry
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}

	enc, err := age.Encrypt(w, recipients...)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(enc)
	modTime := manifest.Created
	if err := writeEntry(tw, manifestName, 0o600, manifestJSON, modTime); err != nil {
		return err
	}
	for _, f := range s.Files {
		if err := writeEntry(tw, string(f.Root)+"/"+f.Path, fs.FileMode(f.Mode), f.Data, modTime); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return enc.Close()
}

func writeEntry(tw *tar.Writer, name string, mode fs.FileMode, data []byte, modTime time.Time) error {
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: int64(mode.Perm()), Size: int64(len(data)),
		ModTime: modTime, Typeflag: tar.TypeReg, Format: tar.FormatPAX,
	}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// ErrWrongKey is returned when none of the identities opens the archive.
var ErrWrongKey = errors.New("the archive does not open with this key or passphrase")

// maxFile bounds what one entry may claim, so a damaged or hostile archive
// cannot make a restore allocate without limit before its digest is checked.
const maxFile = 512 << 20

// Read decrypts and verifies an archive. Every file must be named by the
// manifest with the same size and digest, and every file the manifest names
// must be present.
func Read(r io.Reader, identities ...age.Identity) (*Snapshot, error) {
	dec, err := age.Decrypt(r, identities...)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, ErrWrongKey
		}
		return nil, fmt.Errorf("open the archive: %w", err)
	}
	tr := tar.NewReader(dec)

	header, err := tr.Next()
	if err != nil {
		return nil, fmt.Errorf("read the manifest: %w", err)
	}
	if header.Name != manifestName {
		return nil, fmt.Errorf("the archive starts with %q, not its manifest", header.Name)
	}
	var manifest Manifest
	if err := json.NewDecoder(io.LimitReader(tr, 16<<20)).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("parse the manifest: %w", err)
	}
	if manifest.Format != Format {
		return nil, fmt.Errorf("unsupported backup format %q (this binary reads %s)", manifest.Format, Format)
	}
	want := map[string]Entry{}
	for _, e := range manifest.Files {
		if err := checkRoot(e.Root); err != nil {
			return nil, err
		}
		if err := checkRel(e.Path); err != nil {
			return nil, err
		}
		want[string(e.Root)+"/"+e.Path] = e
	}

	snap := &Snapshot{Manifest: manifest}
	seen := map[string]bool{}
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read the archive: %w", err)
		}
		entry, ok := want[header.Name]
		if !ok || seen[header.Name] {
			return nil, fmt.Errorf("the archive holds %q, which its manifest does not name", header.Name)
		}
		if header.Typeflag != tar.TypeReg || header.Size != entry.Size || header.Size > maxFile {
			return nil, fmt.Errorf("%s does not match its manifest entry", header.Name)
		}
		var buf bytes.Buffer
		if _, err := io.CopyN(&buf, tr, header.Size); err != nil {
			return nil, fmt.Errorf("read %s: %w", header.Name, err)
		}
		sum := sha256.Sum256(buf.Bytes())
		if hex.EncodeToString(sum[:]) != entry.SHA256 {
			return nil, fmt.Errorf("%s is damaged: its digest does not match the manifest", header.Name)
		}
		seen[header.Name] = true
		snap.Files = append(snap.Files, File{Entry: entry, Data: buf.Bytes()})
	}
	for name := range want {
		if !seen[name] {
			return nil, fmt.Errorf("the archive is incomplete: %s is missing", name)
		}
	}
	return snap, nil
}

// Lookup returns a file of the snapshot.
func (s *Snapshot) Lookup(root Root, rel string) (File, bool) {
	for _, f := range s.Files {
		if f.Root == root && f.Path == rel {
			return f, true
		}
	}
	return File{}, false
}

func checkRoot(root Root) error {
	switch root {
	case RootConfig, RootData, RootRelay:
		return nil
	}
	return fmt.Errorf("unknown backup root %q", root)
}

// checkRel accepts only a clean relative slash path: nothing absolute, no
// "..", nothing a restore could resolve outside its root.
func checkRel(rel string) error {
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") || path.Clean(rel) != rel || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return fmt.Errorf("unsafe path %q in a backup", rel)
	}
	return nil
}
