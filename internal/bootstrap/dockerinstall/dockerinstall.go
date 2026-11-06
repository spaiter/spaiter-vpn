// Package dockerinstall installs Docker Engine and the Compose plugin from
// Docker's own apt repository at exact, reviewed versions, for a host that
// opted in with bootstrap.installDocker.
//
// The repository key is embedded rather than downloaded: fetching it at install
// time would make the first package download trust whatever the network handed
// out. Versions are pinned per distribution release rather than "latest", so a
// plan names exactly what an apply will install, and two hosts bootstrapped a
// month apart run the same engine.
//
// Installing packages is not a file transaction. A failed apply restores the
// files it wrote but does not uninstall Docker, which other software may
// already depend on; what was installed is recorded instead, and removing it is
// the operator's decision.
package dockerinstall

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// archiveKey is Docker's "Docker Release (CE deb)" signing key, the same one
// for the Ubuntu and Debian repositories, fingerprint
// 9DC8 5822 9FC7 DD38 854A  E2D8 8D81 803C 0EBF CD88.
//
//go:embed docker-archive-keyring.asc
var archiveKey []byte

const (
	// KeyringPath and SourcesPath carry the spaiter-vpn name, so they can be
	// told apart from a Docker repository an operator configured by hand.
	KeyringPath = "/etc/apt/keyrings/spaiter-vpn-docker.asc"
	SourcesPath = "/etc/apt/sources.list.d/spaiter-vpn-docker.sources"
	// RepositoryHost is how an existing Docker repository entry is recognised.
	RepositoryHost = "download.docker.com"
)

// Versions are the exact Debian package versions installed together.
type Versions struct {
	Engine     string `json:"docker-ce"`
	CLI        string `json:"docker-ce-cli"`
	Containerd string `json:"containerd.io"`
	Compose    string `json:"docker-compose-plugin"`
}

// Release is one supported distribution release and what it installs.
type Release struct {
	ID       string
	Version  string
	Codename string
	Versions Versions
	// EngineVersion and ComposeVersion are what `docker version` and
	// `docker compose version` report afterwards: the proof that the package
	// manager installed what the plan named.
	EngineVersion  string
	ComposeVersion string
}

// releases is the reviewed matrix. Every version here was present in
// download.docker.com's stable pool for that codename when it was pinned
// (2026-11-04); a bump is a code change with its own review.
var releases = []Release{
	{
		ID: "ubuntu", Version: "24.04", Codename: "noble",
		Versions: Versions{
			Engine: "5:29.9.3-1~ubuntu.24.04~noble", CLI: "5:29.9.3-1~ubuntu.24.04~noble",
			Containerd: "2.4.2-3~ubuntu.24.04~noble", Compose: "5.7.0-1~ubuntu.24.04~noble",
		},
		EngineVersion: "29.9.3", ComposeVersion: "5.7.0",
	},
	{
		ID: "debian", Version: "12", Codename: "bookworm",
		Versions: Versions{
			Engine: "5:29.9.3-1~debian.12~bookworm", CLI: "5:29.9.3-1~debian.12~bookworm",
			Containerd: "2.4.2-3~debian.12~bookworm", Compose: "5.7.0-1~debian.12~bookworm",
		},
		EngineVersion: "29.9.3", ComposeVersion: "5.7.0",
	},
	{
		ID: "debian", Version: "13", Codename: "trixie",
		Versions: Versions{
			Engine: "5:29.9.3-1~debian.13~trixie", CLI: "5:29.9.3-1~debian.13~trixie",
			Containerd: "2.4.2-3~debian.13~trixie", Compose: "5.7.0-1~debian.13~trixie",
		},
		EngineVersion: "29.9.3", ComposeVersion: "5.7.0",
	},
}

// ConflictingPackages would be removed or broken by installing docker-ce and
// containerd.io. A host that has any of them installed is refused by name: apt
// would otherwise uninstall another container runtime to make room.
var ConflictingPackages = []string{
	"docker.io", "docker-doc", "docker-compose", "docker-compose-v2",
	"podman-docker", "containerd", "runc",
}

// For returns the pinned release for a distribution, or an error naming the
// supported matrix.
func For(id, version string) (Release, error) {
	for _, release := range releases {
		if release.ID == id && release.Version == version {
			return release, nil
		}
	}
	return Release{}, fmt.Errorf("no pinned Docker packages for %s %s (supported: Ubuntu 24.04, Debian 12, Debian 13)", id, version)
}

// Packages lists name=version arguments for apt-get. composeOnly installs just
// the Compose plugin, for a host whose engine already works.
func (r Release) Packages(composeOnly bool) []string {
	if composeOnly {
		return []string{"docker-compose-plugin=" + r.Versions.Compose}
	}
	return []string{
		"docker-ce=" + r.Versions.Engine,
		"docker-ce-cli=" + r.Versions.CLI,
		"containerd.io=" + r.Versions.Containerd,
		"docker-compose-plugin=" + r.Versions.Compose,
	}
}

// Sources is the deb822 source entry, restricted to this repository's key.
func (r Release) Sources() []byte {
	return []byte(fmt.Sprintf(`# Managed by spaiter-vpn bootstrap (bootstrap.installDocker).
Types: deb
URIs: https://%s/linux/%s
Suites: %s
Components: stable
Architectures: amd64
Signed-By: %s
`, RepositoryHost, r.ID, r.Codename, KeyringPath))
}

// Keyring is the embedded repository key.
func Keyring() []byte { return append([]byte(nil), archiveKey...) }

// Record is what an install did, kept so an operator can see and undo it.
type Record struct {
	InstalledAt time.Time         `json:"installedAt"`
	Release     string            `json:"release"`
	Packages    map[string]string `json:"packages"`
	Files       []string          `json:"files"`
	Engine      string            `json:"engineVersion,omitempty"`
	Compose     string            `json:"composeVersion"`
}

// Runner executes a command with the environment given, returning combined
// output.
type Runner interface {
	Run(ctx context.Context, env []string, name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	return cmd.CombinedOutput()
}

// Installer performs the installation. Root prefixes every host path, for
// tests; it is empty in production.
type Installer struct {
	Runner Runner
	Root   string
	Out    io.Writer
	Now    func() time.Time
}

func (i Installer) path(p string) string { return filepath.Join(i.Root, p) }

func (i Installer) runner() Runner {
	if i.Runner == nil {
		return ExecRunner{}
	}
	return i.Runner
}

// Preconditions returns, by name, everything that makes installing unsafe on
// this host: conflicting runtime packages and a Docker repository configured
// by someone else. Discovery calls it read-only; Install calls it again under
// the bootstrap lock.
func (i Installer) Preconditions(ctx context.Context) (conflicts, foreignSources []string, err error) {
	out, runErr := i.runner().Run(ctx, nil, "dpkg-query", append([]string{"-W", "-f", "${Package} ${db:Status-Status}\n"}, ConflictingPackages...)...)
	// dpkg-query exits 1 when some named package is unknown, which is the
	// common case; its output is still authoritative for the ones it knows.
	// Anything else means the answer cannot be trusted.
	if runErr != nil {
		var exit interface{ ExitCode() int }
		if !errors.As(runErr, &exit) || exit.ExitCode() != 1 {
			return nil, nil, fmt.Errorf("query installed packages: %w: %s", runErr, tail(out))
		}
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == "installed" {
			conflicts = append(conflicts, fields[0])
		}
	}
	sort.Strings(conflicts)

	candidates := []string{i.path("/etc/apt/sources.list")}
	entries, err := os.ReadDir(i.path("/etc/apt/sources.list.d"))
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("inspect apt sources: %w", err)
	}
	for _, entry := range entries {
		candidates = append(candidates, filepath.Join(i.path("/etc/apt/sources.list.d"), entry.Name()))
	}
	for _, candidate := range candidates {
		if candidate == i.path(SourcesPath) {
			continue
		}
		data, err := os.ReadFile(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, nil, fmt.Errorf("read apt source %s: %w", candidate, err)
		}
		if bytes.Contains(data, []byte(RepositoryHost)) {
			foreignSources = append(foreignSources, strings.TrimPrefix(candidate, i.Root))
		}
	}
	return conflicts, foreignSources, nil
}

// Install configures the repository, installs the pinned packages and proves
// the result. It is idempotent: files it wrote on an earlier attempt are
// accepted when byte-identical, and anything else at those paths is refused.
func (i Installer) Install(ctx context.Context, release Release, composeOnly bool) (Record, error) {
	i.Runner = i.runner()
	if i.Out == nil {
		i.Out = io.Discard
	}
	if i.Now == nil {
		i.Now = time.Now
	}
	conflicts, foreign, err := i.Preconditions(ctx)
	if err != nil {
		return Record{}, err
	}
	if !composeOnly && len(conflicts) > 0 {
		return Record{}, fmt.Errorf("refusing to install Docker: conflicting packages are installed (%s); remove them or install Docker yourself", strings.Join(conflicts, ", "))
	}
	if composeOnly && containsAny(conflicts, "docker-compose", "docker-compose-v2") {
		return Record{}, fmt.Errorf("refusing to install the Compose plugin: a distribution Compose package is installed (%s)", strings.Join(conflicts, ", "))
	}
	if len(foreign) > 0 {
		return Record{}, fmt.Errorf("refusing to install Docker: %s already configure %s, and a second entry with another key breaks apt; remove it or install Docker yourself", strings.Join(foreign, ", "), RepositoryHost)
	}

	if err := i.writeOwned(KeyringPath, Keyring()); err != nil {
		return Record{}, err
	}
	if err := i.writeOwned(SourcesPath, release.Sources()); err != nil {
		return Record{}, err
	}
	env := []string{"DEBIAN_FRONTEND=noninteractive"}
	fmt.Fprintln(i.Out, "docker: refreshing package lists")
	if out, err := i.Runner.Run(ctx, env, "apt-get", "update"); err != nil {
		return Record{}, fmt.Errorf("apt-get update: %w: %s", err, tail(out))
	}
	packages := release.Packages(composeOnly)
	fmt.Fprintf(i.Out, "docker: installing %s\n", strings.Join(packages, " "))
	args := append([]string{"install", "-y", "--no-install-recommends", "-o", "Dpkg::Options::=--force-confold"}, packages...)
	if out, err := i.Runner.Run(ctx, env, "apt-get", args...); err != nil {
		return Record{}, fmt.Errorf("apt-get install: %w: %s", err, tail(out))
	}
	if !composeOnly {
		if out, err := i.Runner.Run(ctx, nil, "systemctl", "enable", "--now", "docker.service"); err != nil {
			return Record{}, fmt.Errorf("start docker.service: %w: %s", err, tail(out))
		}
	}

	record := Record{
		InstalledAt: i.Now().UTC(),
		Release:     release.ID + " " + release.Version,
		Packages:    map[string]string{},
		Files:       []string{KeyringPath, SourcesPath},
	}
	for _, pkg := range packages {
		name, version, _ := strings.Cut(pkg, "=")
		record.Packages[name] = version
	}
	if !composeOnly {
		engine, err := i.waitEngine(ctx)
		if err != nil {
			return record, err
		}
		if engine != release.EngineVersion {
			return record, fmt.Errorf("docker reports engine %s after installing %s", engine, release.EngineVersion)
		}
		record.Engine = engine
	}
	out, err := i.Runner.Run(ctx, nil, "docker", "compose", "version", "--short")
	if err != nil {
		return record, fmt.Errorf("docker compose version: %w: %s", err, tail(out))
	}
	compose := strings.TrimPrefix(strings.TrimSpace(string(out)), "v")
	if compose != release.ComposeVersion {
		return record, fmt.Errorf("docker compose reports %s after installing %s", compose, release.ComposeVersion)
	}
	record.Compose = compose
	fmt.Fprintf(i.Out, "docker: engine %s and compose %s installed from %s\n", release.EngineVersion, compose, RepositoryHost)
	return record, nil
}

// waitEngine gives a freshly started daemon a moment to open its socket.
func (i Installer) waitEngine(ctx context.Context) (string, error) {
	var last error
	for attempt := 0; attempt < 30; attempt++ {
		out, err := i.Runner.Run(ctx, nil, "docker", "version", "--format", "{{.Server.Version}}")
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
		last = fmt.Errorf("%w: %s", err, tail(out))
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return "", fmt.Errorf("the docker daemon did not answer after installation: %w", last)
}

func (i Installer) writeOwned(path string, data []byte) error {
	full := i.path(path)
	existing, err := os.ReadFile(full)
	switch {
	case err == nil && bytes.Equal(existing, data):
		return nil
	case err == nil:
		return fmt.Errorf("refusing to install Docker: %s exists with other content; it is not ours to replace", path)
	case !os.IsNotExist(err):
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(full), "."+filepath.Base(full)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
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
	return os.Rename(tmp.Name(), full)
}

// WriteRecord stores the record next to the bootstrap state. It merges with an
// earlier record, so a later compose-only install does not forget the engine.
func WriteRecord(path string, record Record) error {
	merged := record
	if data, err := os.ReadFile(path); err == nil {
		var previous struct {
			Docker *Record `json:"docker"`
		}
		if json.Unmarshal(data, &previous) == nil && previous.Docker != nil {
			merged.Packages = map[string]string{}
			for name, version := range previous.Docker.Packages {
				merged.Packages[name] = version
			}
			for name, version := range record.Packages {
				merged.Packages[name] = version
			}
			if merged.Engine == "" {
				merged.Engine = previous.Docker.Engine
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	data, err := json.MarshalIndent(struct {
		Docker Record `json:"docker"`
	}{merged}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadRecord returns the stored record, or nil when bootstrap never installed
// Docker on this host.
func ReadRecord(path string) (*Record, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		Docker *Record `json:"docker"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return doc.Docker, nil
}

func containsAny(list []string, names ...string) bool {
	for _, item := range list {
		for _, name := range names {
			if item == name {
				return true
			}
		}
	}
	return false
}

func tail(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 6 {
		lines = lines[len(lines)-6:]
	}
	return strings.Join(lines, "\n")
}
