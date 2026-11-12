// Package singbox runs the real sing-box binary against a generated
// configuration. Generating from the fork's own option structs guarantees the
// JSON matches the schema, but not that the values are usable — a shadowsocks
// password of the wrong length, or an unreachable Reality handshake target,
// parses fine and fails at startup. Only `sing-box check` catches those, so it
// is a mandatory step rather than a nicety.
package singbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrUnavailable means the checker itself could not be run — no sing-box
// binary and no usable Docker. It is deliberately distinct from a failed
// check: callers must refuse to install an unchecked config rather than treat
// "could not check" as "checked out fine".
var ErrUnavailable = errors.New("no way to run sing-box check: neither a local binary nor a usable docker image")

// Checker runs `sing-box check`, either with a local binary or inside the
// published image.
type Checker struct {
	// Binary is a local sing-box executable. Preferred when present.
	Binary string
	// Image is the container image used when Binary is empty.
	Image string
	// Docker is the docker command, which may be a sudo wrapper.
	Docker []string
}

// DefaultImage is the core image, pinned to the fork commit it was built from.
//
// The tag is immutable on purpose. A moving tag is exactly wrong for an
// installer: two runs a month apart would produce configs validated against
// different binaries while reporting the same image, and a rollback would have
// nothing to roll back to. Bumping the core is therefore a visible change to
// this constant, reviewed like any other.
//
// Pulling needs no credentials: the image is a public GHCR package, so an
// anonymous `docker pull` succeeds with an empty docker config. The package's
// visibility is set to public independently of the (private) source
// repository; if that is ever tightened, the failure surfaces through
// DefaultImageRegistry below. The image carries org.opencontainers.image.source
// and .revision, so it names its own GPL-3.0 corresponding source.
const DefaultImage = "ghcr.io/spaiter/spaiter-vpn-core:550c0c5"

// DefaultImageRegistry is the host that DefaultImage lives on, so a pull
// failure can name what to authenticate against rather than leaving an
// operator to parse it out of docker's output.
const DefaultImageRegistry = "ghcr.io"

// Detect finds a way to run the checker. A local binary wins because it is
// faster and needs no privileges; Docker is the fallback, tried both directly
// and through a non-interactive sudo, since membership in the docker group is
// not guaranteed.
func Detect(ctx context.Context, binary, image string) (*Checker, error) {
	if binary != "" {
		if _, err := exec.LookPath(binary); err != nil {
			return nil, fmt.Errorf("sing-box binary %q is not executable: %w", binary, err)
		}
		return &Checker{Binary: binary}, nil
	}
	if found, err := exec.LookPath("sing-box"); err == nil {
		return &Checker{Binary: found}, nil
	}
	if image == "" {
		image = DefaultImage
	}
	for _, candidate := range [][]string{{"docker"}, {"sudo", "-n", "docker"}} {
		if _, err := exec.LookPath(candidate[0]); err != nil {
			continue
		}
		probe := exec.CommandContext(ctx, candidate[0], append(candidate[1:], "version", "--format", "{{.Server.Version}}")...)
		if err := probe.Run(); err != nil {
			continue
		}
		return &Checker{Image: image, Docker: candidate}, nil
	}
	return nil, ErrUnavailable
}

// Describe names how the check will be run, for the operator's benefit.
func (c *Checker) Describe() string {
	if c.Binary != "" {
		return c.Binary + " check"
	}
	return strings.Join(c.Docker, " ") + " run --rm " + c.Image + " check"
}

// Check validates a configuration given as bytes.
//
// The config is written to a throwaway directory and checked there, never in
// place. That is not just hygiene: `check` instantiates the config, which
// creates the log file named by log.output, so checking in the target
// directory would have the side effect of writing there before the operator
// has approved anything.
func (c *Checker) Check(ctx context.Context, configData []byte) error {
	dir, err := os.MkdirTemp("", "spaiter-vpn-check-*")
	if err != nil {
		return fmt.Errorf("create temporary directory: %w", err)
	}
	defer os.RemoveAll(dir)

	// 0700 on the directory and 0600 on the file: the config carries every
	// private key in the deployment, and /tmp is world-readable.
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod temporary directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), configData, 0o600); err != nil {
		return fmt.Errorf("write temporary config: %w", err)
	}
	return c.runCheck(ctx, dir, false)
}

// runCheck runs the checker over a prepared directory. With directoryMode it
// passes -C, which merges every *.json in the directory the way the service
// does; otherwise -c on config.json alone.
func (c *Checker) runCheck(ctx context.Context, dir string, directoryMode bool) error {
	target := []string{"-c", "/etc/sing-box/config.json"}
	localTarget := []string{"-c", filepath.Join(dir, "config.json")}
	if directoryMode {
		target = []string{"-C", "/etc/sing-box/"}
		localTarget = []string{"-C", dir}
	}

	var cmd *exec.Cmd
	if c.Binary != "" {
		cmd = exec.CommandContext(ctx, c.Binary, append([]string{"check"}, localTarget...)...)
	} else {
		args := append([]string{}, c.Docker[1:]...)
		args = append(args,
			"run", "--rm",
			// The generated config names container paths, so the throwaway
			// directory is mounted where the config expects to live.
			"-v", dir+":/etc/sing-box",
			c.Image, "check",
		)
		args = append(args, target...)
		cmd = exec.CommandContext(ctx, c.Docker[0], args...)
	}

	var stderr, stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		output := strings.TrimSpace(stderr.String() + stdout.String())

		// Distinguish "the config is bad" (the checker ran and said no) from
		// "the checker did not run" (anything else). Conflating them is how a
		// broken config gets installed by a green pipeline.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// `docker run` also exits non-zero when it never got as far as
			// running anything — an unreachable registry, a tag that does not
			// exist, a daemon that refuses the connection. Reporting any of
			// those as "the config was rejected" sends the operator off to
			// debug a config that was never read.
			if reason := dockerDidNotRun(output); reason != "" {
				return fmt.Errorf("%w: %s\n\nIf the registry now requires authentication, run:\n  docker login %s\n\n%s",
					ErrUnavailable, reason, DefaultImageRegistry, output)
			}
			return &CheckError{ExitCode: exitErr.ExitCode(), Output: output}
		}
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

// CheckDirectory validates a config directory the way the service loads it.
//
// This exists because checking config.json alone is not checking the
// deployment. The service runs with `-C <dir>`, and that reads EVERY top-level
// *.json in the directory and merges them in sorted order — a fragment
// mechanism. So an unrelated JSON file left beside the config is not ignored:
// it is parsed as configuration and brings the service down at startup, while a
// single-file check passes happily. That exact failure happened: a secrets
// bundle written next to config.json made sing-box exit with
// `unknown field "ClashAPISecret"` on every start.
//
// Only the *.json files are copied to a scratch directory and checked there.
// That reproduces the merge faithfully — nothing else in the directory affects
// loading — without `check` writing a log file into the operator's directory
// as a side effect of being asked a question.
func (c *Checker) CheckDirectory(ctx context.Context, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}

	scratch, err := os.MkdirTemp("", "spaiter-vpn-checkdir-*")
	if err != nil {
		return fmt.Errorf("create temporary directory: %w", err)
	}
	defer os.RemoveAll(scratch)
	if err := os.Chmod(scratch, 0o700); err != nil {
		return fmt.Errorf("chmod temporary directory: %w", err)
	}

	var copied []string
	for _, entry := range entries {
		// The same two conditions the loader applies, in the same order.
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(scratch, entry.Name()), data, 0o600); err != nil {
			return fmt.Errorf("stage %s: %w", entry.Name(), err)
		}
		copied = append(copied, entry.Name())
	}
	if len(copied) == 0 {
		return fmt.Errorf("%s holds no .json file, so the service would start with no configuration", dir)
	}

	if err := c.runCheck(ctx, scratch, true); err != nil {
		return fmt.Errorf("%w\n\nThe service loads the whole directory: %s. Every one of those is parsed as config and merged — move anything that is not configuration out of %s",
			err, strings.Join(copied, ", "), dir)
	}
	return nil
}

// dockerDidNotRun recognises the failures where the container never started,
// so they are not misreported as a rejected config. docker returns the same
// exit code either way, so the exit code alone cannot tell them apart and the
// message has to be read.
//
// The discriminator is docker's own framing — "Error response from daemon",
// "Unable to find image", or a "docker:" prefix — rather than the words in the
// message. Keying on phrases like "connection refused" would be wrong: a
// config error from sing-box can contain exactly those words, and a classifier
// that swallowed one would hide a real rejection behind a registry excuse.
// sing-box frames its own failures as `FATAL[0000] …`.
func dockerDidNotRun(output string) string {
	if !isDockerFraming(output) {
		return ""
	}
	lower := strings.ToLower(output)
	// Ordered, because several of these co-occur: docker reports "Unable to
	// find image" and then the underlying reason, and the specific reason is
	// the useful one.
	for _, candidate := range []struct{ pattern, reason string }{
		{"pull access denied", "the registry refused the pull"},
		{"authentication required", "the registry requires authentication"},
		{"unauthorized", "the registry rejected the credentials"},
		{"manifest unknown", "the image tag does not exist in the registry"},
		{"not found: manifest", "the image tag does not exist in the registry"},
		{"certificate signed by unknown authority", "the registry's TLS certificate was not trusted"},
		{"no such host", "the registry host did not resolve"},
		{"connection refused", "the registry refused the connection"},
		{"cannot connect to the docker daemon", "the docker daemon is not reachable"},
		{"permission denied while trying to connect", "this user may not talk to the docker daemon"},
	} {
		if strings.Contains(lower, candidate.pattern) {
			return candidate.reason
		}
	}
	return "docker could not run the image"
}

func isDockerFraming(output string) bool {
	if strings.HasPrefix(strings.TrimSpace(output), "docker:") {
		return true
	}
	return strings.Contains(output, "Error response from daemon") ||
		strings.Contains(output, "Unable to find image")
}

// CheckError is a configuration the real binary rejected.
type CheckError struct {
	ExitCode int
	Output   string
}

func (e *CheckError) Error() string {
	if e.Output == "" {
		return fmt.Sprintf("sing-box check rejected the config (exit %d) without explaining why", e.ExitCode)
	}
	return "sing-box check rejected the config: " + e.Output
}
