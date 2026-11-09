// Package logrotate validates a generated logrotate configuration before it is
// installed.
//
// Worth its own step because the failure is silent and delayed: logrotate skips
// a file it cannot parse and carries on with the others, so a bad stanza does
// not break anything visibly — it just means the core's append-only log grows
// until the disk fills, weeks later, and takes the server down.
package logrotate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrUnavailable reports that logrotate is not installed, so the configuration
// cannot be checked here.
var ErrUnavailable = fmt.Errorf("logrotate is not installed")

// Validate writes the configuration to a private temporary file and asks
// logrotate to parse it.
//
// --debug rather than a real run: it parses and reports what it would do
// without rotating anything, so validating cannot itself truncate the live log.
func Validate(ctx context.Context, data []byte) error {
	path, err := exec.LookPath("logrotate")
	if err != nil {
		return ErrUnavailable
	}

	dir, err := os.MkdirTemp("", "spaiter-vpn-logrotate-")
	if err != nil {
		return fmt.Errorf("create a staging directory: %w", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("restrict the staging directory: %w", err)
	}
	staged := filepath.Join(dir, "spaiter-vpn")
	if err := os.WriteFile(staged, data, 0o600); err != nil {
		return fmt.Errorf("stage the logrotate configuration: %w", err)
	}

	// The exit status is deliberately ignored, and this is the whole subtlety
	// of checking logrotate. --debug exits 1 for reasons that have nothing to
	// do with the configuration being wrong: the log file does not exist yet
	// (the core creates it at first start), and the shared state file under
	// /var/lib/logrotate is unreadable unless we are root. Both produce
	// `error:` lines and a non-zero status for a perfectly valid stanza, so
	// trusting either would refuse every correct configuration.
	//
	// A parse error is distinguishable because logrotate prefixes it with the
	// config file and a line number: `error: <path>:2 unknown option ...`.
	// That is the only signal read here.
	output, _ := exec.CommandContext(ctx, path, "--debug", staged).CombinedOutput()
	marker := "error: " + staged + ":"
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), marker) {
			// Reported with the staging path replaced, so the message names the
			// file the operator is going to install rather than a temporary one
			// that no longer exists by the time they read it.
			return fmt.Errorf("logrotate rejected the generated configuration: %s",
				strings.TrimSpace(strings.ReplaceAll(line, staged, "spaiter-vpn")))
		}
	}
	return nil
}
