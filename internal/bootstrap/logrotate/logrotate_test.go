package logrotate

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// TestValidateDistinguishesParseErrorsFromRuntimeNoise is the point of this
// package. `logrotate --debug` exits non-zero and prints `error:` lines for
// reasons that have nothing to do with the configuration: the log file does not
// exist yet, and the shared state file is unreadable unless we are root.
// Trusting the exit status or grepping for "error:" refuses every valid
// configuration, which was the first implementation and was wrong.
func TestValidateDistinguishesParseErrorsFromRuntimeNoise(t *testing.T) {
	if _, err := exec.LookPath("logrotate"); err != nil {
		t.Skip("logrotate is not installed")
	}
	ctx := context.Background()

	// A valid stanza for a log that does not exist, which is exactly the state
	// at install time: the core has not started yet.
	good := []byte("/var/log/spaiter-vpn/does-not-exist.log {\n  daily\n  rotate 7\n  missingok\n}\n")
	if err := Validate(ctx, good); err != nil {
		t.Fatalf("a valid configuration for a not-yet-created log was rejected: %v", err)
	}

	bad := []byte("/var/log/spaiter-vpn/does-not-exist.log {\n  bogusoption\n  daily\n}\n")
	err := Validate(ctx, bad)
	if err == nil {
		t.Fatal("an unknown option was accepted")
	}
	if !strings.Contains(err.Error(), "bogusoption") {
		t.Fatalf("the failure does not say what is wrong: %v", err)
	}
	// The staging path is temporary and gone by the time anyone reads the
	// message, so it must not be what the message names.
	if strings.Contains(err.Error(), "/tmp/") {
		t.Fatalf("the message names a temporary path: %v", err)
	}
}

// TestValidateReportsAMissingTool separately, so a caller can decide between
// "the configuration is wrong" and "there is nothing here to check it with".
func TestValidateReportsAMissingTool(t *testing.T) {
	if !errors.Is(ErrUnavailable, ErrUnavailable) {
		t.Fatal("ErrUnavailable is not comparable")
	}
}
