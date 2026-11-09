package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A holder whose token cannot be read keeps retrying quietly and stops with
// the context's error when the service is stopped; it never publishes a link.
func TestVKHolderRunsUntilStoppedAndPublishesNothingWithoutAToken(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	dir := filepath.Join(t.TempDir(), "data")

	for name, extra := range map[string][]string{
		"self relogin":     nil,
		"custom relogin":   {"-relogin", filepath.Join(t.TempDir(), "relogin.sh")},
		"explicit options": {"-ws-host", "127.0.0.1:1", "-pass-entry", "services/x", "-heartbeat", "50ms"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		var out bytes.Buffer
		err := runVKHolder(ctx, &out, append([]string{"-data-dir", dir, "-n", "2"}, extra...))
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: err = %v, want the context's deadline", name, err)
		}
	}
	if links, err := os.ReadFile(filepath.Join(dir, "wdtt", "vk_hashes.json")); err == nil && len(bytes.TrimSpace(links)) > 2 {
		t.Errorf("a link was published without a token: %s", links)
	}
}

func TestVKHolderRejectsBadFlagsAndAnUnusableDataDir(t *testing.T) {
	var out bytes.Buffer
	if err := runVKHolder(context.Background(), &out, []string{"-n", "x"}); err == nil {
		t.Error("a bad flag was accepted")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := runVKHolder(context.Background(), &out, []string{"-data-dir", filepath.Join(file, "sub")})
	if err == nil {
		t.Error("a data dir under a regular file was accepted")
	}
}

func TestVKReloginRejectsBadFlags(t *testing.T) {
	var out bytes.Buffer
	if err := runVKRelogin(context.Background(), &out, []string{"-code-wait", "soon"}); err == nil {
		t.Error("a bad relogin flag was accepted")
	}
}
