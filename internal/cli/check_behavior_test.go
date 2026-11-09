package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/singbox"
)

// The directory has an invalid fragment beside a valid main config. Checking
// just the main file must never be presented as validation of the deployment.
func TestRunCheckSingleFileVersusDeployment(t *testing.T) {
	dir := t.TempDir()
	for name, data := range map[string]string{"config.json": "{}", "extra.json": "invalid"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(t.TempDir(), "checker")
	script := `#!/bin/sh
[ "$1" = check ] || exit 90
case "$2" in
-c) exit 0 ;;
-C) [ -f "$3/extra.json" ] || exit 91
    echo 'FATAL invalid fragment' >&2
    exit 2 ;;
*) exit 92 ;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runCheck(context.Background(), &out, []string{"-sing-box", binary, "-dir", dir})
	var rejected *singbox.CheckError
	if !errors.As(err, &rejected) || rejected.ExitCode != 2 {
		t.Fatalf("directory error = %v", err)
	}
	if strings.Contains(out.String(), "\nok") {
		t.Fatalf("false success: %s", out.String())
	}
	out.Reset()
	err = runCheck(context.Background(), &out, []string{"-sing-box", binary, "-config", filepath.Join(dir, "config.json")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "this says nothing about the other files") {
		t.Fatalf("missing scope warning: %s", out.String())
	}
}

func TestRunCheckFailsClosed(t *testing.T) {
	for _, mode := range []string{"unavailable", "missing-file", "bad-flag", "valid-directory"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("PATH", t.TempDir())
			args := []string{"-dir", dir}
			if mode == "missing-file" || mode == "valid-directory" {
				binary := filepath.Join(t.TempDir(), "checker")
				if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-sing-box", binary)
				if mode == "missing-file" {
					args = append(args, "-config", filepath.Join(dir, "missing"))
				} else {
					if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if mode == "bad-flag" {
				args = append(args, "-does-not-exist")
			}
			var out bytes.Buffer
			err := runCheck(context.Background(), &out, args)
			if mode == "valid-directory" {
				if err != nil || !strings.HasSuffix(out.String(), "ok\n") {
					t.Fatalf("result: %v, %s", err, out.String())
				}
				return
			}
			if err == nil || strings.Contains(out.String(), "\nok") {
				t.Fatalf("false success: %v, %s", err, out.String())
			}
			if mode == "unavailable" && !errors.Is(err, singbox.ErrUnavailable) {
				t.Fatalf("error = %v", err)
			}
			if mode == "missing-file" && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
