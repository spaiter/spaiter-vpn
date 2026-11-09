package singbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeExecutable(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDetectFallbacks(t *testing.T) {
	for _, mode := range []string{"explicit", "local", "docker", "sudo", "unavailable", "bad-explicit"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("PATH", dir)
			binary := ""
			switch mode {
			case "explicit":
				binary = fakeExecutable(t, dir, "custom", "exit 0")
			case "local":
				fakeExecutable(t, dir, "sing-box", "exit 0")
			case "docker":
				fakeExecutable(t, dir, "docker", "exit 0")
			case "sudo":
				fakeExecutable(t, dir, "docker", "exit 1")
				fakeExecutable(t, dir, "sudo", `[ "$1" = -n ] && [ "$2" = docker ] && [ "$3" = version ]`)
			case "bad-explicit":
				binary = filepath.Join(dir, "missing")
				fakeExecutable(t, dir, "docker", "exit 0")
			}
			c, err := Detect(context.Background(), binary, "")
			if mode == "unavailable" {
				if !errors.Is(err, ErrUnavailable) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if mode == "bad-explicit" {
				if err == nil {
					t.Fatal("silently fell back from explicit binary")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "local" || mode == "explicit" {
				if c.Binary == "" || len(c.Docker) != 0 {
					t.Fatalf("checker = %+v", c)
				}
			} else {
				if c.Image != DefaultImage {
					t.Fatalf("image = %q", c.Image)
				}
				want := "docker"
				if mode == "sudo" {
					want = "sudo -n docker"
				}
				if strings.Join(c.Docker, " ") != want {
					t.Fatalf("command = %v", c.Docker)
				}
			}
		})
	}
}

func TestCheckIsolatesSecretsAndCleansScratch(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rejection"}[fail], func(t *testing.T) {
			log := filepath.Join(t.TempDir(), "path")
			t.Setenv("CHECK_PATH_LOG", log)
			body := `
[ "$1" = check ] && [ "$2" = -c ] || exit 90
printf '%s' "$3" > "$CHECK_PATH_LOG"
[ "$(stat -c %a "$3")" = 600 ] || exit 91
[ "$(stat -c %a "$(dirname "$3")")" = 700 ] || exit 92
[ "$(cat "$3")" = '{"secret":"test-only"}' ] || exit 93
`
			if fail {
				body += "echo 'FATAL bad key' >&2\nexit 7\n"
			}
			c := &Checker{Binary: fakeExecutable(t, t.TempDir(), "checker", body)}
			err := c.Check(context.Background(), []byte(`{"secret":"test-only"}`))
			if fail {
				var rejected *CheckError
				if !errors.As(err, &rejected) || rejected.ExitCode != 7 || rejected.Output != "FATAL bad key" {
					t.Fatalf("error = %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			path, e := os.ReadFile(log)
			if e != nil {
				t.Fatal(e)
			}
			if _, e := os.Stat(filepath.Dir(string(path))); !errors.Is(e, os.ErrNotExist) {
				t.Fatalf("scratch not removed: %v", e)
			}
		})
	}
}

func TestCheckDockerFailureIsNotConfigRejection(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		unavailable  bool
	}{
		{"registry", "docker: Error response from daemon: manifest unknown", true},
		{"config", "FATAL upstream connection refused", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("FAKE_ERROR", tc.output)
			exe := fakeExecutable(t, t.TempDir(), "docker", `[ "$1" = run ] && [ "$2" = --rm ] && [ "$3" = -v ] && [ "$5" = test-image ] && [ "$6" = check ] && [ "$7" = -c ] && [ "$8" = /etc/sing-box/config.json ] || exit 90
echo "$FAKE_ERROR" >&2
exit 1`)
			err := (&Checker{Docker: []string{exe}, Image: "test-image"}).Check(context.Background(), []byte(`{}`))
			if errors.Is(err, ErrUnavailable) != tc.unavailable {
				t.Fatalf("error = %v", err)
			}
			if !tc.unavailable {
				var e *CheckError
				if !errors.As(err, &e) || e.Output != tc.output {
					t.Fatalf("error = %v", err)
				}
			}
		})
	}
	err := (&Checker{Binary: filepath.Join(t.TempDir(), "missing")}).Check(context.Background(), []byte(`{}`))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing binary: %v", err)
	}
}

func TestCheckDirectoryStagesOnlyTopLevelJSON(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{"config.json": "{}", "extra.json": "{\"bad\":true}", "secret.txt": "do not copy"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "nested.json"), 0700); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "scratch")
	t.Setenv("CHECK_PATH_LOG", log)
	exe := fakeExecutable(t, t.TempDir(), "checker", `
[ "$1" = check ] && [ "$2" = -C ] || exit 90
printf '%s' "$3" > "$CHECK_PATH_LOG"
[ -f "$3/config.json" ] && [ -f "$3/extra.json" ] || exit 91
[ ! -e "$3/secret.txt" ] && [ ! -e "$3/nested.json" ] || exit 92
echo 'FATAL unknown field bad' >&2
exit 2`)
	err := (&Checker{Binary: exe}).CheckDirectory(context.Background(), dir)
	var e *CheckError
	if !errors.As(err, &e) || e.ExitCode != 2 || !strings.Contains(err.Error(), "config.json, extra.json") {
		t.Fatalf("error = %v", err)
	}
	scratch, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(string(scratch)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scratch remains: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "extra.json"))
	if err != nil || string(data) != `{"bad":true}` {
		t.Fatal("source changed")
	}
}

func TestCheckDirectoryRefusesMissingOrEmptyDirectory(t *testing.T) {
	c := &Checker{Binary: "must-not-run"}
	if err := c.CheckDirectory(context.Background(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "no .json") {
		t.Fatalf("empty: %v", err)
	}
	if err := c.CheckDirectory(context.Background(), filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
}
