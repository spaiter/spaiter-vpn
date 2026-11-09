package logrotate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeLogrotate puts a `logrotate` on PATH that prints body, with $2 the staged
// file, and exits with the given status.
func fakeLogrotate(t *testing.T, body string, status int) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" + body + "\nexit " + string(rune('0'+status)) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "logrotate"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// The system PATH stays behind the fake, for scripts that need ls or cat.
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestValidateReadsOnlyTheParseErrorMarker(t *testing.T) {
	ctx := context.Background()

	// Runtime noise with a failing status is not a rejection.
	fakeLogrotate(t, `echo "error: stat of /var/log/x.log failed: No such file or directory"; echo "error: error opening state file /var/lib/logrotate/status"`, 1)
	if err := Validate(ctx, []byte("anything")); err != nil {
		t.Errorf("runtime noise was taken for a parse error: %v", err)
	}

	// A parse error names the config and a line, and is reported without the staging path.
	fakeLogrotate(t, `echo "reading config file $2"; echo "error: $2:2 unknown option 'bogus' -- ignoring line"`, 1)
	err := Validate(ctx, []byte("anything"))
	if err == nil || !strings.Contains(err.Error(), "rejected the generated configuration") || !strings.Contains(err.Error(), "spaiter-vpn:2 unknown option 'bogus'") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), os.TempDir()) {
		t.Errorf("the message names the temporary staging path: %v", err)
	}

	// A clean run passes even with a zero status and no output.
	fakeLogrotate(t, `true`, 0)
	if err := Validate(ctx, []byte("anything")); err != nil {
		t.Errorf("clean run: %v", err)
	}
}

func TestValidateStagesTheConfigurationPrivatelyAndCleansUp(t *testing.T) {
	staging := t.TempDir()
	t.Setenv("TMPDIR", staging)
	record := filepath.Join(t.TempDir(), "record")
	fakeLogrotate(t, `stat_out=$(ls -ld "$(dirname "$2")" | cut -c1-10); echo "$stat_out" >`+record+`; cat "$2" >>`+record, 0)
	if err := Validate(context.Background(), []byte("the-config\n")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(record)
	if !strings.HasPrefix(string(got), "drwx------") || !strings.Contains(string(got), "the-config") {
		t.Errorf("staging record = %q, want a private directory holding the configuration", got)
	}
	if entries, _ := os.ReadDir(staging); len(entries) != 0 {
		t.Errorf("the staging directory was left behind: %v", entries)
	}
}

func TestValidateReportsTheMissingToolAndAnUnusableStagingArea(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if err := Validate(context.Background(), nil); !errors.Is(err, ErrUnavailable) {
		t.Errorf("no logrotate: %v", err)
	}
	fakeLogrotate(t, `true`, 0)
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
	if err := Validate(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "staging directory") {
		t.Errorf("unusable TMPDIR: %v", err)
	}
}
