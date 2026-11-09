package cli

import (
	"bytes"
	"context"
	"errors"
	"github.com/spaiter/spaiter-vpn/internal/bootstrap/apply"
	"os"
	"strings"
	"testing"
)

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

func TestBackupAndRestoreExplainThemselvesOnHelp(t *testing.T) {
	for name, run := range map[string]func(context.Context, *bytes.Buffer) error{
		"backup":  func(ctx context.Context, out *bytes.Buffer) error { return runBackup(ctx, out, []string{"-h"}) },
		"restore": func(ctx context.Context, out *bytes.Buffer) error { return runRestore(ctx, out, []string{"-h"}) },
	} {
		var out bytes.Buffer
		if err := run(context.Background(), &out); err == nil {
			t.Errorf("%s -h reported success", name)
		}
		if !strings.Contains(out.String(), "usage: spaiter-vpn "+name) {
			t.Errorf("%s -h printed:\n%s", name, out.String())
		}
	}
}

func TestBackupRefusesToDumpBinaryOntoATerminal(t *testing.T) {
	asRoot(t)
	layout := deployedLayout(t)
	old := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return true }
	defer func() { stdoutIsTerminal = old }()
	args := append(layoutArgs(layout), "-passphrase-file", writePassFile(t))
	if err := runBackup(context.Background(), os.Stdout, args); !errors.Is(err, ErrUsage) {
		t.Errorf("error = %v", err)
	}
}

func TestBackupReportsAWriterThatBreaksAndLeavesNoFileBehind(t *testing.T) {
	asRoot(t)
	layout := deployedLayout(t)
	args := append(layoutArgs(layout), "-passphrase-file", writePassFile(t))
	if err := runBackup(context.Background(), brokenWriter{}, args); err == nil || !strings.Contains(err.Error(), "pipe closed") {
		t.Errorf("error = %v", err)
	}
}

func TestBackupPassphrasePromptFailuresAreReported(t *testing.T) {
	old := readPassphrase
	defer func() { readPassphrase = old }()

	readPassphrase = func(string) (string, error) { return "", errors.New("no terminal") }
	if _, err := backupRecipients(nil, "", ""); err == nil {
		t.Error("a failed first prompt was ignored")
	}
	calls := 0
	readPassphrase = func(string) (string, error) {
		calls++
		if calls == 2 {
			return "", errors.New("interrupted")
		}
		return testPassphrase, nil
	}
	if _, err := backupRecipients(nil, "", ""); err == nil {
		t.Error("a failed confirmation prompt was ignored")
	}
	if _, err := backupRecipients(nil, "", "/absent/passphrase"); err == nil {
		t.Error("a missing passphrase file was ignored")
	}
}

func TestInteractiveRestoreHonoursARefusalAndAnAcceptance(t *testing.T) {
	for answer, wantRuns := range map[string]int{"no\n": 0, "yes\n": 1} {
		stub := &engineStub{result: nil}
		stub.result = okResult()
		args, _ := restoreHost(t, stub)
		args = args[:len(args)-1] // drop -yes
		atTerminal(t, "")
		stdinHolds(t, answer)
		var out bytes.Buffer
		if err := runRestore(context.Background(), &out, append(args, "-keep-address")); err != nil {
			t.Fatalf("%q: %v\n%s", answer, err, out.String())
		}
		if stub.runCalls != wantRuns {
			t.Errorf("%q: engine runs = %d, want %d", answer, stub.runCalls, wantRuns)
		}
	}
}

func TestRestoreAsksForAnAnswerAndReportsAClosedInput(t *testing.T) {
	stub := &engineStub{result: okResult()}
	args, _ := restoreHost(t, stub)
	args = args[:len(args)-1]
	atTerminal(t, "")
	stdinHolds(t, "")
	if err := runRestore(context.Background(), &bytes.Buffer{}, append(args, "-keep-address")); err == nil {
		t.Error("end of input was taken as consent")
	}
	if stub.runCalls != 0 {
		t.Error("the engine ran without an answer")
	}
}

func writePassFile(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/pass"
	if err := os.WriteFile(path, []byte(testPassphrase+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func okResult() *apply.Result { return &apply.Result{Transaction: "tx"} }
