package cli

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestThePassphraseIsAskedOnTheTerminalNotOnStdout(t *testing.T) {
	terminal := &fakeTerminal{in: strings.NewReader("")}
	oldOpen, oldHidden := openTerminal, readHidden
	openTerminal = func() (io.ReadWriteCloser, error) { return terminal, nil }
	readHidden = func(io.ReadWriteCloser) ([]byte, error) { return []byte("correct horse"), nil }
	defer func() { openTerminal, readHidden = oldOpen, oldHidden }()

	got, err := readPassphraseFromTTY("Passphrase: ")
	if err != nil || got != "correct horse" {
		t.Fatalf("passphrase = %q, %v", got, err)
	}
	if !strings.HasPrefix(terminal.out.String(), "Passphrase: ") || strings.Contains(terminal.out.String(), "correct horse") {
		t.Errorf("terminal shows %q", terminal.out.String())
	}

	readHidden = func(io.ReadWriteCloser) ([]byte, error) { return nil, errors.New("interrupted") }
	if _, err := readPassphraseFromTTY("Passphrase: "); err == nil {
		t.Error("an interrupted prompt returned a passphrase")
	}
}

func TestWithoutATerminalThePassphraseIsRefusedWithTheWayOut(t *testing.T) {
	old := openTerminal
	openTerminal = func() (io.ReadWriteCloser, error) { return nil, errors.New("no tty") }
	defer func() { openTerminal = old }()
	if _, err := readPassphraseFromTTY("Passphrase: "); err == nil || !strings.Contains(err.Error(), "-passphrase-file") {
		t.Errorf("error = %v", err)
	}
}

func TestTheDefaultHiddenReadNeedsARealTerminal(t *testing.T) {
	if _, err := readHidden(&fakeTerminal{in: strings.NewReader("")}); err == nil {
		t.Error("a non-file terminal was read for a password")
	}
}
