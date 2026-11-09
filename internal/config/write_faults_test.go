package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// faultyFile is a real temporary file with one step made to fail.
type faultyFile struct {
	*os.File
	failChmod, failWrite, failSync, failClose bool
	closed                                    int
}

func (f *faultyFile) Chmod(m os.FileMode) error {
	if f.failChmod {
		return errors.New("injected chmod failure")
	}
	return f.File.Chmod(m)
}

func (f *faultyFile) Write(p []byte) (int, error) {
	if f.failWrite {
		return 0, errors.New("injected write failure")
	}
	return f.File.Write(p)
}

func (f *faultyFile) Sync() error {
	if f.failSync {
		return errors.New("injected sync failure")
	}
	return f.File.Sync()
}

func (f *faultyFile) Close() error {
	f.closed++
	err := f.File.Close()
	if f.failClose {
		return errors.New("injected close failure")
	}
	return err
}

func TestEachWriteStepFailsByNameAndLeavesTheOriginalAndNoTemporaries(t *testing.T) {
	cases := map[string]struct {
		set  func(*faultyFile)
		want string
	}{
		"chmod": {func(f *faultyFile) { f.failChmod = true }, "chmod"},
		"write": {func(f *faultyFile) { f.failWrite = true }, "write"},
		"sync":  {func(f *faultyFile) { f.failSync = true }, "sync"},
		"close": {func(f *faultyFile) { f.failClose = true }, "close"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			var made *faultyFile
			old := createTemp
			createTemp = func(dir, pattern string) (tempFile, error) {
				f, err := os.CreateTemp(dir, pattern)
				if err != nil {
					return nil, err
				}
				made = &faultyFile{File: f}
				c.set(made)
				return made, nil
			}
			t.Cleanup(func() { createTemp = old })

			err := Write(path, []byte("replacement"), 0o600)
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("err = %v, want it to name %q and carry the cause", err, c.want)
			}
			if got, _ := os.ReadFile(path); string(got) != "original" {
				t.Errorf("a failed write changed the file: %q", got)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 1 {
				t.Errorf("a temporary file leaked: %v", entries)
			}
			if made.closed != 1 {
				t.Errorf("the temporary file was closed %d times, want once", made.closed)
			}
		})
	}
}

func TestWriteSucceedsThroughTheSeamToo(t *testing.T) {
	old := createTemp
	createTemp = func(dir, pattern string) (tempFile, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		return &faultyFile{File: f}, nil
	}
	t.Cleanup(func() { createTemp = old })
	path := filepath.Join(t.TempDir(), "c.json")
	if err := Write(path, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "ok" {
		t.Errorf("content = %q", got)
	}
}
