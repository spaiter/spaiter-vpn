package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/control"
)

// serveRig answers the access-file lookups from a table instead of /etc.
func serveRig(t *testing.T, files map[string]error, access control.Access) (socket, audit string, args []string) {
	t.Helper()
	old := loadControlAccess
	loadControlAccess = func(path string) (control.Access, error) {
		if err, listed := files[filepath.Base(path)]; listed {
			if err != nil {
				return control.Access{}, err
			}
			return access, nil
		}
		return control.Access{}, os.ErrNotExist
	}
	t.Cleanup(func() { loadControlAccess = old })

	dir := t.TempDir()
	socket, audit = filepath.Join(dir, "run", "control.sock"), filepath.Join(dir, "audit.log")
	args = []string{"-socket", socket, "-access", filepath.Join(dir, "control.json"), "-audit", audit,
		"-config-root", filepath.Join(dir, "etc"), "-data-root", filepath.Join(dir, "var")}
	return socket, audit, args
}

func TestControlServeListensUntilItsContextEnds(t *testing.T) {
	pretendRoot(t, true)
	access := control.Access{APIVersion: control.APIVersion, Operators: []uint32{1000}, Observers: []uint32{1001, 1002}}
	socket, audit, args := serveRig(t, map[string]error{"control.json": nil}, access)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var out bytes.Buffer
	if err := runControlServe(ctx, &out, args); err != nil {
		t.Fatalf("serve: %v", err)
	}
	for _, want := range []string{"listening on " + socket, "1 operator(s)", "2 observer(s)", "audit " + audit} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("announcement lacks %q:\n%s", want, out.String())
		}
	}
}

func TestControlServeMergesTheAccessBootstrapKeepsForItsOwnAccounts(t *testing.T) {
	pretendRoot(t, true)
	access := control.Access{APIVersion: control.APIVersion, Operators: []uint32{1000}}
	_, _, args := serveRig(t, map[string]error{"control.json": nil, "control.bootstrap.json": nil}, access)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	var out bytes.Buffer
	if err := runControlServe(ctx, &out, args); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if !strings.Contains(out.String(), "operator(s)") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestControlServeRefusesWhatItCannotTrust(t *testing.T) {
	pretendRoot(t, true)
	access := control.Access{APIVersion: control.APIVersion}

	_, _, args := serveRig(t, map[string]error{"control.json": errors.New("must be owned by root")}, access)
	if err := runControlServe(context.Background(), &bytes.Buffer{}, args); err == nil || !strings.Contains(err.Error(), "owned by root") {
		t.Errorf("untrusted access file: %v", err)
	}

	// A bootstrap allow-list that exists but cannot be read stops the daemon:
	// starting without it would silently drop the service accounts it names.
	_, _, args = serveRig(t, map[string]error{"control.json": nil, "control.bootstrap.json": errors.New("unreadable")}, access)
	if err := runControlServe(context.Background(), &bytes.Buffer{}, args); err == nil || !strings.Contains(err.Error(), "control.bootstrap.json") {
		t.Errorf("unreadable bootstrap allow-list: %v", err)
	}

	// A path that is not a socket is not ours to remove.
	socket, _, args := serveRig(t, map[string]error{"control.json": nil}, access)
	if err := os.MkdirAll(filepath.Dir(socket), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(socket, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runControlServe(context.Background(), &bytes.Buffer{}, args); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("a file at the socket path: %v", err)
	}
}

func TestControlServeRefusesWithoutRoot(t *testing.T) {
	pretendRoot(t, false)
	if err := runControlServe(context.Background(), &bytes.Buffer{}, nil); err == nil || !strings.Contains(err.Error(), "as root") {
		t.Errorf("error = %v", err)
	}
}
