package provision

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type okRegistrar struct{}

func (okRegistrar) Register(context.Context) (json.RawMessage, error) {
	return json.RawMessage(`{"private_key":"k"}`), nil
}

func readOnlyDir(t *testing.T, path string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o700) })
}

func TestAWARPAccountThatCannotBeCachedIsAFailureNotAFreeRegistration(t *testing.T) {
	p, _, _, store := newTestProvisioner(t)
	readOnlyDir(t, store.Path("warp"))
	if _, err := p.EnsureWARP(context.Background(), "42", okRegistrar{}); err == nil {
		t.Error("an account that was registered but could not be stored was reported as success")
	}
}

func TestARelayPasswordThatCannotBeStoredStopsTheProvisioning(t *testing.T) {
	p, api, _, store := brokenProvisioner(t)
	api.endpoints["wg-wdtt-in"] = endpointWith(nil)
	passwords := filepath.Join(t.TempDir(), "passwords.json")
	if err := os.WriteFile(passwords, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	readOnlyDir(t, store.Path("wdtt"))
	if _, err := p.EnsureWDTT(context.Background(), "wg-wdtt-in", "42", passwords); err == nil {
		t.Error("a password that could not be stored was reported as success")
	}
}
