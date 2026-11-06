package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

func TestReadRejectsUnsafeCredentials(t *testing.T) {
	dir := t.TempDir()
	store := Store{Dir: dir, UID: uint32(os.Getuid())}

	write := func(name, content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(dir, name), mode); err != nil {
			t.Fatal(err)
		}
	}

	write("good", "token-value\n", 0o600)
	value, err := store.Read("good")
	if err != nil {
		t.Fatal(err)
	}
	if value != "token-value" {
		t.Fatalf("value = %q, want the trimmed token", value)
	}

	// Mode is not cosmetic: a group- or world-readable token on a host that
	// runs a publicly reachable bot is a credential anyone with a shell has.
	write("exposed", "token-value\n", 0o644)
	if _, err := store.Read("exposed"); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("a 0644 credential was accepted: %v", err)
	}

	write("empty", "   \n", 0o600)
	if _, err := store.Read("empty"); err == nil {
		t.Fatal("an empty credential was accepted")
	}

	// Two lines means the file is not what the caller thinks it is — usually a
	// pasted token followed by a comment, which would be sent as the token.
	write("multiline", "token-value\nsecond\n", 0o600)
	if _, err := store.Read("multiline"); err == nil {
		t.Fatal("a multi-line credential was accepted")
	}

	if err := os.Symlink("/etc/shadow", filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read("linked"); err == nil {
		t.Fatal("a symlinked credential was followed")
	}

	if _, err := store.Read("missing"); err == nil {
		t.Fatal("a missing credential was accepted")
	}
}

// TestReadRejectsPathsDisguisedAsNames. The store takes a logical name so a
// reviewable desired-state document cannot choose which file root reads.
func TestReadRejectsPathsDisguisedAsNames(t *testing.T) {
	store := Store{Dir: t.TempDir(), UID: uint32(os.Getuid())}
	for _, name := range []string{"../escape", "sub/token", "/etc/shadow", ".", "", "Token", "token_value"} {
		if _, err := store.Read(state.SecretRef(name)); err == nil {
			t.Errorf("credential reference %q was accepted", name)
		}
	}
}

// TestRefuseResolverNeverReturnsAValue guards the paths that must not resolve
// secrets, such as planning.
func TestRefuseResolverNeverReturnsAValue(t *testing.T) {
	value, err := Refuse("telegram-token")
	if err == nil {
		t.Fatal("the refusing resolver returned no error")
	}
	if value != "" {
		t.Fatalf("value = %q, want empty", value)
	}
}

func TestRedactLeavesShortValuesAlone(t *testing.T) {
	// A short value would match too much text; redacting "ab" out of a log
	// would corrupt it while protecting nothing worth protecting.
	if got := Redact("error for ab", "ab"); got != "error for ab" {
		t.Fatalf("got %q, want the text unchanged", got)
	}
	if got := Redact("token=long-secret-value", "long-secret-value"); !strings.Contains(got, "[redacted]") {
		t.Fatalf("got %q, want the secret replaced", got)
	}
}
