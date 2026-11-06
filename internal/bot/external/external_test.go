package external

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// fakeBinary writes an executable shell script and returns its path. Real
// scripts rather than an injected function, so the exec path -- arguments,
// exit status, output handling -- is exercised and not just the parsing.
func fakeBinary(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	return path
}

func TestHashCheckParsesVerdicts(t *testing.T) {
	bin := fakeBinary(t, `
echo "some noise on the way"
echo "HASH_CHECK|h1|ok|TURN urls=2"
echo "HASH_CHECK|h2|dead|room is gone"
echo "HASH_CHECK|h3|captcha|v2 challenge"
`)
	got, err := NewHashChecker(bin, quiet()).Check(context.Background(), []string{"h1", "h2", "h3"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("verdicts = %v", got)
	}
	if !got["h1"].Conclusive() || got["h1"].Dead() {
		t.Errorf("h1 = %+v, want a conclusive live verdict", got["h1"])
	}
	if !got["h2"].Dead() {
		t.Errorf("h2 = %+v, want dead", got["h2"])
	}
	// A captcha says nothing about the link: acting on it would empty a pool
	// because the checker happened to be challenged.
	if got["h3"].Conclusive() || got["h3"].Dead() {
		t.Errorf("h3 = %+v, want an inconclusive verdict", got["h3"])
	}
	if got["h1"].Detail != "TURN urls=2" {
		t.Errorf("detail = %q", got["h1"].Detail)
	}
}

// TestHashCheckKeepsPipesInTheDetail: the detail is free text and splitting it
// on every pipe would truncate the one thing an admin reads.
func TestHashCheckKeepsPipesInTheDetail(t *testing.T) {
	bin := fakeBinary(t, `echo "HASH_CHECK|h1|error|step5 failed|retry=2|code=7"`)
	got, err := NewHashChecker(bin, quiet()).Check(context.Background(), []string{"h1"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got["h1"].Detail != "step5 failed|retry=2|code=7" {
		t.Errorf("detail = %q, want the pipes kept", got["h1"].Detail)
	}
}

// TestHashCheckPassesEveryHash guards the argument list: a hash left off is a
// link that silently never gets validated.
func TestHashCheckPassesEveryHash(t *testing.T) {
	bin := fakeBinary(t, `
for h in "$@"; do echo "HASH_CHECK|$h|ok|seen"; done
`)
	hashes := []string{"a", "b", "c", "d"}
	got, err := NewHashChecker(bin, quiet()).Check(context.Background(), hashes)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	for _, h := range hashes {
		if _, ok := got[h]; !ok {
			t.Errorf("%s was not checked", h)
		}
	}
}

// TestHashCheckKeepsVerdictsFromABadExit matters because the helper reports as
// it goes and may exit non-zero after finding a dead link. Throwing the output
// away would waste a run that takes a minute per hash.
func TestHashCheckKeepsVerdictsFromABadExit(t *testing.T) {
	bin := fakeBinary(t, `
echo "HASH_CHECK|h1|dead|gone"
echo "something broke" >&2
exit 3
`)
	got, err := NewHashChecker(bin, quiet()).Check(context.Background(), []string{"h1"})
	if err != nil {
		t.Fatalf("Check should keep the verdicts it got: %v", err)
	}
	if !got["h1"].Dead() {
		t.Errorf("h1 = %+v", got["h1"])
	}
}

func TestHashCheckFailsLoudlyWithNoVerdicts(t *testing.T) {
	bin := fakeBinary(t, `echo "cannot start" >&2; exit 1`)
	_, err := NewHashChecker(bin, quiet()).Check(context.Background(), []string{"h1"})
	if err == nil {
		t.Fatal("a helper that said nothing was reported as success")
	}
	if !strings.Contains(err.Error(), "cannot start") {
		t.Errorf("error should carry the helper's complaint: %v", err)
	}
}

func TestHashCheckWithNothingToDo(t *testing.T) {
	// No binary needed: an empty pool is answered without running anything.
	got, err := NewHashChecker("", quiet()).Check(context.Background(), nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestHashCheckRejectsAMissingBinary(t *testing.T) {
	_, err := NewHashChecker("/nonexistent/helper", quiet()).
		Check(context.Background(), []string{"h1"})
	if err == nil {
		t.Fatal("a missing helper was accepted")
	}
}

// TestWARPRegistrationScrapesTheAccount covers the awkward part: the account
// is a JSON object embedded in a binary cache file, written by a core that
// keeps running afterwards.
func TestWARPRegistrationScrapesTheAccount(t *testing.T) {
	old := WARPPollInterval
	WARPPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { WARPPollInterval = old })

	// Writes binary noise around the account, as the real cache does, and then
	// keeps running until it is killed.
	bin := fakeBinary(t, `
cfg=""
while [ $# -gt 0 ]; do [ "$1" = "-c" ] && cfg="$2"; shift; done
db=$(grep -o '"path": *"[^"]*"' "$cfg" | head -1 | sed 's/.*"\(\/[^"]*\)"/\1/')
printf '\x01\x02binary{"other":"record"}noise' > "$db"
printf '{"private_key":"k","endpoint_v4":"162.159.198.1","ipv4":"172.16.0.2"}' >> "$db"
printf 'trailing\x00bytes' >> "$db"
while true; do sleep 1; done
`)

	registrar := NewWARPRegistrar(bin, func(cacheDB string) any {
		return map[string]any{
			"experimental": map[string]any{
				"cache_file": map[string]any{"enabled": true, "path": cacheDB},
			},
		}
	}, quiet())

	account, err := registrar.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(account, &decoded); err != nil {
		t.Fatalf("the scraped account does not parse: %v (%s)", err, account)
	}
	if decoded["private_key"] != "k" || decoded["ipv4"] != "172.16.0.2" {
		t.Errorf("account = %v", decoded)
	}
	// The other JSON record in the file must not be mistaken for the account.
	if _, wrong := decoded["other"]; wrong {
		t.Error("the scrape matched the wrong record")
	}
}

func TestWARPRegistrationGivesUpWhenNothingAppears(t *testing.T) {
	oldPoll, oldTimeout := WARPPollInterval, WARPRegisterTimeout
	WARPPollInterval, WARPRegisterTimeout = 5*time.Millisecond, 80*time.Millisecond
	t.Cleanup(func() { WARPPollInterval, WARPRegisterTimeout = oldPoll, oldTimeout })

	bin := fakeBinary(t, `while true; do sleep 1; done`)
	registrar := NewWARPRegistrar(bin, func(string) any { return map[string]any{} }, quiet())

	start := time.Now()
	if _, err := registrar.Register(context.Background()); err == nil {
		t.Fatal("a registration that produced nothing was reported as success")
	}
	// And it gave up rather than hanging: the button behind this has a user
	// waiting on it.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %s to give up", elapsed)
	}
}

func TestWARPRegistrationHonoursCancellation(t *testing.T) {
	oldPoll := WARPPollInterval
	WARPPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { WARPPollInterval = oldPoll })

	bin := fakeBinary(t, `while true; do sleep 1; done`)
	registrar := NewWARPRegistrar(bin, func(string) any { return map[string]any{} }, quiet())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := registrar.Register(ctx)
		done <- err
	}()
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Error("cancellation was reported as a successful registration")
		}
	case <-time.After(5 * time.Second):
		t.Error("Register ignored cancellation")
	}
}

func TestWARPRegistrationRejectsAMissingBinary(t *testing.T) {
	registrar := NewWARPRegistrar("/nonexistent/core", func(string) any { return nil }, quiet())
	if _, err := registrar.Register(context.Background()); err == nil {
		t.Fatal("a missing core was accepted")
	}
}

// TestWARPRegistrationCleansUp: the helper writes an account into a temporary
// directory, and leaving those behind would scatter credentials across /tmp.
func TestWARPRegistrationCleansUp(t *testing.T) {
	old := WARPPollInterval
	WARPPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { WARPPollInterval = old })

	before := countTempDirs(t)
	bin := fakeBinary(t, `
cfg=""
while [ $# -gt 0 ]; do [ "$1" = "-c" ] && cfg="$2"; shift; done
db=$(grep -o '"path": *"[^"]*"' "$cfg" | head -1 | sed 's/.*"\(\/[^"]*\)"/\1/')
printf '{"private_key":"k","ipv4":"1.2.3.4"}' > "$db"
`)
	registrar := NewWARPRegistrar(bin, func(cacheDB string) any {
		return map[string]any{"experimental": map[string]any{
			"cache_file": map[string]any{"path": cacheDB}}}
	}, quiet())

	if _, err := registrar.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if after := countTempDirs(t); after > before {
		t.Errorf("left %d registration directories behind", after-before)
	}
}

func countTempDirs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "warpreg-") {
			n++
		}
	}
	return n
}
