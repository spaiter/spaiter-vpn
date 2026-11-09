package selftest

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// liveFixture writes a config.json the self-test can read and returns options
// pointing at a stub management API.
func liveFixture(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (Options, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	doc := fmt.Sprintf(`{"log":{"output":"/etc/sing-box/sing-box.log","level":"debug"},
		"experimental":{"clash_api":{"external_controller":%q,"secret":"test-only"}}}`, strings.TrimPrefix(server.URL, "http://"))
	if err := os.WriteFile(config, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := DefaultOptions()
	opts.ConfigPath = config
	opts.LogPath = filepath.Join(dir, "sing-box.log")
	opts.Port = 0 // never bound, so the post-cleanup port check cannot trip on this host
	opts.SettleDelay, opts.HandshakeTimeout = 0, 0
	return opts, &calls
}

func TestRunRefusesAnUnreadableOrIncompleteConfigBeforeTouchingAnything(t *testing.T) {
	opts := DefaultOptions()
	opts.ConfigPath = filepath.Join(t.TempDir(), "absent.json")
	if _, err := Run(context.Background(), &bytes.Buffer{}, opts); err == nil {
		t.Fatal("a missing config was accepted")
	}

	// No clash API secret: the management API rejects unauthenticated calls,
	// so the run stops here instead of failing mid-way with an endpoint added.
	dir := t.TempDir()
	opts.ConfigPath = filepath.Join(dir, "config.json")
	os.WriteFile(opts.ConfigPath, []byte(`{"log":{"output":"/x/log","level":"debug"}}`), 0o600)
	opts.LogPath = filepath.Join(dir, "log")
	if _, err := Run(context.Background(), &bytes.Buffer{}, opts); err == nil {
		t.Fatal("a config with no clash API was accepted")
	}
}

func TestRunStopsAtAFailedAddWithNothingToCleanUp(t *testing.T) {
	opts, calls := liveFixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "refused", http.StatusInternalServerError)
	})
	var out bytes.Buffer
	_, err := Run(context.Background(), &out, opts)
	if err == nil || !strings.Contains(err.Error(), "add test endpoint") {
		t.Fatalf("err = %v", err)
	}
	for _, c := range *calls {
		if strings.HasPrefix(c, "DELETE") || strings.HasSuffix(c, "/apply") {
			t.Errorf("the run went on after the endpoint was refused: %v", *calls)
		}
	}
	if strings.Contains(out.String(), "CLEANUP FAILED") {
		t.Errorf("cleanup was attempted for an endpoint that was never added:\n%s", out.String())
	}
}

func TestRunRemovesItsEndpointWhenTheApplyFails(t *testing.T) {
	opts, calls := liveFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/manage/apply":
			http.Error(w, "apply exploded", http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	var out bytes.Buffer
	_, err := Run(context.Background(), &out, opts)
	if err == nil || !strings.Contains(err.Error(), "apply test endpoint") {
		t.Fatalf("err = %v", err)
	}
	// Whatever went wrong, the endpoint it added must be asked to be removed.
	deleted := false
	for _, c := range *calls {
		if c == "DELETE /manage/endpoints/"+opts.Tag {
			deleted = true
		}
	}
	if !deleted {
		t.Errorf("the test endpoint was left in the config: %v", *calls)
	}
}

func TestRunRefusesAnApplyThatDisturbedExistingEndpoints(t *testing.T) {
	opts, calls := liveFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/manage/apply" {
			// Recreating or reloading means live listeners were torn down.
			fmt.Fprint(w, `{"message":"ok","endpoints":{"added":["`+"bt-selftest-in"+`"],"recreated":["prod-in"]}}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	var out bytes.Buffer
	_, err := Run(context.Background(), &out, opts)
	if err == nil {
		t.Fatal("an apply that recreated a production endpoint passed")
	}
	if !strings.Contains(err.Error(), "prod-in") {
		t.Errorf("the disturbed endpoint is not named: %v", err)
	}
	found := false
	for _, c := range *calls {
		found = found || strings.HasPrefix(c, "DELETE /manage/endpoints/")
	}
	if !found {
		t.Errorf("no cleanup after a refused apply: %v", *calls)
	}
}

// liveFixtureAt rebuilds a fixture around a new handler and log level, keeping
// the options' other settings.
func liveFixtureAt(t *testing.T, level string, handler func(w http.ResponseWriter, r *http.Request), base Options) (Options, *[]string) {
	t.Helper()
	opts, calls := liveFixture(t, handler)
	opts.Port, opts.SettleDelay, opts.HandshakeTimeout = base.Port, base.SettleDelay, base.HandshakeTimeout
	// The core has been running, so its log exists before the test begins.
	if err := os.WriteFile(opts.LogPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(opts.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opts.ConfigPath, []byte(strings.Replace(string(data), `"level":"debug"`, `"level":"`+level+`"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	return opts, calls
}
