package subserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeStore stands in for the bot's cache and records what was asked for, so a
// test can assert the token reached it undecorated.
type fakeStore struct {
	bundles map[string][]byte
	err     error
	asked   []string
}

func (f *fakeStore) BundleCache(token string) ([]byte, bool, error) {
	f.asked = append(f.asked, token)
	if f.err != nil {
		return nil, false, f.err
	}
	bundle, ok := f.bundles[token]
	return bundle, ok, nil
}

func newServer(store *fakeStore) *Server {
	return New(store, slog.New(slog.DiscardHandler))
}

func get(t *testing.T, h http.Handler, path string) *http.Response {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Result()
}

func TestServesTheCachedBundleVerbatim(t *testing.T) {
	bundle := []byte(`{"outbounds":[{"type":"vless","tag":"VLESS Reality"}]}`)
	store := &fakeStore{bundles: map[string][]byte{"tok-1": bundle}}
	resp := get(t, newServer(store).Handler(), "/sub/tok-1")

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	// Verbatim: the cache is what the refresh loop built, and re-encoding it
	// here would be a second chance to change what a client receives.
	if string(body) != string(bundle) {
		t.Errorf("body = %s, want the cached bytes", body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	// An intermediary holding an old copy would defeat the whole point of a
	// URL the client re-polls.
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if len(store.asked) != 1 || store.asked[0] != "tok-1" {
		t.Errorf("store was asked for %v", store.asked)
	}
}

func TestUnknownTokenIsNotFound(t *testing.T) {
	resp := get(t, newServer(&fakeStore{bundles: map[string][]byte{}}).Handler(), "/sub/nope")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// TestAnUnreadableCacheLooksLikeAMiss keeps the endpoint from confirming that
// a token exists when something behind it is broken.
func TestAnUnreadableCacheLooksLikeAMiss(t *testing.T) {
	store := &fakeStore{err: errors.New("disk is on fire")}
	resp := get(t, newServer(store).Handler(), "/sub/tok-1")

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "fire") {
		t.Errorf("the error reached the client: %s", body)
	}
}

// TestHealthAnswersEverywhereElse: this port sits behind a tunnel and a
// reverse proxy, both of which probe the root. A 404 there reads as the
// service being down.
func TestHealthAnswersEverywhereElse(t *testing.T) {
	h := newServer(&fakeStore{}).Handler()
	for _, path := range []string{"/", "/healthz", "/anything"} {
		resp := get(t, h, path)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s -> %d, want 200", path, resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if strings.TrimSpace(string(body)) != "ok" {
			t.Errorf("%s -> %q", path, body)
		}
	}
}

// TestTokenIsNotAPath is the traversal guard at the routing layer. The store
// filters names too, but a token with a slash should never reach it: it would
// be asking for a different resource.
func TestTokenIsNotAPath(t *testing.T) {
	store := &fakeStore{bundles: map[string][]byte{}}
	h := newServer(store).Handler()

	// ServeMux normalises a path before routing, so a traversal attempt is
	// answered with a redirect to the cleaned path rather than reaching this
	// handler at all. Either way it must not produce a bundle, and the store
	// must never be asked for it -- which is the assertion that matters.
	for _, path := range []string{"/sub/", "/sub/a/b", "/sub/../../etc/passwd"} {
		resp := get(t, h, path)
		if resp.StatusCode == http.StatusOK && strings.HasPrefix(path, "/sub/") && path != "/sub/" {
			body, _ := io.ReadAll(resp.Body)
			if strings.Contains(string(body), "outbounds") {
				t.Errorf("%s served a bundle", path)
			}
		}
	}
	for _, asked := range store.asked {
		if strings.Contains(asked, "/") {
			t.Errorf("a token containing a slash reached the store: %q", asked)
		}
	}
}

func TestOnlyReadsAreAllowed(t *testing.T) {
	h := newServer(&fakeStore{bundles: map[string][]byte{"tok": []byte("{}")}}).Handler()

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "/sub/tok", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s -> %d, want 405", method, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow == "" {
			t.Errorf("%s: no Allow header", method)
		}
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/sub/tok", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("HEAD -> %d, want 200", rec.Code)
	}
}

// TestRunServesAndStops exercises the real listener, because the shutdown path
// is the part a handler test cannot reach.
func TestRunServesAndStops(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	store := &fakeStore{bundles: map[string][]byte{"tok": []byte(`{"outbounds":[]}`)}}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- newServer(store).Run(ctx, addr) }()

	deadline := time.Now().Add(5 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = http.Get("http://" + addr + "/sub/tok")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("server never answered: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != `{"outbounds":[]}` {
		t.Errorf("body = %s", body)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run returned %v; a cancelled context is a clean stop", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("Run did not return after the context was cancelled")
	}
}

// TestRunReportsAnUnusableAddress is also the regression test for a deadlock:
// Run used to wait on a watcher goroutine that sat on ctx.Done(), which for
// context.Background() is a nil channel and blocks forever. A port already in
// use would therefore hang the bot at startup instead of reporting why.
//
// A port out of range rather than an unroutable host: a bad host name sends Go
// to the resolver and the test would wait on DNS instead of on the thing it is
// checking. This fails in the parser, immediately.
func TestRunReportsAnUnusableAddress(t *testing.T) {
	done := make(chan error, 1)
	go func() { done <- newServer(&fakeStore{}).Run(context.Background(), "127.0.0.1:99999") }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an unusable listen address was accepted")
		}
		if !strings.Contains(err.Error(), "subserver") {
			t.Errorf("error should name the package: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after failing to listen; it is waiting on something")
	}
}
