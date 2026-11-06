package manage

import (
	"context"
	"encoding/json"
	"errors"
	stdio "io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stub serves the slice of the API these methods use and records what it was
// asked, so a test can assert the method and path as well as the decoding.
type stub struct {
	*httptest.Server
	seen []string // method + decoded path, for routing assertions
	raw  []string // method + RequestURI, the only place the wire form survives
}

func newStub(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *stub {
	t.Helper()
	s := &stub{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.seen = append(s.seen, r.Method+" "+r.URL.Path)
		s.raw = append(s.raw, r.Method+" "+r.RequestURI)
		if got := r.Header.Get("Authorization"); got != "Bearer test-secret" {
			t.Errorf("Authorization = %q, want the bearer secret", got)
		}
		handler(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func clientFor(t *testing.T, s *stub) *Client {
	t.Helper()
	c, err := New(strings.TrimPrefix(s.URL, "http://"), "test-secret")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestInboundsAndUsers(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manage/inbounds":
			_, _ = w.Write([]byte(`[{"tag":"vless-reality-in","type":"vless"},{"tag":"mieru-in","type":"mieru"}]`))
		case "/manage/inbounds/vless-reality-in":
			_, _ = w.Write([]byte(`{"tag":"vless-reality-in","type":"vless","listen_port":10861}`))
		case "/manage/inbounds/vless-reality-in/users":
			_, _ = w.Write([]byte(`[{"name":"alice","uuid":"u-1"}]`))
		default:
			http.NotFound(w, r)
		}
	})
	c := clientFor(t, s)
	ctx := context.Background()

	list, err := c.Inbounds(ctx)
	if err != nil {
		t.Fatalf("Inbounds: %v", err)
	}
	if len(list) != 2 || list[0].Tag != "vless-reality-in" || list[1].Type != "mieru" {
		t.Fatalf("Inbounds = %+v", list)
	}

	raw, err := c.Inbound(ctx, "vless-reality-in")
	if err != nil {
		t.Fatalf("Inbound: %v", err)
	}
	// Returned verbatim, so a caller can read a protocol-specific field this
	// package deliberately does not model.
	var inbound struct {
		ListenPort int `json:"listen_port"`
	}
	if err := json.Unmarshal(raw, &inbound); err != nil || inbound.ListenPort != 10861 {
		t.Fatalf("inbound did not come back verbatim: %v %q", err, raw)
	}

	users, err := c.Users(ctx, "vless-reality-in")
	if err != nil {
		t.Fatalf("Users: %v", err)
	}
	if len(users) != 1 || !strings.Contains(string(users[0]), "alice") {
		t.Fatalf("Users = %q", users)
	}
}

// TestUsersOfInboundWithoutUserListIsNotAnError is the case that would
// otherwise read as a broken API: an inbound that simply has no users yet.
func TestUsersOfInboundWithoutUserListIsNotAnError(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	users, err := clientFor(t, s).Users(context.Background(), "snell-in")
	if err != nil {
		t.Fatalf("a 404 user list should be empty, not an error: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("users = %q, want none", users)
	}
}

func TestNotFoundIsDistinguishable(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	_, err := clientFor(t, s).Inbound(context.Background(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error should wrap ErrNotFound, got %v", err)
	}
}

func TestServerErrorIsNotMistakenForNotFound(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	_, err := clientFor(t, s).Inbound(context.Background(), "x")
	if err == nil {
		t.Fatal("a 500 must be an error")
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("a 500 was reported as ErrNotFound; callers would treat it as normal")
	}
}

func TestAddAndDeleteUser(t *testing.T) {
	var body []byte
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body = readBody(t, r)
		}
		_, _ = w.Write([]byte(`{}`))
	})
	c := clientFor(t, s)
	ctx := context.Background()

	if err := c.AddUser(ctx, "tuic-in", map[string]any{"name": "bob", "uuid": "u-2"}); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if !strings.Contains(string(body), `"name":"bob"`) {
		t.Errorf("POST body = %q", body)
	}
	if err := c.DeleteUser(ctx, "tuic-in", "bob"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	want := []string{"POST /manage/inbounds/tuic-in/users", "DELETE /manage/inbounds/tuic-in/users/bob"}
	if len(s.seen) != 2 || s.seen[0] != want[0] || s.seen[1] != want[1] {
		t.Errorf("requests = %v, want %v", s.seen, want)
	}
}

// TestTagsAreEscaped matters because a tag is operator-supplied text and goes
// straight into a path.
func TestTagsAreEscaped(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) })
	if err := clientFor(t, s).DeleteUser(context.Background(), "a/b", "c d"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	// r.URL.Path is already decoded, so the escaping is only visible in the
	// request line. Escaped, a slash in a tag stays inside its segment;
	// unescaped it would address a different resource entirely.
	if got := s.raw[0]; got != "DELETE /manage/inbounds/a%2Fb/users/c%20d" {
		t.Errorf("request line = %q: the tag separator leaked into the path", got)
	}
}

func TestPutEndpointSendsTheWholeThing(t *testing.T) {
	var body []byte
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			body = readBody(t, r)
		}
		_, _ = w.Write([]byte(`{}`))
	})
	ep := map[string]any{
		"tag":   "awg-in",
		"peers": []any{map[string]any{"public_key": "old"}, map[string]any{"public_key": "new"}},
	}
	if err := clientFor(t, s).PutEndpoint(context.Background(), "awg-in", ep); err != nil {
		t.Fatalf("PutEndpoint: %v", err)
	}
	// Both peers must be on the wire: PUT replaces the list, so sending only
	// the new one would drop everyone else's tunnel.
	if !strings.Contains(string(body), `"old"`) || !strings.Contains(string(body), `"new"`) {
		t.Errorf("PUT body = %q, want every peer", body)
	}
}

func TestUserStatsAndReset(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stats/users" {
			_, _ = w.Write([]byte(`[{"user":"alice","upload":1,"download":2,"conn_count":3,"active":4}]`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	c := clientFor(t, s)
	ctx := context.Background()

	stats, err := c.UserStats(ctx)
	if err != nil {
		t.Fatalf("UserStats: %v", err)
	}
	if len(stats) != 1 || stats[0].User != "alice" || stats[0].Download != 2 || stats[0].Active != 4 {
		t.Fatalf("UserStats = %+v", stats)
	}
	if err := c.ResetUserStats(ctx, "alice"); err != nil {
		t.Fatalf("ResetUserStats: %v", err)
	}
	if got := s.seen[1]; got != "DELETE /stats/users/alice" {
		t.Errorf("reset hit %q", got)
	}
}

func TestVersionIsALivenessProbe(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			t.Errorf("Version hit %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"version":"x"}`))
	})
	if err := clientFor(t, s).Version(context.Background()); err != nil {
		t.Fatalf("Version: %v", err)
	}
}

func TestNewFromCoreConfig(t *testing.T) {
	dir := t.TempDir()

	// A controller bound to every interface is dialled on loopback, which is
	// how it is written in the deployment this came from.
	path := filepath.Join(dir, "config.json")
	writeFile(t, path, `{"experimental":{"clash_api":{"external_controller":":9090","secret":"s"}}}`)
	c, err := NewFromCoreConfig(path)
	if err != nil {
		t.Fatalf("NewFromCoreConfig: %v", err)
	}
	if c.BaseURL != "http://127.0.0.1:9090" {
		t.Errorf("BaseURL = %q", c.BaseURL)
	}
	if c.Secret != "s" {
		t.Errorf("Secret = %q", c.Secret)
	}

	explicit := filepath.Join(dir, "explicit.json")
	writeFile(t, explicit, `{"experimental":{"clash_api":{"external_controller":"10.0.0.1:9999","secret":"s"}}}`)
	if c, err := NewFromCoreConfig(explicit); err != nil {
		t.Fatalf("NewFromCoreConfig: %v", err)
	} else if c.BaseURL != "http://10.0.0.1:9999" {
		t.Errorf("BaseURL = %q", c.BaseURL)
	}

	for _, tc := range []struct{ name, content, want string }{
		{"no clash api", `{"experimental":{}}`, "external_controller"},
		{"not json", `{`, "parse"},
	} {
		p := filepath.Join(dir, tc.name+".json")
		writeFile(t, p, tc.content)
		if _, err := NewFromCoreConfig(p); err == nil {
			t.Errorf("%s was accepted", tc.name)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q should mention %q", tc.name, err, tc.want)
		}
	}

	if _, err := NewFromCoreConfig(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("a missing core config must be an error: there is nothing to talk to")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func readBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	defer r.Body.Close()
	data, err := stdio.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	return data
}
