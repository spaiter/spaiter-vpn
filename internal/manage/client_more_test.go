package manage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/core/option"
)

func TestNewRefusesWhatCannotWork(t *testing.T) {
	if _, err := New("", "s"); err == nil {
		t.Error("no address was accepted")
	}
	// The API rejects unauthenticated requests, so a client without a secret
	// is a client that fails on every call; better to fail here, once.
	if _, err := New("127.0.0.1:9090", ""); err == nil {
		t.Error("no secret was accepted")
	}
	if _, err := New("http://[::1", "s"); err == nil {
		t.Error("an unparsable address was accepted")
	}
	c, err := New("https://core.example:9443/", "s")
	if err != nil || c.BaseURL != "https://core.example:9443" {
		t.Errorf("explicit scheme: %+v %v", c, err)
	}
}

func TestEndpointCallsUseTheRightVerbsAndPaths(t *testing.T) {
	var bodies []string
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(data))
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/manage/endpoints":
			w.Write([]byte(`[{"tag":"a"},{"tag":"b"}]`))
		case r.URL.Path == "/manage/apply":
			w.Write([]byte(`{"message":"ok","endpoints":{"added":["a"],"reloaded":null}}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	c := clientFor(t, s)
	ctx := context.Background()

	if err := c.AddEndpoint(ctx, option.Endpoint{Type: "wireguard", Tag: "wg-new", Options: &option.WireGuardEndpointOptions{MTU: 1280}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bodies[0], `"tag":"wg-new"`) {
		t.Errorf("body = %s", bodies[0])
	}
	if err := c.DeleteEndpoint(ctx, "wg/new"); err != nil {
		t.Fatal(err)
	}
	// A tag with a slash must stay one path segment.
	if got := s.raw[1]; got != "DELETE /manage/endpoints/wg%2Fnew" {
		t.Errorf("raw = %q", got)
	}
	result, err := c.Apply(ctx)
	if err != nil || result.Message != "ok" || len(result.Endpoints.Added) != 1 || result.Endpoints.Recreated != nil || result.Endpoints.Reloaded != nil {
		t.Fatalf("apply: %+v %v (a brand-new tag must be Added, with nothing recreated)", result, err)
	}
	list, err := c.Endpoints(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("endpoints: %v %v", list, err)
	}
	want := []string{"POST /manage/endpoints", "DELETE /manage/endpoints/wg/new", "POST /manage/apply", "GET /manage/endpoints"}
	for i, w := range want {
		if s.seen[i] != w {
			t.Errorf("call %d = %q, want %q", i, s.seen[i], w)
		}
	}
}

func TestMalformedResponsesAreErrorsNotEmptyResults(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", 600)))
	})
	c := clientFor(t, s)
	ctx := context.Background()
	if _, err := c.Apply(ctx); err == nil || !strings.Contains(err.Error(), "decode apply response") {
		t.Errorf("apply: %v", err)
	} else if strings.Count(err.Error(), "x") > 410 {
		t.Errorf("a huge body was echoed into the error: %d bytes", len(err.Error()))
	}
	if _, err := c.Endpoints(ctx); err == nil || !strings.Contains(err.Error(), "decode endpoint list") {
		t.Errorf("endpoints: %v", err)
	}
	if _, err := c.UserStats(ctx); err == nil || !strings.Contains(err.Error(), "decode user stats") {
		t.Errorf("stats: %v", err)
	}
}

func TestStatusCodesAreClassified(t *testing.T) {
	code := http.StatusOK
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		w.Write([]byte("detail"))
	})
	c := clientFor(t, s)
	ctx := context.Background()
	for status, check := range map[int]func(error) bool{
		http.StatusNotFound:   func(err error) bool { return errors.Is(err, ErrNotFound) },
		http.StatusBadRequest: func(err error) bool { return errors.Is(err, ErrBadRequest) },
		http.StatusInternalServerError: func(err error) bool {
			return !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrBadRequest) && strings.Contains(err.Error(), "HTTP 500")
		},
		http.StatusUnauthorized: func(err error) bool { return strings.Contains(err.Error(), "HTTP 401") },
	} {
		code = status
		err := c.DeleteEndpoint(ctx, "t")
		if err == nil || !check(err) || !strings.Contains(err.Error(), "detail") {
			t.Errorf("status %d: %v", status, err)
		}
	}
	code = http.StatusNoContent
	if err := c.DeleteEndpoint(ctx, "t"); err != nil {
		t.Errorf("204: %v", err)
	}
	// A dead server is a transport error naming the call.
	s.Close()
	if err := c.DeleteEndpoint(ctx, "t"); err == nil || !strings.Contains(err.Error(), "DELETE /manage/endpoints/t") {
		t.Errorf("closed server: %v", err)
	}
	// A cancelled context stops the call.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.Endpoints(cctx); err == nil {
		t.Error("a cancelled context still made the call")
	}
}

func TestEndpointReadsOneEndpointVerbatim(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag":"wg","peers":[{"public_key":"k"}]}`))
	})
	raw, err := clientFor(t, s).Endpoint(context.Background(), "wg")
	if err != nil || !json.Valid(raw) || !strings.Contains(string(raw), "public_key") {
		t.Errorf("%s %v", raw, err)
	}
	if s.seen[0] != "GET /manage/endpoints/wg" {
		t.Errorf("seen = %v", s.seen)
	}
}

func TestCredentialsFromCoreConfig(t *testing.T) {
	c, err := CredentialsFromCoreConfig([]byte(`{"experimental":{"clash_api":{"external_controller":":9090","secret":"s3"}}}`))
	if err != nil || c.Controller != "127.0.0.1:9090" || c.Secret != "s3" {
		t.Errorf("%+v %v", c, err)
	}
	c, _ = CredentialsFromCoreConfig([]byte(`{"experimental":{"clash_api":{"external_controller":"10.0.0.1:1","secret":"s"}}}`))
	if c.Controller != "10.0.0.1:1" {
		t.Errorf("an explicit host was rewritten: %q", c.Controller)
	}
	for name, doc := range map[string]string{
		"not json": "{", "no controller": `{"experimental":{"clash_api":{"secret":"s"}}}`,
		"no secret": `{"experimental":{"clash_api":{"external_controller":":1"}}}`, "empty": `{}`,
	} {
		if _, err := CredentialsFromCoreConfig([]byte(doc)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestNewFromCredentialsFileIsStrict(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	c, err := NewFromCredentialsFile(write("ok.json", `{"controller":"127.0.0.1:9090","secret":"s"}`))
	if err != nil || c.BaseURL != "http://127.0.0.1:9090" || c.Secret != "s" {
		t.Fatalf("%+v %v", c, err)
	}
	for name, content := range map[string]string{
		"typo":       `{"controler":"127.0.0.1:9090","secret":"s"}`, // an unknown field must not pass as an empty one
		"no secret":  `{"controller":"127.0.0.1:9090"}`,
		"no address": `{"secret":"s"}`,
		"not json":   `controller: x`,
	} {
		if _, err := NewFromCredentialsFile(write(name+".json", content)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := NewFromCredentialsFile(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("a missing file was accepted")
	}
	// The secret must never come back in an error message.
	_, err = NewFromCredentialsFile(write("leak.json", `{"controller":"127.0.0.1:1","secret":"TOPSECRET","extra":1}`))
	if err == nil || strings.Contains(err.Error(), "TOPSECRET") {
		t.Errorf("error leaks the secret or is nil: %v", err)
	}
}
