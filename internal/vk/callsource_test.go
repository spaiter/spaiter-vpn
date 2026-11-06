package vk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// constAccess returns a fixed access token.
func constAccess(tok string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return tok, nil }
}

// mintOnly serves getCallToken with a fixed token, counting the calls.
func mintOnly(t *testing.T, token string, calls *atomic.Int32) *Client {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			calls.Add(1)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"response": map[string]any{"api_base_url": "https://calls.okcdn.ru", "token": token},
		})
	}))
	t.Cleanup(s.Close)
	return &Client{APIHost: s.URL}
}

func fakeDial(ctx context.Context, _ string) (CallConn, error) {
	return &fakeConn{drop: make(chan struct{})}, nil
}

func TestLiveCallSourceOpensACall(t *testing.T) {
	ok := newOKServer(t,
		map[string]any{"session_key": "SK", "uid": 7},
		map[string]any{"join_link": "HASH", "token": "WT", "id": "c1"})
	src := &LiveCallSource{
		OK:          ok.client(),
		Mint:        mintOnly(t, "$uumTOK", nil),
		AccessToken: constAccess("vk1.a.OK"),
		Dial:        fakeDial,
	}
	link, conn, err := src.Open(context.Background())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if link != "HASH" || conn == nil {
		t.Fatalf("link=%q conn=%v", link, conn)
	}
}

func TestLiveCallSourcePropagatesADeadAccessToken(t *testing.T) {
	// Mint server that rejects the access token (error_code 5).
	ms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"error_code": 5, "error_msg": "User authorization failed"},
		})
	}))
	t.Cleanup(ms.Close)
	src := &LiveCallSource{
		OK:          &OKClient{Host: "http://unused"},
		Mint:        &Client{APIHost: ms.URL},
		AccessToken: constAccess("vk1.a.DEAD"),
		Dial:        fakeDial,
	}
	if _, _, err := src.Open(context.Background()); !errors.Is(err, ErrAccessTokenExpired) {
		t.Fatalf("open gave %v, want ErrAccessTokenExpired", err)
	}
}

func TestLiveCallSourceRemintsAStaleCallToken(t *testing.T) {
	var anonymCalls atomic.Int32
	var mintCalls atomic.Int32
	// okcdn: first anonymLogin has no session key (stale), the next succeeds.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/auth/anonymLogin"):
			if anonymCalls.Add(1) == 1 {
				_ = json.NewEncoder(w).Encode(map[string]any{"error_code": 401, "error_msg": "Token is outdated"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"session_key": "SK", "uid": 7})
		case strings.HasPrefix(r.URL.Path, "/api/vchat/startConversation"):
			_ = json.NewEncoder(w).Encode(map[string]any{"join_link": "HASH", "token": "WT", "id": "c1"})
		}
	}))
	t.Cleanup(ok.Close)

	src := &LiveCallSource{
		OK:          &OKClient{Host: ok.URL},
		Mint:        mintOnly(t, "$uumTOK", &mintCalls),
		AccessToken: constAccess("vk1.a.OK"),
		Dial:        fakeDial,
	}
	link, _, err := src.Open(context.Background())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if link != "HASH" {
		t.Fatalf("link = %q", link)
	}
	// Minted twice: once on the first open, once to replace the stale token.
	if got := mintCalls.Load(); got != 2 {
		t.Fatalf("mint calls = %d, want 2 (initial + re-mint)", got)
	}
	if got := anonymCalls.Load(); got != 2 {
		t.Fatalf("anonymLogin calls = %d, want 2", got)
	}
}
