package vk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mintServer answers getCallToken with a fixed reply and records the request it
// saw, so a test can assert both the answer and how VK was asked.
type mintServer struct {
	server  *httptest.Server
	reply   any
	gotAuth string
	gotPath string
	gotQ    map[string]string
}

func newMintServer(t *testing.T, reply any) *mintServer {
	t.Helper()
	m := &mintServer{reply: reply, gotQ: map[string]string{}}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.gotAuth = r.Header.Get("Authorization")
		m.gotPath = r.URL.Path
		for k := range r.URL.Query() {
			m.gotQ[k] = r.URL.Query().Get(k)
		}
		body, _ := json.Marshal(m.reply)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mintServer) client() *Client {
	return &Client{APIHost: m.server.URL}
}

func TestMintCallTokenReturnsTheTokenAndHost(t *testing.T) {
	m := newMintServer(t, map[string]any{
		"response": map[string]any{"api_base_url": "https://calls.okcdn.ru", "token": "$uumTOKEN"},
	})
	ct, err := m.client().MintCallToken(context.Background(), "  vk1.a.ACCESS  ")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if ct.Token != "$uumTOKEN" || ct.APIBaseURL != "https://calls.okcdn.ru" {
		t.Fatalf("call token = %+v", ct)
	}
	// The access token travels as a Bearer header, trimmed, never in the query.
	if m.gotAuth != "Bearer vk1.a.ACCESS" {
		t.Errorf("Authorization = %q", m.gotAuth)
	}
	if m.gotPath != "/method/messages.getCallToken" {
		t.Errorf("path = %q", m.gotPath)
	}
	for k, want := range map[string]string{"env": "production", "v": CallsAPIVersion, "lang": "3"} {
		if m.gotQ[k] != want {
			t.Errorf("query %s = %q, want %q", k, m.gotQ[k], want)
		}
	}
}

func TestMintCallTokenMapsAuthFailureToExpired(t *testing.T) {
	for _, code := range []int{5, 1117, 1114} {
		m := newMintServer(t, map[string]any{
			"error": map[string]any{"error_code": code, "error_msg": "User authorization failed"},
		})
		_, err := m.client().MintCallToken(context.Background(), "vk1.a.DEAD")
		if !errors.Is(err, ErrAccessTokenExpired) {
			t.Fatalf("code %d gave %v, want ErrAccessTokenExpired", code, err)
		}
	}
}

func TestMintCallTokenPassesOtherErrorsThrough(t *testing.T) {
	m := newMintServer(t, map[string]any{
		"error": map[string]any{"error_code": 6, "error_msg": "Too many requests per second"},
	})
	_, err := m.client().MintCallToken(context.Background(), "vk1.a.OK")
	if err == nil || errors.Is(err, ErrAccessTokenExpired) {
		t.Fatalf("a rate-limit error gave %v; it should be a plain retryable error", err)
	}
}

func TestMintCallTokenRejectsAnEmptyAccessToken(t *testing.T) {
	// No server call should happen for an empty token.
	m := newMintServer(t, map[string]any{"response": map[string]any{"token": "nope"}})
	if _, err := m.client().MintCallToken(context.Background(), "   "); !errors.Is(err, ErrAccessTokenExpired) {
		t.Fatalf("empty token gave %v, want ErrAccessTokenExpired", err)
	}
	if m.gotAuth != "" {
		t.Errorf("VK was called for an empty token")
	}
}

func TestMintCallTokenErrorsWhenNoTokenInResponse(t *testing.T) {
	m := newMintServer(t, map[string]any{"response": map[string]any{"api_base_url": "https://calls.okcdn.ru"}})
	if _, err := m.client().MintCallToken(context.Background(), "vk1.a.OK"); err == nil {
		t.Fatalf("a response with no token should be an error")
	}
}

func TestExtractAccessTokenFindsTheSilentAuthToken(t *testing.T) {
	// The real response shape, wrapped in surrounding capture noise.
	capture := []byte(`...HTTP/2 frame junk...{"response":{"access_token":"vk1.a.QZ_76k1G-abc.def","access_token_id":"162436512","additional_signup_required":false,"expires_in":31536000,"is_partial":false,"source":1,"user_id":1000000}}trailing...`)
	at, err := ExtractAccessToken(capture)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if at.Token != "vk1.a.QZ_76k1G-abc.def" {
		t.Errorf("token = %q", at.Token)
	}
	if at.ExpiresIn != 31536000 {
		t.Errorf("expires_in = %d, want 31536000 (a year)", at.ExpiresIn)
	}
	if at.UserID != "1000000" {
		t.Errorf("user_id = %q", at.UserID)
	}
}

func TestExtractAccessTokenReportsWhenAbsent(t *testing.T) {
	if _, err := ExtractAccessToken([]byte(`{"response":1}no token here`)); err == nil {
		t.Fatalf("a capture without an exchange response should error")
	}
}
