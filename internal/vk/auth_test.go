package vk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// mockVK answers /token from a sequence of responses, recording each query it
// was asked, so a test can assert both what VK was told and what it answered.
type mockVK struct {
	server  *httptest.Server
	replies []any
	queries []url.Values
	i       int
}

func newMockVK(t *testing.T, replies ...any) *mockVK {
	t.Helper()
	m := &mockVK{replies: replies}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.queries = append(m.queries, r.URL.Query())
		if m.i >= len(m.replies) {
			t.Errorf("VK was called more times than it had replies")
			w.WriteHeader(http.StatusTeapot)
			return
		}
		body, _ := json.Marshal(m.replies[m.i])
		m.i++
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockVK) client() *Client {
	return &Client{OAuthHost: m.server.URL, AppID: "123", Secret: "shh", DeviceID: "dev-1"}
}

func TestLoginWithoutASecondFactorReturnsTheToken(t *testing.T) {
	m := newMockVK(t, map[string]any{"access_token": "AT", "user_id": 777})
	tok, ch, err := m.client().Login(context.Background(), "user", "pass")
	if err != nil || ch != nil {
		t.Fatalf("login: token=%v challenge=%v err=%v", tok, ch, err)
	}
	if tok.Access != "AT" || tok.UserID != "777" {
		t.Fatalf("token = %+v", tok)
	}
	q := m.queries[0]
	for k, want := range map[string]string{
		"grant_type": "password", "client_id": "123", "client_secret": "shh",
		"username": "user", "password": "pass", "2fa_supported": "1", "device_id": "dev-1",
	} {
		if q.Get(k) != want {
			t.Errorf("query %s = %q, want %q", k, q.Get(k), want)
		}
	}
	if q.Has("code") {
		t.Errorf("a first sign-in should not carry a code")
	}
}

func TestATwoFactorSignInIsFinishedByTheCode(t *testing.T) {
	m := newMockVK(t,
		map[string]any{"error": "need_validation", "validation_sid": "SID9", "phone_mask": "+7***55", "validation_type": "2fa_sms"},
		map[string]any{"access_token": "AT2", "user_id": "42"},
	)
	c := m.client()
	tok, ch, err := c.Login(context.Background(), "user", "pass")
	if err != nil || tok != nil || ch == nil {
		t.Fatalf("login: token=%v challenge=%v err=%v", tok, ch, err)
	}
	if ch.SID != "SID9" || ch.Hint != "+7***55" || ch.Via != "2fa_sms" {
		t.Fatalf("challenge = %+v", ch)
	}
	tok, err = c.SubmitCode(context.Background(), ch, " 123456 ")
	if err != nil {
		t.Fatalf("submit code: %v", err)
	}
	if tok.Access != "AT2" {
		t.Fatalf("token = %+v", tok)
	}
	// The code was sent, and the resubmission was the same credentials.
	q := m.queries[1]
	if q.Get("code") != "123456" || q.Get("username") != "user" || q.Get("password") != "pass" {
		t.Fatalf("code resubmission query = %v", q)
	}
}

func TestAWrongCodeIsRejectedWithoutLosingTheChallenge(t *testing.T) {
	m := newMockVK(t,
		map[string]any{"error": "need_validation", "validation_sid": "SID9", "validation_type": "2fa_app"},
		map[string]any{"error": "need_validation", "validation_sid": "SID9", "validation_type": "2fa_app"},
		map[string]any{"access_token": "AT3"},
	)
	c := m.client()
	_, ch, err := c.Login(context.Background(), "user", "pass")
	if err != nil || ch == nil {
		t.Fatalf("login: %v %v", ch, err)
	}
	if _, err := c.SubmitCode(context.Background(), ch, "000000"); !errors.Is(err, ErrWrongCode) {
		t.Fatalf("a rejected code gave %v, want ErrWrongCode", err)
	}
	// The same challenge still works for a second attempt.
	tok, err := c.SubmitCode(context.Background(), ch, "654321")
	if err != nil || tok.Access != "AT3" {
		t.Fatalf("retry: token=%v err=%v", tok, err)
	}
}

func TestAnEmptyCodeNeverReachesVK(t *testing.T) {
	m := newMockVK(t, map[string]any{"error": "need_validation", "validation_sid": "S"})
	c := m.client()
	_, ch, _ := c.Login(context.Background(), "user", "pass")
	if _, err := c.SubmitCode(context.Background(), ch, "   "); !errors.Is(err, ErrWrongCode) {
		t.Fatalf("empty code gave %v, want ErrWrongCode", err)
	}
	if len(m.queries) != 1 {
		t.Fatalf("VK was called %d times for an empty code; it should not have been", len(m.queries))
	}
}

func TestABadPasswordIsInvalidCredentials(t *testing.T) {
	m := newMockVK(t, map[string]any{"error": "invalid_client", "error_description": "Username or password is incorrect"})
	_, _, err := m.client().Login(context.Background(), "user", "nope")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("bad password gave %v, want ErrInvalidCredentials", err)
	}
}

func TestACaptchaIsReportedWithItsImage(t *testing.T) {
	m := newMockVK(t, map[string]any{"error": "need_captcha", "captcha_sid": "CS", "captcha_img": "https://vk/c.png"})
	_, _, err := m.client().Login(context.Background(), "user", "pass")
	var captcha *CaptchaError
	if !errors.As(err, &captcha) {
		t.Fatalf("captcha gave %v, want *CaptchaError", err)
	}
	if captcha.SID != "CS" || captcha.ImageURL != "https://vk/c.png" {
		t.Fatalf("captcha = %+v", captcha)
	}
}
