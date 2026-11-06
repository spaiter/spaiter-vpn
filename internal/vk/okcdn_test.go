package vk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// okServer answers the two okcdn endpoints from fixed replies and records the
// query it was asked, so a test can assert both sides of each call.
type okServer struct {
	server     *httptest.Server
	anonym     any
	start      any
	anonymSeen url.Values
	startSeen  url.Values
}

func newOKServer(t *testing.T, anonym, start any) *okServer {
	t.Helper()
	o := &okServer{anonym: anonym, start: start}
	o.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/auth/anonymLogin"):
			o.anonymSeen = r.URL.Query()
			_ = json.NewEncoder(w).Encode(o.anonym)
		case strings.HasPrefix(r.URL.Path, "/api/vchat/startConversation"):
			o.startSeen = r.URL.Query()
			_ = json.NewEncoder(w).Encode(o.start)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(o.server.Close)
	return o
}

func (o *okServer) client() *OKClient { return &OKClient{Host: o.server.URL} }

func TestAnonymLoginReturnsTheSession(t *testing.T) {
	o := newOKServer(t,
		map[string]any{"session_key": "SK123", "uid": 579898041479},
		nil)
	s, err := o.client().AnonymLogin(context.Background(), "$uumCALL")
	if err != nil {
		t.Fatalf("anonymLogin: %v", err)
	}
	if s.SessionKey != "SK123" || s.UID != "579898041479" {
		t.Fatalf("session = %+v", s)
	}
	// The call token travels as auth_token inside session_data, with the fixed app key.
	if o.anonymSeen.Get("application_key") != OKAppKey {
		t.Errorf("application_key = %q", o.anonymSeen.Get("application_key"))
	}
	var sd map[string]any
	if err := json.Unmarshal([]byte(o.anonymSeen.Get("session_data")), &sd); err != nil {
		t.Fatalf("session_data not JSON: %v", err)
	}
	if sd["auth_token"] != "$uumCALL" {
		t.Errorf("auth_token = %v", sd["auth_token"])
	}
}

func TestAnonymLoginMapsAMissingSessionKeyToExpired(t *testing.T) {
	o := newOKServer(t,
		map[string]any{"error_code": 401, "error_msg": "AUTH_LOGIN : Token is outdated"},
		nil)
	_, err := o.client().AnonymLogin(context.Background(), "$uumOLD")
	if !errors.Is(err, ErrCallTokenExpired) {
		t.Fatalf("outdated token gave %v, want ErrCallTokenExpired", err)
	}
}

func TestAnonymLoginRejectsAnEmptyToken(t *testing.T) {
	o := newOKServer(t, map[string]any{"session_key": "nope"}, nil)
	if _, err := o.client().AnonymLogin(context.Background(), "  "); !errors.Is(err, ErrCallTokenExpired) {
		t.Fatalf("empty token gave %v, want ErrCallTokenExpired", err)
	}
	if o.anonymSeen != nil {
		t.Errorf("okcdn was called for an empty token")
	}
}

func TestStartConversationReturnsAHoldableCall(t *testing.T) {
	o := newOKServer(t,
		map[string]any{"session_key": "SK", "uid": 42},
		map[string]any{"join_link": "ABChash", "token": "WSTOK", "id": "conv-1"})
	c := o.client()
	s, err := c.AnonymLogin(context.Background(), "$uumCALL")
	if err != nil {
		t.Fatal(err)
	}
	conv, err := c.StartConversation(context.Background(), s)
	if err != nil {
		t.Fatalf("startConversation: %v", err)
	}
	if conv.JoinLink != "ABChash" || conv.WSToken != "WSTOK" || conv.ConvID != "conv-1" {
		t.Fatalf("conversation = %+v", conv)
	}
	// The call is made as the VK Calls app with a join link.
	if o.startSeen.Get("session_key") != "SK" || o.startSeen.Get("createJoinLink") != "true" {
		t.Errorf("start query = %v", o.startSeen)
	}
	var pl map[string]any
	_ = json.Unmarshal([]byte(o.startSeen.Get("payload")), &pl)
	if pl["caller_app_id"].(float64) != float64(OKCallerAppID) {
		t.Errorf("caller_app_id = %v", pl["caller_app_id"])
	}
}

func TestStartConversationRejectsAHalfBuiltCall(t *testing.T) {
	o := newOKServer(t,
		map[string]any{"session_key": "SK", "uid": 42},
		map[string]any{"join_link": "ABChash", "error_msg": "no token here"}) // missing token+id
	c := o.client()
	s, _ := c.AnonymLogin(context.Background(), "$uumCALL")
	if _, err := c.StartConversation(context.Background(), s); err == nil {
		t.Fatal("a response missing the token or id should be an error")
	}
}

func TestOwnerWSURLCarriesTheConversationAndToken(t *testing.T) {
	u := OwnerWSURL("", &Conversation{JoinLink: "H", WSToken: "WSTOK", ConvID: "conv-9"}, "42")
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u, OKWSHost) {
		t.Errorf("url host = %q", u)
	}
	q := parsed.Query()
	if q.Get("token") != "WSTOK" || q.Get("conversationId") != "conv-9" || q.Get("userId") != "42" {
		t.Errorf("ws query = %v", q)
	}
	if q.Get("peerId") == "" {
		t.Errorf("peerId should be set")
	}
}

func TestRandomUUIDLooksLikeOne(t *testing.T) {
	u := randomUUID()
	if len(u) != 36 || strings.Count(u, "-") != 4 || u[14] != '4' {
		t.Fatalf("uuid = %q", u)
	}
}
