package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-telegram/bot"

	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// sentMessage is one request the library made, decoded.
type sentMessage struct {
	ChatID    json.Number `json:"chat_id"`
	Text      string      `json:"text"`
	ParseMode string      `json:"parse_mode"`
}

// fakeTelegram is a Telegram API the library talks to over HTTP, so the
// request the library actually builds is what gets asserted -- not a mock of
// the call this package makes to it.
type fakeTelegram struct {
	mu   sync.Mutex
	sent []sentMessage
	// fail, when set, is returned as an API error for the given chat id.
	fail map[string]string
}

func newFakeTelegram(t *testing.T) (*fakeTelegram, *bot.Bot) {
	t.Helper()
	fake := &fakeTelegram{fail: map[string]string{}}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)

	// SkipGetMe because there is no account here, and the server URL points the
	// library at the fake.
	client, err := bot.New("test:token",
		bot.WithServerURL(server.URL), bot.WithSkipGetMe())
	if err != nil {
		t.Fatalf("bot.New: %v", err)
	}
	return fake, client
}

func (f *fakeTelegram) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	message, err := decodeRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if description, bad := f.fail[message.ChatID.String()]; bad {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": false, "error_code": 403, "description": description,
		})
		return
	}
	f.sent = append(f.sent, message)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "result": map[string]any{"message_id": len(f.sent)},
	})
}

// decodeRequest reads the request the library built, which is multipart form
// data rather than JSON -- the same encoding it uses for uploads.
func decodeRequest(r *http.Request) (sentMessage, error) {
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		var message sentMessage
		return message, json.NewDecoder(r.Body).Decode(&message)
	}
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		return sentMessage{}, err
	}
	return sentMessage{
		ChatID:    json.Number(r.FormValue("chat_id")),
		Text:      r.FormValue("text"),
		ParseMode: r.FormValue("parse_mode"),
	}, nil
}

func (f *fakeTelegram) messages() []sentMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentMessage{}, f.sent...)
}

func newStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	return store
}

func TestNotifyReachesTheUser(t *testing.T) {
	fake, client := newFakeTelegram(t)
	n := NewNotifier(client, newStore(t), quiet())

	if err := n.Notify(context.Background(), "4242", "конфигурация обновилась"); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	sent := fake.messages()
	if len(sent) != 1 {
		t.Fatalf("messages = %d", len(sent))
	}
	if sent[0].ChatID.String() != "4242" {
		t.Errorf("chat id = %s", sent[0].ChatID)
	}
	if sent[0].Text != "конфигурация обновилась" {
		t.Errorf("text = %q", sent[0].Text)
	}
	// Legacy Markdown, not V2. The library's ParseModeMarkdown constant is V2,
	// which reserves '.', '-', '!' and '(' -- characters the configured texts
	// are full of -- and Telegram rejects a message with any of them unescaped.
	if sent[0].ParseMode != "Markdown" {
		t.Errorf("parse mode = %q", sent[0].ParseMode)
	}
}

// TestNotifyRejectsSomethingThatIsNotAChatID: the state files key users by
// their Telegram id as a string, and a malformed key would otherwise be sent to
// the API as a username and reach somebody else's chat.
func TestNotifyRejectsSomethingThatIsNotAChatID(t *testing.T) {
	fake, client := newFakeTelegram(t)
	n := NewNotifier(client, newStore(t), quiet())

	err := n.Notify(context.Background(), "@someone", "hello")
	if err == nil {
		t.Fatal("a non-numeric id was accepted")
	}
	if len(fake.messages()) != 0 {
		t.Error("it was sent anyway")
	}
}

func TestNotifyAdminsReachesEveryone(t *testing.T) {
	fake, client := newFakeTelegram(t)
	store := newStore(t)
	for _, id := range []int64{1, 2, 3} {
		if err := store.AddAdmin(id); err != nil {
			t.Fatalf("AddAdmin: %v", err)
		}
	}
	n := NewNotifier(client, store, quiet())

	if err := n.NotifyAdmins(context.Background(), "пул почти пуст"); err != nil {
		t.Fatalf("NotifyAdmins: %v", err)
	}
	if got := len(fake.messages()); got != 3 {
		t.Errorf("messages = %d, want one per admin", got)
	}
}

// TestNotifyAdminsKeepsGoingPastAFailure: what comes through here is the pool
// emptying or a path breaking, and one admin who blocked the bot must not stop
// the others from hearing it.
func TestNotifyAdminsKeepsGoingPastAFailure(t *testing.T) {
	fake, client := newFakeTelegram(t)
	store := newStore(t)
	for _, id := range []int64{1, 2, 3} {
		if err := store.AddAdmin(id); err != nil {
			t.Fatalf("AddAdmin: %v", err)
		}
	}
	fake.fail["2"] = "Forbidden: bot was blocked by the user"
	n := NewNotifier(client, store, quiet())

	err := n.NotifyAdmins(context.Background(), "пул почти пуст")
	if err == nil {
		t.Fatal("the failure was swallowed")
	}
	// Reported, and the other two still got it.
	if !strings.Contains(err.Error(), "admin 2") {
		t.Errorf("error should name the admin: %v", err)
	}
	if got := len(fake.messages()); got != 2 {
		t.Errorf("messages = %d, want the other two delivered", got)
	}
	// And it is recognisably permanent, so a caller that retries can stop.
	if !Unreachable(err) {
		t.Error("a blocked chat was not recognised as unreachable")
	}
}

func TestNoAdminsIsNotAnError(t *testing.T) {
	// An empty list means the alarms have nowhere to go, which is logged. It is
	// not a failure to report upward: the caller is a background loop that
	// would log the same thing again.
	_, client := newFakeTelegram(t)
	n := NewNotifier(client, newStore(t), quiet())
	if err := n.NotifyAdmins(context.Background(), "hello"); err != nil {
		t.Errorf("NotifyAdmins with no admins: %v", err)
	}
}

func TestUnreachableTellsPermanentFromTransient(t *testing.T) {
	permanent := []string{
		"Forbidden: bot was blocked by the user",
		"Forbidden: user is deactivated",
		"Bad Request: chat not found",
		"Forbidden: bot was kicked from the group chat",
	}
	for _, description := range permanent {
		if !Unreachable(errors.New(description)) {
			t.Errorf("%q should be permanent", description)
		}
	}
	transient := []string{
		"Too Many Requests: retry after 30",
		"Bad Gateway",
		"context deadline exceeded",
		"",
	}
	for _, description := range transient {
		if Unreachable(errors.New(description)) {
			t.Errorf("%q should not be permanent: retrying it is right", description)
		}
	}
	if Unreachable(nil) {
		t.Error("nil is not an unreachable chat")
	}
}
