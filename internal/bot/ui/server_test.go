package ui

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/control"
)

// fakeTelegram records what the bot sends.
type fakeTelegram struct {
	mu   sync.Mutex
	sent []map[string]any
}

func (f *fakeTelegram) handler(w http.ResponseWriter, r *http.Request) {
	fields := map[string]any{"method": r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		if err := r.ParseMultipartForm(1 << 20); err == nil {
			for key, values := range r.MultipartForm.Value {
				fields[key] = values[0]
			}
		}
	} else {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &fields)
	}
	f.mu.Lock()
	f.sent = append(f.sent, fields)
	f.mu.Unlock()
	_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1,"chat":{"id":1},"date":0}}`))
}

func (f *fakeTelegram) last(t *testing.T) map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		t.Fatal("nothing was sent")
	}
	return f.sent[len(f.sent)-1]
}

type fakeControl struct {
	requests []control.Request
	commitOK bool
}

func (f *fakeControl) Do(_ context.Context, request control.Request) (control.Response, error) {
	f.requests = append(f.requests, request)
	switch request.Operation {
	case control.OpPrepare:
		result, _ := json.Marshal(map[string]any{
			"id": "0123456789abcdef0123456789abcdef",
			"plan": map[string]any{
				"mode":    "migrate",
				"changes": []map[string]any{{"path": "/deployment/ports/awg-in", "before": 10861, "after": 10870}},
				"actions": []map[string]any{{"mutates": true, "summary": "apply the configuration diff"}, {"mutates": false, "summary": "read only"}},
			},
		})
		return control.Response{OK: true, Result: result}, nil
	case control.OpCommit:
		if !f.commitOK {
			return control.Response{Error: "health wait failed"}, nil
		}
		result, _ := json.Marshal(map[string]string{"Transaction": "tx-9"})
		return control.Response{OK: true, Result: result}, nil
	}
	return control.Response{OK: true}, nil
}

func serverUI(t *testing.T) (*UI, *fakeTelegram, *fakeControl) {
	t.Helper()
	telegram := &fakeTelegram{}
	server := httptest.NewServer(http.HandlerFunc(telegram.handler))
	t.Cleanup(server.Close)
	client, err := bot.New("1:token", bot.WithServerURL(server.URL), bot.WithSkipGetMe())
	if err != nil {
		t.Fatal(err)
	}
	access, store := newAccess(t)
	if err := store.AddAdmin(1); err != nil {
		t.Fatal(err)
	}
	u := New(botcfg.ExampleConfig(), nil, access, store, quiet())
	u.Attach(client)
	ctl := &fakeControl{}
	u.SetControl(ctl)
	return u, telegram, ctl
}

func message(uid int64, text string) *models.Update {
	return &models.Update{Message: &models.Message{From: &models.User{ID: uid}, Text: text, Chat: models.Chat{ID: uid}}}
}

func callback(uid int64, data string) *models.CallbackQuery {
	return &models.CallbackQuery{ID: "q", From: models.User{ID: uid}, Data: data,
		Message: models.MaybeInaccessibleMessage{Message: &models.Message{ID: 1, Chat: models.Chat{ID: uid}}}}
}

func TestAPortCommandShowsThePlanAndChangesNothingUntilConfirmed(t *testing.T) {
	u, telegram, ctl := serverUI(t)
	u.onPort(context.Background(), nil, message(1, "/port awg-in 10870"))
	if len(ctl.requests) != 1 || ctl.requests[0].Operation != control.OpPrepare || ctl.requests[0].Change.Ports["awg-in"] != 10870 {
		t.Fatalf("requests = %#v", ctl.requests)
	}
	sent := telegram.last(t)
	text, _ := sent["text"].(string)
	markup, _ := json.Marshal(sent["reply_markup"])
	if !strings.Contains(text, "10861 -> 10870") || !strings.Contains(text, "apply the configuration diff") || strings.Contains(text, "read only") {
		t.Fatalf("plan text = %q", text)
	}
	if !strings.Contains(string(markup), cbConfirm+"0123456789abcdef0123456789abcdef") {
		t.Fatalf("no confirm button: %s", markup)
	}

	ctl.commitOK = true
	u.handleServer(context.Background(), callback(1, cbConfirm+"0123456789abcdef0123456789abcdef"), 1, cbConfirm+"0123456789abcdef0123456789abcdef")
	last := ctl.requests[len(ctl.requests)-1]
	if last.Operation != control.OpCommit || last.Ticket != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("commit request = %#v", last)
	}
	if text, _ := telegram.last(t)["text"].(string); !strings.Contains(text, "tx-9") {
		t.Fatalf("result text = %q", text)
	}
}

func TestServerCommandsAreAdminOnly(t *testing.T) {
	u, _, ctl := serverUI(t)
	u.onRotate(context.Background(), nil, message(99, "/rotate 42"))
	u.onImage(context.Background(), nil, message(99, "/image repo/core:2"))
	if len(ctl.requests) != 0 {
		t.Fatalf("a non-admin reached the daemon: %#v", ctl.requests)
	}
}

func TestMalformedServerCommandsNeverReachTheDaemon(t *testing.T) {
	u, _, ctl := serverUI(t)
	for _, text := range []string{"/port awg-in", "/port awg-in 0", "/port awg-in many", "/rotate", "/image"} {
		switch {
		case strings.HasPrefix(text, "/port"):
			u.onPort(context.Background(), nil, message(1, text))
		case strings.HasPrefix(text, "/rotate"):
			u.onRotate(context.Background(), nil, message(1, text))
		default:
			u.onImage(context.Background(), nil, message(1, text))
		}
	}
	if len(ctl.requests) != 0 {
		t.Fatalf("malformed commands reached the daemon: %#v", ctl.requests)
	}
}

func TestTheServerMenuIsAbsentWithoutADaemon(t *testing.T) {
	u, _, _ := serverUI(t)
	u.control = nil
	markup, _ := json.Marshal(u.mainMenu(1))
	if strings.Contains(string(markup), cbServer) {
		t.Fatal("the server menu is offered with no daemon to serve it")
	}
	u.SetControl(&fakeControl{})
	markup, _ = json.Marshal(u.mainMenu(1))
	if !strings.Contains(string(markup), cbServer) {
		t.Fatal("an admin is not offered the server menu")
	}
	if markup, _ = json.Marshal(u.mainMenu(2)); strings.Contains(string(markup), cbServer) {
		t.Fatal("a non-admin is offered the server menu")
	}
}
