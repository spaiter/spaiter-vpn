package ui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

func TestBundleHelpers(t *testing.T) {
	if countNodes([]byte(`{"outbounds":[{"tag":"a"},{"tag":"b"}]}`)) != 2 || countNodes([]byte("x")) != 0 || countNodes(nil) != 0 {
		t.Error("countNodes")
	}
	a, err := structuralHash([]byte(`{"outbounds":[{"tag":"a","port":1}]}`))
	if err != nil || a == "" {
		t.Fatalf("hash: %q %v", a, err)
	}
	b, _ := structuralHash([]byte(`{"outbounds":[{"port":1,"tag":"a"}]}`))
	c, _ := structuralHash([]byte(`{"outbounds":[{"tag":"a","port":2}]}`))
	if a != b || a == c {
		t.Errorf("the hash must ignore key order and see a changed port: %q %q %q", a, b, c)
	}
	if _, err := structuralHash([]byte("{")); err == nil {
		t.Error("garbage hashed")
	}
	for n, want := range map[int64]string{0: "0.0B", 1023: "1023.0B", 1024: "1.0KB", 5 << 20: "5.0MB", 3 << 30: "3.0GB", 2 << 40: "2.0TB"} {
		if human(n) != want {
			t.Errorf("human(%d) = %q, want %q", n, human(n), want)
		}
	}
	// Tunnel names are capped at 15 characters by the clients.
	if got := shortProfileName("1234567890123"); got != "amnezia-0123" || len(got) > 15 {
		t.Errorf("shortProfileName = %q", got)
	}
	if shortProfileName("ab") != "amnezia-ab" {
		t.Error("short uid")
	}
}

func TestQueryChatPrefersTheMessageChat(t *testing.T) {
	q := callback(5, "x")
	q.Message.Message.Chat.ID = 99
	if queryChat(q) != 99 {
		t.Error("the chat of the message the button is on")
	}
	q = &models.CallbackQuery{From: models.User{ID: 5}}
	if queryChat(q) != 5 {
		t.Error("with no message, the presser's own chat")
	}
}

func TestLabelsFallBackFromTagToProtocolToRaw(t *testing.T) {
	u, _, _ := serverUI(t)
	u.cfg.UI.TagLabel = map[string]string{"t1": "Tag one"}
	u.cfg.UI.ProtoLabel = map[string]string{"vless": "VLESS"}
	if u.tagLabel("t1", "vless") != "Tag one" || u.tagLabel("t2", "vless") != "VLESS" || u.tagLabel("t3", "raw") != "raw" {
		t.Error("tagLabel fallbacks")
	}
	u.cfg.UI.ClientHint = map[string]string{"vless": "Hiddify", "t1": "Special"}
	if got := u.pickText("vless", "t1"); !strings.Contains(got, "Special") || !strings.Contains(got, "Tag one") {
		t.Errorf("per-tag hint wins: %q", got)
	}
	if got := u.pickText("vless", "t2"); !strings.Contains(got, "Hiddify") {
		t.Errorf("per-kind hint: %q", got)
	}
	if got := u.pickText("other", "t3"); !strings.Contains(got, u.label("default_client")) {
		t.Errorf("default client: %q", got)
	}
	// A message nobody configured shows its key, not an empty bubble.
	if got := u.text("no_such_message", 1); !strings.Contains(got, "no_such_message") {
		t.Errorf("unconfigured text: %q", got)
	}
}

func TestDisplayNameOfOnlyNamesTelegramAccounts(t *testing.T) {
	u, _, _ := serverUI(t)
	u.access.Register(state.User{ID: 77, Username: "alice"})
	if !strings.Contains(u.displayNameOf("77"), "alice") {
		t.Errorf("%q", u.displayNameOf("77"))
	}
	// An account added by hand has nobody behind it.
	if u.displayNameOf("laptop") != "" {
		t.Error("a hand-made account was given a person's name")
	}
}

func TestOptionsRegisterEveryAdminCommandExactlyOnce(t *testing.T) {
	u, _, _ := serverUI(t)
	// bot.New applies the options; a duplicate or missing handler would show
	// as a command that does nothing, which the menu test cannot see.
	options := u.Options()
	if len(options) < len(adminCommands) {
		t.Errorf("%d options for %d admin commands", len(options), len(adminCommands))
	}
	if _, err := bot.New("1:token", append(options, bot.WithSkipGetMe())...); err != nil {
		t.Fatal(err)
	}
}

func TestCourtesyNoticesAndWebLinks(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()

	u.Tell(ctx, 9, "")
	if len(telegram.sent) != 0 {
		t.Error("an empty notice was sent")
	}
	u.Tell(ctx, 9, "access granted")
	if got := telegram.messagesTo(9); len(got) != 1 || got[0] != "access granted" {
		t.Errorf("Tell: %q", got)
	}
	u.NotifyAccessRequest(ctx, 9)
	if got := telegram.messagesTo(1); len(got) != 1 || !strings.Contains(got[0], "9") {
		t.Errorf("admins were not asked: %q", got)
	}

	// No Mini App minter: the button says unavailable.
	u.deliverWebLink(ctx, callback(5, cbWebLink), 5)
	if text, _ := telegram.last(t)["text"].(string); text != u.label("unavailable") {
		t.Errorf("no minter: %q", text)
	}
	var minted int64
	u.SetWebAppLogin(func(uid int64) (string, error) { minted = uid; return "https://app.example/?t=ONE", nil })
	u.deliverWebLink(ctx, callback(5, cbWebLink), 5)
	sent := telegram.last(t)
	if minted != 5 || fmt.Sprint(sent["protect_content"]) != "true" {
		t.Errorf("minted for %d, protect_content=%v: a login link must not be forwardable", minted, sent["protect_content"])
	}
	u.SetWebAppLogin(func(int64) (string, error) { return "", errors.New("mint failed") })
	u.deliverWebLink(ctx, callback(5, cbWebLink), 5)
	if text, _ := telegram.last(t)["text"].(string); !strings.Contains(text, "mint failed") {
		t.Errorf("mint failure: %q", text)
	}
}

func TestAnnounceAndHelpWithAClient(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	u.Announce(ctx)
	seen := strings.Join(telegram.methods(), " ")
	if !strings.Contains(seen, "setMyCommands") {
		t.Errorf("the command menu was not published: %s", seen)
	}
	// A stranger's /help is the same path as /start: a request, not a manual.
	u.onHelp(ctx, u.client, message(88, "/help"))
	if len(u.access.Pending()) != 1 {
		t.Errorf("pending = %v", u.access.Pending())
	}
	// An approved user gets the rich help page.
	u.access.Approve(5)
	u.onHelp(ctx, u.client, message(5, "/help"))
	if !strings.Contains(strings.Join(telegram.methods(), " "), "sendRichMessage") {
		t.Errorf("no rich help: %v", telegram.methods())
	}
	u.onHelp(ctx, u.client, &models.Update{})
}
