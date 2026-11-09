package ui

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/go-telegram/bot/models"
)

// messagesTo lists the sendMessage calls addressed to one chat.
func (f *fakeTelegram) messagesTo(chat int64) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, m := range f.sent {
		if m["method"] != "sendMessage" {
			continue
		}
		if fmt.Sprint(m["chat_id"]) == fmt.Sprint(chat) {
			text, _ := m["text"].(string)
			out = append(out, text)
		}
	}
	return out
}

func (f *fakeTelegram) methods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, m := range f.sent {
		out = append(out, m["method"].(string))
	}
	return out
}

func TestAdminCommandsAreRefusedToEveryoneElseWithTheirOwnID(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	for name, handler := range map[string]func(context.Context, *models.Update){
		"allow":     func(c context.Context, up *models.Update) { u.onAllow(c, nil, up) },
		"deny":      func(c context.Context, up *models.Update) { u.onDeny(c, nil, up) },
		"whitelist": func(c context.Context, up *models.Update) { u.onWhitelist(c, nil, up) },
		"notify":    func(c context.Context, up *models.Update) { u.onNotify(c, nil, up) },
		"pushcfg":   func(c context.Context, up *models.Update) { u.onPushConfig(c, nil, up) },
		"vkhash":    func(c context.Context, up *models.Update) { u.onVKHash(c, nil, up) },
		"vkcode":    func(c context.Context, up *models.Update) { u.onVKCode(c, nil, up) },
		"reset":     func(c context.Context, up *models.Update) { u.onReset(c, nil, up) },
		"add":       func(c context.Context, up *models.Update) { u.onAdd(c, nil, up) },
		"del":       func(c context.Context, up *models.Update) { u.onDelete(c, nil, up) },
	} {
		handler(ctx, message(99, "/"+name+" 5 5"))
		got := telegram.messagesTo(99)
		if len(got) == 0 || !strings.Contains(got[len(got)-1], "99") {
			t.Errorf("/%s from a stranger: replies = %q (it must name their id so they can ask to be added)", name, got)
		}
	}
	admins, _ := u.store.Admins()
	if len(admins) != 1 || len(u.access.Whitelist()) != 0 {
		t.Errorf("a stranger changed access: admins=%v whitelist=%v", admins, u.access.Whitelist())
	}
	for _, m := range telegram.methods() {
		if m != "sendMessage" {
			t.Errorf("a refused command also did %s", m)
		}
	}
}

func TestAllowAndDenyChangeWhoIsApprovedAndTellTheTarget(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()

	u.onAllow(ctx, nil, message(1, "/allow 42"))
	if !u.access.IsAllowed(42) {
		t.Fatal("/allow did not approve")
	}
	if got := telegram.messagesTo(42); len(got) != 1 || got[0] != u.cfg.UI.AccessGranted {
		t.Errorf("the approved user was told %q", got)
	}
	if got := telegram.messagesTo(1); len(got) == 0 || !strings.Contains(got[len(got)-1], "42") {
		t.Errorf("the admin got no confirmation naming 42: %q", got)
	}

	u.onWhitelist(ctx, nil, message(1, "/whitelist"))
	if got := telegram.messagesTo(1); !strings.Contains(got[len(got)-1], "42") {
		t.Errorf("the whitelist view lacks 42: %q", got[len(got)-1])
	}

	u.onDeny(ctx, nil, message(1, "/deny 42"))
	if u.access.IsAllowed(42) {
		t.Fatal("/deny left the user approved")
	}
	if got := telegram.messagesTo(42); len(got) != 2 || got[1] != u.cfg.UI.AccessRevoked {
		t.Errorf("the revoked user was told %q", got)
	}
}

func TestHealthShowsTheMonitorToAdminsOnly(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()

	u.onHealth(ctx, nil, message(1, "/health"))
	if got := telegram.messagesTo(1); len(got) == 0 || got[len(got)-1] != u.label("unavailable") {
		t.Errorf("without a monitor /health should say it is unavailable: %q", got)
	}
	u.SetHealth(func() string { return "🩺 all good" })
	u.onHealth(ctx, nil, message(1, "/health"))
	if got := telegram.messagesTo(1); got[len(got)-1] != "🩺 all good" {
		t.Errorf("/health replied %q", got[len(got)-1])
	}
	u.onHealth(ctx, nil, message(99, "/health"))
	for _, m := range telegram.messagesTo(99) {
		if strings.Contains(m, "all good") {
			t.Error("a stranger saw the health page")
		}
	}
}

func TestAllowAndDenyRejectAMissingOrNonNumericID(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	for _, text := range []string{"/allow", "/allow @alice", "/deny", "/deny 4x2"} {
		before := len(telegram.messagesTo(1))
		if strings.HasPrefix(text, "/allow") {
			u.onAllow(ctx, nil, message(1, text))
		} else {
			u.onDeny(ctx, nil, message(1, text))
		}
		got := telegram.messagesTo(1)
		if len(got) != before+1 || got[len(got)-1] != u.label("usage_id") {
			t.Errorf("%q: the admin was not told the usage: %q", text, got)
		}
	}
	if len(u.access.Whitelist()) != 0 {
		t.Errorf("a malformed id changed the whitelist: %v", u.access.Whitelist())
	}
}

func TestNotifyReachesEveryApprovedUserAndAdminExactlyOnce(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	for _, id := range []int64{10, 11} {
		if err := u.access.Approve(id); err != nil {
			t.Fatal(err)
		}
	}
	u.onNotify(ctx, nil, message(1, "/notify Вышла версия 0.1.7.\nОбновитесь."))
	for _, chat := range []int64{10, 11, 1} {
		got := telegram.messagesTo(chat)
		if chat == 1 {
			// The admin is a recipient and also receives the summary.
			if len(got) != 2 || got[0] != "Вышла версия 0.1.7.\nОбновитесь." {
				t.Errorf("admin: %q", got)
			}
			continue
		}
		if len(got) != 1 || got[0] != "Вышла версия 0.1.7.\nОбновитесь." {
			t.Errorf("chat %d got %q, want the announcement once", chat, got)
		}
	}
	if err := u.access.Approve(1); err != nil { // the admin is also whitelisted
		t.Fatal(err)
	}
	if sent, failed := u.broadcast(ctx, "x"); sent != 3 || failed != 0 {
		t.Errorf("broadcast = %d sent, %d failed, want 3/0 (an admin who is also whitelisted counts once)", sent, failed)
	}

	// A bare /notify says how to use it and sends nothing to anyone else.
	before := len(telegram.messagesTo(10))
	u.onNotify(ctx, nil, message(1, "/notify   "))
	if len(telegram.messagesTo(10)) != before {
		t.Error("an empty /notify was broadcast")
	}
	if got := telegram.messagesTo(1); got[len(got)-1] != u.label("usage_notify") {
		t.Errorf("usage = %q", got[len(got)-1])
	}
}

func TestAccessRequestFlowThroughStartAndTheAdminsButtons(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()

	// A stranger's /start records a request and asks the admin, rather than greeting.
	u.onStart(ctx, nil, message(77, "/start"))
	if u.access.IsAllowed(77) {
		t.Fatal("/start approved a stranger")
	}
	if len(u.access.Pending()) != 1 {
		t.Fatalf("pending = %v", u.access.Pending())
	}
	if got := telegram.messagesTo(77); len(got) != 1 || !strings.Contains(got[0], "77") {
		t.Errorf("the requester was told %q", got)
	}
	if got := telegram.messagesTo(1); len(got) != 1 || !strings.Contains(got[0], "77") {
		t.Errorf("the admin was told %q", got)
	}

	// A non-admin pressing the admin's decision button does nothing: the
	// keyboard is not the authority.
	u.onCallback(ctx, u.client, &models.Update{CallbackQuery: callback(77, cbWL+"add:77")})
	if u.access.IsAllowed(77) {
		t.Fatal("a requester approved themselves by calling the admin button")
	}

	u.onCallback(ctx, u.client, &models.Update{CallbackQuery: callback(1, cbWL+"add:77")})
	if !u.access.IsAllowed(77) {
		t.Fatal("the admin's approve button did not approve")
	}
	if got := telegram.messagesTo(77); got[len(got)-1] != u.cfg.UI.AccessGranted {
		t.Errorf("approved user was told %q", got[len(got)-1])
	}

	u.onCallback(ctx, u.client, &models.Update{CallbackQuery: callback(1, cbWL+"del:77")})
	if u.access.IsAllowed(77) {
		t.Fatal("revoke did not revoke")
	}

	u.access.RequestAccess(78)
	u.onCallback(ctx, u.client, &models.Update{CallbackQuery: callback(1, cbWL+"no:78")})
	if len(u.access.Pending()) != 0 || u.access.IsAllowed(78) {
		t.Errorf("reject: pending=%v allowed=%v", u.access.Pending(), u.access.IsAllowed(78))
	}
}

func TestCallbacksNeedApprovalAndMalformedOnesAreHarmless(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()

	// Self-service buttons for someone not approved turn into an access request.
	for _, data := range []string{cbGetConfig, cbMyStats, cbAllMethods, cbAPK, cbWebLink, cbPick + "x:y", cbGen + "x:y"} {
		if !needsApproval(data) {
			t.Errorf("%q does not require approval", data)
		}
	}
	for _, data := range []string{cbMenu, cbNoop, cbUsers, cbAccess, cbWL + "add:1"} {
		if needsApproval(data) {
			t.Errorf("%q requires approval, but is gated another way", data)
		}
	}
	u.onCallback(ctx, u.client, &models.Update{CallbackQuery: callback(55, cbMyStats)})
	if len(u.access.Pending()) != 1 {
		t.Fatalf("an unapproved self-service press was not turned into a request: %v", u.access.Pending())
	}

	// Admin-only buttons pressed by a non-admin fall through to "unavailable".
	n := len(telegram.sent)
	u.onCallback(ctx, u.client, &models.Update{CallbackQuery: callback(55, cbUsers)})
	if len(telegram.sent) <= n {
		t.Error("an admin button pressed by a non-admin got no answer")
	}
	// Malformed decision data neither panics nor changes access.
	for _, data := range []string{cbWL, cbWL + "add", cbWL + "add:abc", cbWL + "bogus:5"} {
		u.onCallback(ctx, u.client, &models.Update{CallbackQuery: callback(1, data)})
	}
	if u.access.IsAllowed(5) {
		t.Error("malformed callback data approved someone")
	}
	// Nothing to do for a disabled button or a callback with no message.
	u.onCallback(ctx, u.client, &models.Update{CallbackQuery: callback(1, cbNoop)})
	u.onCallback(ctx, u.client, &models.Update{CallbackQuery: &models.CallbackQuery{ID: "q", From: models.User{ID: 1}, Data: cbMenu}})
	u.onUpdate(ctx, u.client, &models.Update{})
	u.onUpdate(ctx, u.client, message(1, "free text is ignored"))
}

func TestSplitCallbackAndParseID(t *testing.T) {
	for in, want := range map[string][3]any{
		"pick:vless:reality-in": {"vless", "reality-in", true},
		"pick:vless":            {"", "", false},
		"pick::tag":             {"", "", false},
		"pick:":                 {"", "", false},
	} {
		kind, tag, ok := splitCallback(in, "pick:")
		// The parts are only meaningful when ok: callers never read them otherwise.
		if ok != want[2] || (ok && (kind != want[0] || tag != want[1])) {
			t.Errorf("splitCallback(%q) = %q %q %v", in, kind, tag, ok)
		}
	}
	if id, err := parseID(" 42 "); err != nil || id != 42 {
		t.Errorf("parseID: %d %v", id, err)
	}
	for _, bad := range []string{"", "x", "1.5", "99999999999999999999"} {
		if _, err := parseID(bad); err == nil {
			t.Errorf("parseID(%q) accepted", bad)
		}
	}
}
