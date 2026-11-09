package ui

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/spaiter/spaiter-vpn/internal/bot/servicetest"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

// svcUI is a UI over a real service.Service and a fake core: the same code a
// deployment runs, with only the core and Telegram replaced. User 1 is the
// admin; user 5 is approved.
func svcUI(t *testing.T) (*UI, *fakeTelegram, *servicetest.Fixture) {
	t.Helper()
	return svcUIWith(t, servicetest.New(t))
}

func svcUIWith(t *testing.T, fx *servicetest.Fixture) (*UI, *fakeTelegram, *servicetest.Fixture) {
	t.Helper()
	telegram := &fakeTelegram{}
	server := httptest.NewServer(http.HandlerFunc(telegram.handler))
	t.Cleanup(server.Close)
	client, err := bot.New("1:token", bot.WithServerURL(server.URL), bot.WithSkipGetMe())
	if err != nil {
		t.Fatal(err)
	}
	cfg := fx.Config
	cfg.Subscription.HostCF = "cf.example.org"
	cfg.Subscription.HostDirect = "direct.example.org:8080"
	access := NewAccess(fx.Store, quiet())
	if err := fx.Store.AddAdmin(1); err != nil {
		t.Fatal(err)
	}
	if err := access.Approve(5); err != nil {
		t.Fatal(err)
	}
	u := New(cfg, fx.Service, access, fx.Store, quiet())
	u.Attach(client)
	return u, telegram, fx
}

func press(u *UI, uid int64, data string) {
	u.onCallback(context.Background(), u.client, &models.Update{CallbackQuery: callback(uid, data)})
}

func lastText(t *testing.T, f *fakeTelegram) string {
	t.Helper()
	text, _ := f.last(t)["text"].(string)
	return text
}

func TestAddCreatesTheAccountAndSendsTheLinkProtected(t *testing.T) {
	u, telegram, fx := svcUI(t)
	ctx := context.Background()

	u.onAdd(ctx, nil, message(1, "/add vless-reality-in alice"))
	adds, _, _ := fx.API.Counts()
	if adds != 1 {
		t.Fatalf("adds = %d", adds)
	}
	var link map[string]any
	for _, m := range telegram.sent {
		if m["method"] == "sendMessage" && strings.Contains(fmt.Sprint(m["text"]), "vless://") {
			link = m
		}
	}
	if link == nil {
		t.Fatalf("no message carries the link: %v", telegram.methods())
	}
	// A link is a credential: it must not be forwardable.
	if fmt.Sprint(link["protect_content"]) != "true" {
		t.Errorf("the link message is not protected: %v", link["protect_content"])
	}

	// Usage, and an unknown protocol, never create anything.
	u.onAdd(ctx, nil, message(1, "/add vless-reality-in"))
	if got := telegram.messagesTo(1); got[len(got)-1] != u.label("usage_add") {
		t.Errorf("usage: %q", got[len(got)-1])
	}
	u.onAdd(ctx, nil, message(1, "/add no-such-in bob"))
	if adds2, _, _ := fx.API.Counts(); adds2 != 1 {
		t.Errorf("an unknown protocol created an account")
	}
	if got := telegram.messagesTo(1); !strings.Contains(got[len(got)-1], "no-such-in") && !strings.Contains(got[len(got)-1], "rror") {
		t.Errorf("the failure is not reported: %q", got[len(got)-1])
	}
}

func TestDeleteAndResetReportTheirOutcome(t *testing.T) {
	u, telegram, fx := svcUI(t)
	ctx := context.Background()
	u.onAdd(ctx, nil, message(1, "/add vless-reality-in alice"))
	fx.API.SetStats(manage.UserStat{User: "alice", Upload: 10, Download: 20})

	u.onDelete(ctx, nil, message(1, "/del"))
	if got := telegram.messagesTo(1); got[len(got)-1] != u.label("usage_del") {
		t.Errorf("del usage: %q", got[len(got)-1])
	}
	u.onDelete(ctx, nil, message(1, "/del vless-reality-in alice"))
	if _, _, deletes := fx.API.Counts(); deletes != 1 {
		t.Errorf("deletes = %d", deletes)
	}
	if got := telegram.messagesTo(1); !strings.Contains(got[len(got)-1], "alice") {
		t.Errorf("del confirmation: %q", got[len(got)-1])
	}
	// Deleting what is not there is an error shown to the admin, not a success.
	before := len(telegram.messagesTo(1))
	u.onDelete(ctx, nil, message(1, "/del vless-reality-in alice"))
	if got := telegram.messagesTo(1); len(got) != before+1 || got[len(got)-1] == u.text("deleted", "alice", "vless-reality-in") {
		t.Errorf("a repeated delete claimed success: %q", got[len(got)-1])
	}

	u.onReset(ctx, nil, message(1, "/reset"))
	if got := telegram.messagesTo(1); got[len(got)-1] != u.label("usage_reset") {
		t.Errorf("reset usage: %q", got[len(got)-1])
	}
	u.onReset(ctx, nil, message(1, "/reset alice"))
	if got := telegram.messagesTo(1); got[len(got)-1] != u.text("reset", "alice") {
		t.Errorf("reset: %q", got[len(got)-1])
	}
	u.onReset(ctx, nil, message(1, "/reset nobody"))
	if got := telegram.messagesTo(1); got[len(got)-1] == u.text("reset", "nobody") {
		t.Errorf("resetting an unknown user claimed success")
	}
}

func TestMethodMenuIsBuiltFromTheLiveCore(t *testing.T) {
	u, telegram, fx := svcUI(t)
	press(u, 5, cbGetConfig)
	markup := fmt.Sprint(telegram.last(t)["reply_markup"])
	for _, tag := range []string{"vless-reality-in", "hysteria-in", "awg-in", "awg3-in"} {
		if !strings.Contains(markup, tag) {
			t.Errorf("%s missing from the menu: %s", tag, markup)
		}
	}
	// The internal front-ends are never offered as a profile.
	for _, hidden := range []string{"wg-masque-in", "wg-wdtt-in"} {
		if strings.Contains(markup, hidden) {
			t.Errorf("%s offered", hidden)
		}
	}
	if !strings.Contains(markup, cbPick+kindWARP) || !strings.Contains(markup, cbPick+kindWDTT) {
		t.Errorf("the chain methods are not appended: %s", markup)
	}
	_ = fx
}

func TestEveryMethodIsDeliveredAsTheClientCanRead(t *testing.T) {
	u, telegram, fx := svcUI(t)

	press(u, 5, cbGen+kindInbound+":vless-reality-in")
	methods := strings.Join(telegram.methods(), " ")
	if !strings.Contains(methods, "sendPhoto") {
		t.Errorf("no QR for a link method: %s", methods)
	}
	if adds, _, _ := fx.API.Counts(); adds != 1 {
		t.Errorf("the account was not minted: %d", adds)
	}
	// The QR encodes the credential: it must not be forwardable.
	for _, m := range telegram.sent {
		if m["method"] == "sendPhoto" && fmt.Sprint(m["protect_content"]) != "true" {
			t.Errorf("a QR of a credential was sent unprotected: %v", m)
		}
	}
	if !strings.Contains(lastText(t, telegram), u.text("ready", "", u.clientApps("vless-reality-in"))[:10]) {
		t.Errorf("the delivery is not closed with the ready text: %q", lastText(t, telegram))
	}

	// AmneziaWG: a QR of the profile and a short-named .conf for the importer.
	before := len(telegram.sent)
	press(u, 5, cbGen+kindEndpoint+":awg-in")
	var doc map[string]any
	for _, m := range telegram.sent[before:] {
		if m["method"] == "sendDocument" {
			doc = m
		}
	}
	if doc == nil {
		t.Fatalf("no .conf document: %v", telegram.methods())
	}

	press(u, 5, cbGen+kindWARP+":warp")
	if fx.Registrar.Calls() != 1 {
		t.Errorf("WARP registrations = %d", fx.Registrar.Calls())
	}
	press(u, 5, cbGen+kindWDTT+":wdtt")

	// A method the core does not have is reported to the person who pressed it.
	press(u, 5, cbGen+kindInbound+":no-such-in")
	if text := lastText(t, telegram); !strings.Contains(text, "no-such-in") && !strings.Contains(text, "rror") {
		t.Errorf("failure not reported: %q", text)
	}
}

func TestSubscriptionIsCachedAndAnnouncedOnce(t *testing.T) {
	u, telegram, fx := svcUI(t)
	press(u, 5, cbAllMethods)

	token, err := fx.Store.SubscriptionToken("5")
	if err != nil {
		t.Fatal(err)
	}
	cached, found, err := fx.Store.BundleCache(token)
	if err != nil || !found || countNodes(cached) == 0 {
		t.Fatalf("the bundle was not cached for first use (an empty cache is a 404): found=%v err=%v", found, err)
	}
	cf, direct := u.SubscriptionURLs(token)
	if cf != "https://cf.example.org/sub/"+token || direct != "http://direct.example.org:8080/sub/"+token {
		t.Errorf("urls: %q %q", cf, direct)
	}
	sent := telegram.last(t)
	text := fmt.Sprint(sent["text"])
	if !strings.Contains(text, cf) || !strings.Contains(text, direct) || fmt.Sprint(sent["protect_content"]) != "true" {
		t.Errorf("the subscription message: protect=%v\n%s", sent["protect_content"], text)
	}
	// The hash is adopted with the delivery, so the next refresh announces nothing.
	subs, _ := fx.Store.Subscriptions()
	if subs[token].LastHash == "" {
		t.Error("the structural hash was not recorded")
	}

	// Without a configured host that route is simply absent.
	u.cfg.Subscription.HostCF, u.cfg.Subscription.HostDirect = "", ""
	if cf, direct := u.SubscriptionURLs(token); cf != "" || direct != "" {
		t.Errorf("urls without hosts: %q %q", cf, direct)
	}
}

func TestStatsViewsForUserAndAdmin(t *testing.T) {
	u, telegram, fx := svcUI(t)

	press(u, 5, cbMyStats)
	if lastText(t, telegram) != u.text("no_stats") {
		t.Errorf("a user who never connected: %q", lastText(t, telegram))
	}
	fx.API.SetStats(
		manage.UserStat{User: "5", Upload: 2048, Download: 5 << 20, ConnCount: 7},
		manage.UserStat{User: "laptop", Upload: 1, Download: 9 << 30, Active: 1},
	)
	press(u, 5, cbMyStats)
	if got := lastText(t, telegram); !strings.Contains(got, "2.0KB") || !strings.Contains(got, "5.0MB") || !strings.Contains(got, "7") {
		t.Errorf("my stats: %q", got)
	}

	press(u, 1, cbAllStats)
	got := lastText(t, telegram)
	if !strings.Contains(got, "`5`") || !strings.Contains(got, "`laptop`") || !strings.Contains(got, "Σ") || !strings.Contains(got, "9.0GB") {
		t.Errorf("totals: %q", got)
	}
	// Non-admins cannot reach the admin views by knowing the callback data.
	before := len(telegram.sent)
	press(u, 5, cbAllStats)
	if lastText(t, telegram) == got || len(telegram.sent) == before {
		t.Errorf("a user was shown the admin totals or got no answer")
	}

	// Who holds a configuration: from the inbounds, busiest first.
	press(u, 1, cbUsers)
	if lastText(t, telegram) != u.label("no_users") {
		t.Errorf("nobody provisioned yet: %q", lastText(t, telegram))
	}
	u.onAdd(context.Background(), nil, message(1, "/add vless-reality-in laptop"))
	u.onAdd(context.Background(), nil, message(1, "/add vless-reality-in 5"))
	press(u, 1, cbUsers)
	list := lastText(t, telegram)
	if strings.Index(list, "`laptop`") < 0 || strings.Index(list, "`5`") < 0 || strings.Index(list, "`laptop`") > strings.Index(list, "`5`") {
		t.Errorf("the busiest account is not first:\n%s", list)
	}
	if !strings.Contains(list, "🟢") || !strings.Contains(list, "⚪️") {
		t.Errorf("active/idle markers:\n%s", list)
	}
}
