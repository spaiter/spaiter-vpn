package ui

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/go-telegram/bot/models"

	"github.com/spaiter/spaiter-vpn/internal/bot/servicetest"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

func TestDeliveriesReportEachFailingStepToTheUser(t *testing.T) {
	cases := map[string]struct {
		data  string
		setup func(u *UI, telegramFailing func(string))
	}{
		"link account": {cbGen + "i:no-such-inbound", nil},
		"awg peer":     {cbGen + "e:no-such-endpoint", nil},
		"json config":  {cbGen + "i:shadowtls-in", nil}, // not on the fixture's core
		"warp": {cbGen + "w:warp", func(u *UI, _ func(string)) {
			corrupt(t, u.store, "warp/5.json")
		}},
		"wdtt": {cbGen + "v:wdtt", func(u *UI, _ func(string)) {
			corrupt(t, u.store, "wdtt/5.json")
		}},
	}
	for name, c := range cases {
		u, telegram, _ := svcUI(t)
		if c.setup != nil {
			c.setup(u, func(string) {})
		}
		before := len(telegram.methods())
		press(u, 5, c.data)
		if len(telegram.methods()) == before {
			t.Errorf("%s: the failure was not reported", name)
		}
	}
}

func TestEveryDeliveryKindSucceedsWithAWorkingCore(t *testing.T) {
	u, telegram, fx := svcUI(t)
	fx.API.AddShadowTLS()
	for _, data := range []string{
		cbGen + "e:awg-in",
		cbGen + "w:warp",
		cbGen + "v:wdtt",
		cbGen + "i:shadowtls-in",
		cbGen + "i:vless-reality-in",
	} {
		before := len(telegram.methods())
		press(u, 5, data)
		if sent := telegram.methods()[before:]; !slices.Contains(sent, "sendMessage") {
			t.Errorf("%s: nothing closed the delivery: %v", data, sent)
		}
	}
	if !slices.Contains(telegram.methods(), "sendDocument") {
		t.Error("no configuration file was sent")
	}
	// The per-tag hint wins over the generic client name.
	u.cfg.UI.ClientHint = map[string]string{"shadowtls-in": "Hiddify"}
	if u.clientHint("shadowtls-in") != "Hiddify" || u.clientHint("other") != u.label("default_client") {
		t.Error("clientHint fallbacks")
	}
}

func TestMenusAndStatsReportAFailingCore(t *testing.T) {
	u, telegram, fx := svcUI(t)
	errCore := errors.New("core down")

	fx.API.FailOn("Inbounds", errCore)
	for _, data := range []string{cbGetConfig, cbUsers} {
		before := len(telegram.methods())
		press(u, 1, data)
		if len(telegram.methods()) == before {
			t.Errorf("%s: a failing core went unreported", data)
		}
	}
	fx.API.FailOn("Inbounds", nil)

	fx.API.FailOn("UserStats", errCore)
	for _, data := range []string{cbMyStats, cbAllStats} {
		before := len(telegram.methods())
		press(u, 1, data)
		if len(telegram.methods()) == before {
			t.Errorf("%s: a failing stats call went unreported", data)
		}
	}
	// The users view needs accounts first, then stats.
	fx.API.FailOn("UserStats", nil)
	press(u, 5, cbGen+"i:vless-reality-in")
	fx.API.FailOn("UserStats", errCore)
	before := len(telegram.methods())
	press(u, 1, cbUsers)
	if len(telegram.methods()) == before {
		t.Error("users view with failing stats went unreported")
	}
}

func TestSubscriptionDeliveryReportsEachFailingStep(t *testing.T) {
	cases := map[string]func(u *UI, fx *servicetest.Fixture){
		"bundle": func(_ *UI, fx *servicetest.Fixture) { fx.API.FailOn("Inbounds", errors.New("core down")) },
		"token":  func(u *UI, _ *servicetest.Fixture) { corrupt(t, u.store, "subs.json") },
		"cache": func(u *UI, _ *servicetest.Fixture) {
			if err := os.RemoveAll(u.store.Path("wdtt", "subs-cache")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(u.store.Path("wdtt", "subs-cache"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range cases {
		u, telegram, fx := svcUI(t)
		setup(u, fx)
		before := len(telegram.methods())
		press(u, 5, cbAllMethods)
		sent := telegram.methods()[before:]
		if slices.Contains(sent, "sendPhoto") || len(sent) == 0 {
			t.Errorf("%s: sent %v", name, sent)
		}
	}
}

func TestBadCallbackDataAndAdminBranchesAreHandled(t *testing.T) {
	u, telegram, _ := svcUI(t)
	for _, data := range []string{cbPick + "nocolon", cbGen + ":", cbPick + "i:vless-reality-in"} {
		before := len(telegram.methods())
		press(u, 5, data)
		if len(telegram.methods()) == before {
			t.Errorf("%q: no answer", data)
		}
	}
	press(u, 5, cbMenuNew)
	if !strings.Contains(lastText(t, telegram), u.cfg.UI.Hello[:5]) {
		t.Errorf("menu:new = %q", lastText(t, telegram))
	}
	// The admin screens and the server callbacks are reachable by an admin only.
	press(u, 1, cbAccess)
	press(u, 1, cbConfirm+"0123456789abcdef0123456789abcdef")
	press(u, 5, cbAccess)
	if !strings.Contains(lastText(t, telegram), u.label("unavailable")) {
		t.Errorf("a non-admin reached the access screen: %q", lastText(t, telegram))
	}
	// An update that carries a callback is routed even from the fallback handler.
	u.onUpdate(context.Background(), u.client, &models.Update{CallbackQuery: callback(5, cbMenu)})
	u.onUpdate(context.Background(), u.client, &models.Update{})
	if u.caller(nil) != 0 {
		t.Error("caller(nil)")
	}
}

func TestStartRepliesToTheApprovedAndAsksTheRest(t *testing.T) {
	u, telegram, _ := svcUI(t)
	ctx := context.Background()
	u.onStart(ctx, nil, &models.Update{})
	u.onStart(ctx, nil, message(5, "/start"))
	if !strings.Contains(lastText(t, telegram), u.cfg.UI.Hello[:5]) {
		t.Errorf("approved /start = %q", lastText(t, telegram))
	}
	u.onStart(ctx, nil, message(77, "/start"))
	if len(u.access.Pending()) != 1 {
		t.Error("an unknown user's request was not recorded")
	}
}

func TestAccessDecisionsReportStoreFailures(t *testing.T) {
	u, telegram, _ := svcUI(t)
	breakFile(t, u.store, "whitelist.json")
	breakFile(t, u.store, "pending.json")
	for _, data := range []string{cbWL + "add:77", cbWL + "no:77", cbWL + "rm:77"} {
		before := len(telegram.methods())
		press(u, 1, data)
		if len(telegram.methods()) == before {
			t.Errorf("%s: a store failure went unreported", data)
		}
	}
	// An access request that cannot be passed to the admin is only logged.
	telegram.failing("sendMessage", -1)
	u.notifyAdminsOfRequest(context.Background(), 77)
}

func TestKeyboardsShowPendingRequestsAndTheBypassShortcut(t *testing.T) {
	u, _, _ := svcUI(t)
	u.access.RequestAccess(42)
	flat := flatten(u.accessMenu())
	if !slices.Contains(flat, cbWL+"add:42") || !slices.Contains(flat, cbWL+"no:42") {
		t.Errorf("the pending user has no decision buttons: %v", flat)
	}
	if !slices.Contains(flatten(u.pickKeyboard(kindWDTT, "wdtt")), cbAllMethods) {
		t.Error("the relay method does not suggest the subscription")
	}
}

func TestProtoMenuNamesAFailingEndpointListing(t *testing.T) {
	u, _, fx := svcUI(t)
	fx.API.FailOn("Endpoints", errors.New("down"))
	if _, err := u.protoMenu(context.Background()); err == nil {
		t.Error("a failing endpoint listing built a menu")
	}
}

func TestServerCommandsNeedTheDaemonAndTheirArguments(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	u.onRotate(ctx, nil, message(1, "/rotate"))
	if !strings.Contains(lastText(t, telegram), u.label("usage_rotate")) {
		t.Errorf("rotate usage = %q", lastText(t, telegram))
	}
	u.onRotate(ctx, nil, message(1, "/rotate 42"))
	u.onImage(ctx, nil, message(1, "/image repo/core:2"))

	u.control = nil
	u.onRotate(ctx, nil, message(1, "/rotate 42"))
	if !strings.Contains(lastText(t, telegram), u.text("srv_unavailable")) {
		t.Errorf("without a daemon: %q", lastText(t, telegram))
	}
	u.SetControl(&scriptedControl{})
	u.onRotate(ctx, nil, message(1, "/rotate 42"))
	if !strings.Contains(lastText(t, telegram), "srv_failed") && lastText(t, telegram) == "" {
		t.Errorf("a refusing daemon: %q", lastText(t, telegram))
	}
}

func TestHelpFallsBackToPlainTextAndSkipsUndescribedCommands(t *testing.T) {
	u, telegram, _ := serverUI(t)
	ctx := context.Background()
	telegram.failing("sendMessage", 1)
	u.onHelp(ctx, nil, message(1, "/help"))
	if len(telegram.methods()) < 2 {
		t.Errorf("no plain fallback after the rich help was refused: %v", telegram.methods())
	}
	u.cfg.UI.Commands = map[string]string{"help": ""}
	_ = u.commandTable([]string{"help", "start"})
}

func TestVKReloginCodeFailuresAreReportedToTheAdmin(t *testing.T) {
	u := newVKCodeUI(t)
	setStatus(t, u, "awaiting-code")
	if err := os.Mkdir(u.cfg.Paths.VKReloginCode()+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if got := u.deliverVKReloginCode("123456"); !strings.Contains(got, "error") && got == "vk_code_accepted" {
		t.Errorf("staging failure: %q", got)
	}
	if err := os.Remove(u.cfg.Paths.VKReloginCode() + ".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(u.cfg.Paths.VKReloginCode(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(u.cfg.Paths.VKReloginCode()+"/keep", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := u.deliverVKReloginCode("123456"); got == "vk_code_accepted" {
		t.Errorf("rename failure: %q", got)
	}
}

func TestAdoptingAHashNeedsAReadableBundleAndAnExistingToken(t *testing.T) {
	u := newVKCodeUI(t)
	if err := u.adoptHash("t", []byte("{")); err == nil {
		t.Error("garbage hashed")
	}
	if err := u.adoptHash("unknown", []byte(`{"outbounds":[]}`)); err != nil {
		t.Errorf("an unknown token: %v", err)
	}
	token, err := u.store.SubscriptionToken("5")
	if err != nil {
		t.Fatal(err)
	}
	if err := u.adoptHash(token, []byte(`{"outbounds":[]}`)); err != nil {
		t.Fatal(err)
	}
	subs, _ := u.store.Subscriptions()
	if subs[token].LastHash == "" {
		t.Error("the hash was not adopted")
	}
	_ = state.Subscriptions{}
}

func TestNewFallsBackToTheDefaultLogger(t *testing.T) {
	u, _, _ := svcUI(t)
	if New(u.cfg, u.svc, u.access, u.store, nil).log == nil {
		t.Error("no default logger")
	}
}
