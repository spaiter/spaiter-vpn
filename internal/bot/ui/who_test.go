package ui

import (
	"strings"
	"testing"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/service"
)

func TestRenderWhoShowsTheMethodInUseFirst(t *testing.T) {
	cfg := botcfg.ExampleConfig()
	store := newStore(t)
	u := New(cfg, nil, NewAccess(store, quiet()), store, quiet())

	text := u.renderWho(service.Activity{
		Date: "2026-11-14", LiveUsers: true, PerUserInbounds: true,
		Users: []service.UserActivity{
			{
				User:       "80071",
				Live:       []service.InboundUse{{Inbound: "vless-reality-in", Bytes: 12 << 20, Conns: 3}},
				LiveProbes: 2,
				Today: []service.InboundUse{
					{Inbound: "vless-reality-in", Bytes: 700 << 20},
					{Inbound: "wg-wdtt-in", Bytes: 2 << 20},
				},
				TodayProbed: 11,
			},
			{User: "guide_test", LiveProbes: 1},
		},
	})
	for _, want := range []string{
		"🟢 `80071`",
		"*VLESS Reality* 12.0MB (3)",
		"*VLESS Reality* 700.0MB · WG-over-VK 2.0MB _(+11: ",
		// An account name is escaped, or legacy Markdown refuses the message.
		"guide\\_test",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "who_") {
		t.Errorf("a label key leaked:\n%s", text)
	}
}

func TestRenderWhoSaysWhenTheCoreCannotTell(t *testing.T) {
	cfg := botcfg.ExampleConfig()
	store := newStore(t)
	u := New(cfg, nil, NewAccess(store, quiet()), store, quiet())

	if text := u.renderWho(service.Activity{}); !strings.Contains(text, cfg.UI.Buttons["who_old_core"]) {
		t.Errorf("an old core read as nobody online:\n%s", text)
	}
	text := u.renderWho(service.Activity{LiveUsers: true})
	if !strings.Contains(text, cfg.UI.Buttons["who_old_core_today"]) || !strings.Contains(text, cfg.UI.Buttons["who_nobody"]) {
		t.Errorf("partial view not flagged:\n%s", text)
	}
}
