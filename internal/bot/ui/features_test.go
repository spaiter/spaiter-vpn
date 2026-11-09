package ui

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/go-telegram/bot/models"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
)

// TestCopyButtonRespectsTheAPILimit: a copy button over 256 characters makes
// Telegram reject the whole message, so the button is dropped instead.
func TestCopyButtonRespectsTheAPILimit(t *testing.T) {
	if copyButton("c", "") != nil {
		t.Error("an empty text got a copy button")
	}
	fits := strings.Repeat("я", copyTextLimit) // 256 runes, 512 bytes
	if b := copyButton("c", fits); b == nil || b.CopyText.Text != fits {
		t.Error("a text of exactly 256 characters was refused; the limit is characters, not bytes")
	}
	if copyButton("c", fits+"x") != nil {
		t.Error("a text of 257 characters got a copy button")
	}
	row := copyRow(copyEntry{"a", "vless://short"}, copyEntry{"b", strings.Repeat("x", 300)}, copyEntry{"c", ""})
	if len(row) != 1 || row[0].Text != "a" {
		t.Errorf("copyRow kept the wrong buttons: %+v", row)
	}
	if withRows(nil, row, nil, []models.InlineKeyboardButton{}).InlineKeyboard == nil {
		t.Error("withRows lost the one non-empty row")
	}
	if got := len(withRows(keyboard(row), nil).InlineKeyboard); got != 1 {
		t.Errorf("withRows appended an empty row: %d rows", got)
	}
}

// TestEveryCommandIsDescribedAndEveryDescriptionIsACommand keeps the "/" menu,
// the help table and the handlers in step: a handler without a description is
// invisible in the menu, and a description without a handler advertises a
// command that does nothing.
func TestEveryCommandIsDescribedAndEveryDescriptionIsACommand(t *testing.T) {
	cfg := botcfg.ExampleConfig()
	for _, name := range adminCommands {
		if cfg.UI.Commands[name] == "" {
			t.Errorf("/%s has no description, so it is not in the menu", name)
		}
	}
	for name := range cfg.UI.Commands {
		if !slices.Contains(adminCommands, name) {
			t.Errorf("%q is described but is not a published command", name)
		}
	}
	for _, name := range userCommands {
		if !slices.Contains(adminCommands, name) {
			t.Errorf("/%s is offered to users but not to admins", name)
		}
	}
	// /claim is deliberately absent: it is typed once, from the server's
	// instructions, and listing it would invite everyone to try.
	if slices.Contains(adminCommands, "claim") || cfg.UI.Commands["claim"] != "" {
		t.Error("/claim is advertised")
	}

	u := New(cfg, nil, NewAccess(newStore(t), quiet()), nil, quiet())
	if got := len(u.commandList(userCommands)); got != len(userCommands) {
		t.Errorf("commandList published %d of %d user commands", got, len(userCommands))
	}
	if got := u.commandList([]string{"nonexistent"}); len(got) != 0 {
		t.Errorf("an undescribed command was published: %+v", got)
	}
}

// TestHelpPageMarshals: the rich message is a tagged union the library
// marshals by hand, and a block built with the wrong variant pointer fails
// only at send time. Every block the page uses is exercised here.
func TestHelpPageMarshals(t *testing.T) {
	cfg := botcfg.ExampleConfig()
	u := New(cfg, nil, NewAccess(newStore(t), quiet()), nil, quiet())

	for _, admin := range []bool{false, true} {
		data, err := json.Marshal(u.helpMessage(admin))
		if err != nil {
			t.Fatalf("admin=%v: %v", admin, err)
		}
		text := string(data)
		for _, want := range []string{
			`"type":"heading"`, `"type":"paragraph"`, `"type":"list"`,
			`"type":"table"`, `"type":"buttons"`, `"callback_data":"menu:new"`,
			`"style":"primary"`, `"/help"`, cfg.UI.Help["title"],
		} {
			if !strings.Contains(text, want) {
				t.Errorf("admin=%v: help page lacks %s", admin, want)
			}
		}
		hasAdmin := strings.Contains(text, `"type":"details"`) && strings.Contains(text, `"/pushcfg"`)
		if hasAdmin != admin {
			t.Errorf("admin=%v: admin section present=%v", admin, hasAdmin)
		}
	}
}

// TestKeyboardsCarryStylesAndTheDisabledAPKButton: the primary action is
// coloured, verdicts are green and red, and a missing APK is shown greyed out
// rather than hidden.
func TestKeyboardsCarryStylesAndTheDisabledAPKButton(t *testing.T) {
	cfg := botcfg.ExampleConfig()
	cfg.Paths.APK = "/nonexistent/latest.apk"
	cfg.Paths.APKURL = ""
	store := newStore(t)
	u := New(cfg, nil, NewAccess(store, quiet()), store, quiet())

	menu := u.mainMenu(42)
	if first := menu.InlineKeyboard[0][0]; first.CallbackData != cbGetConfig || first.Style != stylePrimary {
		t.Errorf("the config button is not the primary action: %+v", first)
	}
	var disabled *models.InlineKeyboardButton
	for _, row := range menu.InlineKeyboard {
		for i := range row {
			if row[i].Disabled != nil {
				disabled = &row[i]
			}
		}
	}
	if disabled == nil || disabled.CallbackData != cbNoop || disabled.Text != cfg.UI.Buttons["apk_unavailable"] {
		t.Errorf("no disabled APK button in the menu: %+v", disabled)
	}
	if needsApproval(cbNoop) || needsApproval(cbMenuNew) {
		t.Error("navigation data is gated by approval")
	}

	pick := u.pickKeyboard(kindInbound, "vless-reality-in")
	if pick.InlineKeyboard[0][0].Style != styleSuccess {
		t.Error("the generate button is not green")
	}
	req := u.requestKeyboard(7).InlineKeyboard[0]
	if req[0].Style != styleSuccess || req[1].Style != styleDanger {
		t.Errorf("approve/deny are not green/red: %+v", req)
	}
}
