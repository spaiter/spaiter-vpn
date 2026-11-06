package ui

import (
	"context"
	"time"
	"unicode/utf8"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/spaiter/spaiter-vpn/internal/bot/webapp"
)

// The newer Bot API surface the bot leans on: copy buttons under secrets,
// coloured and disabled buttons, reactions as command receipts, the command
// menu and a rich /help. Everything here degrades gracefully -- a client or a
// self-hosted API server too old for one of these loses the nicety, not the
// function -- so none of it is load-bearing for handing out a configuration.

// Button styles as the API spells them (Bot API 9.4).
const (
	stylePrimary = "primary"
	styleSuccess = "success"
	styleDanger  = "danger"
)

// copyTextLimit is the API's cap on what a copy button may carry.
const copyTextLimit = 256

// copyButton is a button that puts text on the clipboard.
//
// Nil when the text does not fit: the API rejects the whole message otherwise,
// and most configurations -- a JSON file, a WireGuard profile -- are far over.
// The share links and the subscription URLs fit, and those are exactly what a
// desktop user otherwise selects by hand out of a code block.
func copyButton(label, text string) *models.InlineKeyboardButton {
	n := utf8.RuneCountInString(text)
	if n == 0 || n > copyTextLimit {
		return nil
	}
	return &models.InlineKeyboardButton{Text: label, CopyText: &models.CopyTextButton{Text: text}}
}

// styled colours a button.
func styled(b models.InlineKeyboardButton, style string) models.InlineKeyboardButton {
	b.Style = style
	return b
}

// disabledButton is shown but cannot be pressed. Used where the alternative
// was hiding the button, which left the user wondering whether the feature
// exists at all.
func disabledButton(text string) models.InlineKeyboardButton {
	return models.InlineKeyboardButton{Text: text, CallbackData: cbNoop, Disabled: &models.DisabledButton{}}
}

// copyRow builds one keyboard row of copy buttons, skipping what does not fit.
func copyRow(entries ...copyEntry) []models.InlineKeyboardButton {
	var out []models.InlineKeyboardButton
	for _, e := range entries {
		if b := copyButton(e.label, e.text); b != nil {
			out = append(out, *b)
		}
	}
	return out
}

type copyEntry struct{ label, text string }

// withRows appends rows to a keyboard, dropping empty ones.
func withRows(markup *models.InlineKeyboardMarkup, rows ...[]models.InlineKeyboardButton) *models.InlineKeyboardMarkup {
	if markup == nil {
		markup = &models.InlineKeyboardMarkup{}
	}
	for _, r := range rows {
		if len(r) > 0 {
			markup.InlineKeyboard = append(markup.InlineKeyboard, r)
		}
	}
	return markup
}

// noPreview keeps a message with a URL from growing a preview card: the links
// the bot sends are subscriptions and share URIs, and a preview of those is
// either an error page or a leak of the token into a third party's fetcher.
func noPreview() *models.LinkPreviewOptions {
	return &models.LinkPreviewOptions{IsDisabled: bot.True()}
}

// ack marks a command as processed with a reaction, which is quieter than a
// confirmation message and survives the chat being cleaned up. Failures are
// expected -- reactions are not available everywhere -- and are not reported.
func (u *UI) ack(ctx context.Context, m *models.Message) {
	if m == nil || u.client == nil {
		return
	}
	if _, err := u.client.SetMessageReaction(ctx, &bot.SetMessageReactionParams{
		ChatID:    m.Chat.ID,
		MessageID: m.ID,
		Reaction: []models.ReactionType{{
			Type:              models.ReactionTypeTypeEmoji,
			ReactionTypeEmoji: &models.ReactionTypeEmoji{Type: models.ReactionTypeTypeEmoji, Emoji: "✅"},
		}},
	}); err != nil {
		u.log.Debug("could not react to a command", "error", err)
	}
}

// --- command menu ---

// userCommands are what everyone sees in the "/" menu. Each is a command the
// bot answers for anyone; the admin ones are published per admin chat below,
// so an ordinary user is not shown a menu of things that refuse them.
var userCommands = []string{"start", "menu", "help"}

var adminCommands = []string{
	"start", "menu", "help", "whitelist", "allow", "deny",
	"add", "del", "reset", "rotate", "port", "image", "pushcfg",
	"vkhash", "vkcode", "weblogin",
}

// Announce publishes the command menu and the bot's description, once at
// startup. The admin scope is re-published whenever an admin is added.
func (u *UI) Announce(ctx context.Context) {
	if u.client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if _, err := u.client.SetMyCommands(ctx, &bot.SetMyCommandsParams{
		Commands: u.commandList(userCommands),
		Scope:    &models.BotCommandScopeDefault{},
	}); err != nil {
		u.log.Warn("could not publish the command menu", "error", err)
	}
	for _, admin := range u.access.Admins() {
		u.publishAdminCommands(ctx, admin)
	}
	// The menu button beside the input opens the Mini App where there is
	// one; otherwise Telegram's default command list stays.
	if url := webapp.URL(u.cfg); url != "" {
		if _, err := u.client.SetChatMenuButton(ctx, &bot.SetChatMenuButtonParams{
			MenuButton: &models.MenuButtonWebApp{
				Type: models.MenuButtonTypeWebApp, Text: truncate(u.label("webapp"), 16),
				WebApp: models.WebAppInfo{URL: url},
			},
		}); err != nil {
			u.log.Warn("could not set the menu button", "error", err)
		}
	}
	if d := u.cfg.UI.Description; d != "" {
		if _, err := u.client.SetMyDescription(ctx, &bot.SetMyDescriptionParams{Description: d}); err != nil {
			u.log.Warn("could not set the bot description", "error", err)
		}
	}
	if d := u.cfg.UI.ShortDescription; d != "" {
		if _, err := u.client.SetMyShortDescription(ctx, &bot.SetMyShortDescriptionParams{ShortDescription: d}); err != nil {
			u.log.Warn("could not set the short description", "error", err)
		}
	}
}

// publishAdminCommands gives one admin's chat the full menu.
func (u *UI) publishAdminCommands(ctx context.Context, admin int64) {
	if u.client == nil {
		return
	}
	if _, err := u.client.SetMyCommands(ctx, &bot.SetMyCommandsParams{
		Commands: u.commandList(adminCommands),
		Scope:    &models.BotCommandScopeChat{ChatID: admin},
	}); err != nil {
		u.log.Warn("could not publish the admin command menu", "admin", admin, "error", err)
	}
}

// commandList renders commands with their configured descriptions. A command
// with no description is left out rather than published blank, which the API
// refuses.
func (u *UI) commandList(names []string) []models.BotCommand {
	out := make([]models.BotCommand, 0, len(names))
	for _, name := range names {
		desc := u.cfg.UI.Commands[name]
		if desc == "" {
			continue
		}
		out = append(out, models.BotCommand{Command: name, Description: truncate(desc, 256)})
	}
	return out
}
