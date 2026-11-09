// Package telegram delivers the bot's messages.
//
// It is a thin layer over the library on purpose: the surrounding packages take
// a Notifier interface, so the background loops and the provisioning path can be
// exercised without a Telegram account, and the library's types do not spread
// into them.
package telegram

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

// Sender is the part of the library the notifier uses.
type Sender interface {
	SendMessage(ctx context.Context, params *bot.SendMessageParams) (*models.Message, error)
}

// Notifier sends messages to users and to the admins.
type Notifier struct {
	sender Sender
	store  *state.Store
	log    *slog.Logger

	// ParseMode is how message text is rendered. Set once here rather than per
	// call site, because the texts all come from the same place: the config.
	ParseMode models.ParseMode
}

// DefaultParseMode is legacy Markdown, and the V1 is not an oversight.
//
// The library's ParseModeMarkdown constant is MarkdownV2, which reserves
// characters the existing texts are full of -- '.', '-', '!', '(' -- and
// Telegram rejects a message with any of them unescaped. Every string in the
// config was written for V1, so defaulting to V2 would turn the whole
// user-facing surface into 400s that only show up when a particular message is
// actually sent.
const DefaultParseMode = models.ParseModeMarkdownV1

// NewNotifier builds a notifier.
func NewNotifier(sender Sender, store *state.Store, log *slog.Logger) *Notifier {
	if log == nil {
		log = slog.Default()
	}
	return &Notifier{sender: sender, store: store, log: log, ParseMode: DefaultParseMode}
}

// Notify sends one message to one user, identified the way the state files
// identify them: by the Telegram id as a string.
func (n *Notifier) Notify(ctx context.Context, uid, text string) error {
	id, err := strconv.ParseInt(uid, 10, 64)
	if err != nil {
		return fmt.Errorf("telegram: %q is not a chat id: %w", uid, err)
	}
	return n.send(ctx, id, text)
}

// NotifyAdmins sends one message to everyone on the admin list.
//
// Every failure is collected rather than returned at the first one: the alarms
// that come through here are about the pool emptying or a path breaking, and one
// admin who has blocked the bot must not stop the others from hearing it.
func (n *Notifier) NotifyAdmins(ctx context.Context, text string) error {
	admins, err := n.store.Admins()
	if err != nil {
		return err
	}
	if len(admins) == 0 {
		// Worth saying out loud: the alarms have nowhere to go, which is a
		// deployment that looks healthy and reports nothing.
		n.log.Warn("there are no admins to notify")
		return nil
	}

	var failures []error
	for _, id := range admins {
		if err := n.send(ctx, id, text); err != nil {
			failures = append(failures, fmt.Errorf("admin %d: %w", id, err))
		}
	}
	return errors.Join(failures...)
}

func (n *Notifier) send(ctx context.Context, chatID int64, text string) error {
	_, err := n.sender.SendMessage(ctx, &bot.SendMessageParams{
		ChatID:    chatID,
		Text:      text,
		ParseMode: n.ParseMode,
		// The moved-subscription notice carries the new URLs; a preview of a
		// subscription URL is a token handed to a preview fetcher.
		LinkPreviewOptions: &models.LinkPreviewOptions{IsDisabled: bot.True()},
	})
	if err != nil {
		return fmt.Errorf("telegram: send to %d: %w", chatID, err)
	}
	return nil
}

// Unreachable reports whether an error means this chat will never accept a
// message again, as opposed to a transient failure.
//
// The distinction matters to anything that retries: a user who blocked the bot
// or deleted their account is not coming back, and treating that as a temporary
// fault means retrying on every tick forever. Matched on the API's description
// text because that is all Telegram gives -- every one of these arrives as the
// same 403.
func Unreachable(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, permanent := range []string{
		"bot was blocked by the user",
		"user is deactivated",
		"chat not found",
		"bot was kicked",
	} {
		if strings.Contains(message, permanent) {
			return true
		}
	}
	return false
}
