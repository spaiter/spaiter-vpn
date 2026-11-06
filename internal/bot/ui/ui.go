package ui

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/loops"
	"github.com/spaiter/spaiter-vpn/internal/bot/service"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/bot/telegram"
)

// UI routes Telegram updates.
//
// The library is depended on directly here and nowhere else: this is the
// Telegram layer, and wrapping six send methods in an interface to prove it
// could be swapped would be ceremony. Everything below it takes narrow
// interfaces instead.
type UI struct {
	cfg    botcfg.Config
	svc    *service.Service
	access *Access
	apk    *APK
	store  *state.Store
	log    *slog.Logger

	// client is set once the bot is built, which cannot happen before the
	// handlers are registered.
	client *bot.Bot

	// The three collaborators an admin reaches through commands. Optional
	// because the interface is usable without them -- a deployment with no
	// hash checker simply cannot validate links -- and the handlers say so
	// rather than failing.
	validator Validator
	checker   PoolChecker
	refresher Refresher
	control   Control
	webLogin  func() (string, error)
}

// PoolChecker validates the whole VK pool on demand.
type PoolChecker interface {
	Validate(ctx context.Context) (loops.Summary, error)
}

// Refresher rebuilds every subscription on demand.
type Refresher interface {
	RefreshAll(ctx context.Context, reason string) (int, error)
}

// SetPoolChecker and SetRefresher attach what the admin commands drive.
func (u *UI) SetPoolChecker(c PoolChecker) { u.checker = c }

// SetRefresher attaches the subscription refresher.
func (u *UI) SetRefresher(r Refresher) { u.refresher = r }

// New builds the interface.
func New(cfg botcfg.Config, svc *service.Service, access *Access, store *state.Store, log *slog.Logger) *UI {
	if log == nil {
		log = slog.Default()
	}
	return &UI{
		cfg: cfg, svc: svc, access: access, store: store,
		apk: NewAPK(cfg, store, log), log: log,
	}
}

// Options are the handler registrations to pass to bot.New.
//
// The default handler catches callback queries; commands are matched exactly
// so that /start does not also answer /startfoo. Other free text is ignored.
func (u *UI) Options() []bot.Option {
	exact := bot.MatchTypeExact
	return []bot.Option{
		bot.WithDefaultHandler(u.onUpdate),
		bot.WithMessageTextHandler("/start", exact, u.onStart),
		bot.WithMessageTextHandler("/help", exact, u.onHelp),
		bot.WithMessageTextHandler("/menu", exact, u.onStart),
		bot.WithMessageTextHandler("/whitelist", exact, u.onWhitelist),
		bot.WithMessageTextHandler("/claim", bot.MatchTypePrefix, u.onClaim),
		bot.WithMessageTextHandler("/rotate", bot.MatchTypePrefix, u.onRotate),
		bot.WithMessageTextHandler("/weblogin", exact, u.onWebLogin),
		bot.WithMessageTextHandler("/port", bot.MatchTypePrefix, u.onPort),
		bot.WithMessageTextHandler("/image", bot.MatchTypePrefix, u.onImage),
		bot.WithMessageTextHandler("/add", bot.MatchTypePrefix, u.onAdd),
		bot.WithMessageTextHandler("/del", bot.MatchTypePrefix, u.onDelete),
		bot.WithMessageTextHandler("/reset", bot.MatchTypePrefix, u.onReset),
		bot.WithMessageTextHandler("/allow", bot.MatchTypePrefix, u.onAllow),
		bot.WithMessageTextHandler("/deny", bot.MatchTypePrefix, u.onDeny),
		bot.WithMessageTextHandler("/vkhash", bot.MatchTypePrefix, u.onVKHash),
		bot.WithMessageTextHandler("/vkcode", bot.MatchTypePrefix, u.onVKCode),
		bot.WithMessageTextHandler("/pushcfg", bot.MatchTypePrefix, u.onPushConfig),
	}
}

// Attach records the client the handlers send through.
func (u *UI) Attach(client *bot.Bot) { u.client = client }

// onUpdate is the fallback for callback queries.
//
// Free text is ignored entirely. It was only ever a VK call link, and that
// path is gone; answering stray messages would also make the bot noisy in any
// group it was added to.
func (u *UI) onUpdate(ctx context.Context, client *bot.Bot, update *models.Update) {
	if update.CallbackQuery != nil {
		u.onCallback(ctx, client, update)
		return
	}
	// One exception to ignoring free text: while a VK relogin is waiting for the
	// verification code, a bare six-digit message from an admin is that code,
	// typed straight into the chat. Gated on an admin sender and an actually
	// waiting relogin, so an ordinary number from anyone else is still ignored.
	if m := update.Message; m != nil && sixDigits(m.Text) != "" {
		uid := u.caller(m.From)
		if u.access.IsAdmin(uid) && u.vkReloginAwaitingCode() {
			u.ack(ctx, m)
			u.reply(ctx, uid, u.deliverVKReloginCode(m.Text), nil)
		}
	}
}

// caller identifies who sent an update and records them.
func (u *UI) caller(from *models.User) int64 {
	if from == nil {
		return 0
	}
	u.access.Register(state.User{
		ID:        from.ID,
		Username:  from.Username,
		FirstName: from.FirstName,
		LastName:  from.LastName,
	})
	return from.ID
}

// onStart answers /start, /help and /menu.
func (u *UI) onStart(ctx context.Context, client *bot.Bot, update *models.Update) {
	if update.Message == nil {
		return
	}
	uid := u.caller(update.Message.From)
	if u.access.IsAllowed(uid) {
		u.reply(ctx, uid, u.cfg.UI.Hello, u.mainMenu(uid))
		return
	}

	// Not approved: record the request and tell the admins, so access is
	// granted by a person rather than by knowing the bot's name.
	u.access.RequestAccess(uid)
	u.reply(ctx, uid, u.text("access_pending", formatID(uid)), nil)
	u.notifyAdminsOfRequest(ctx, uid)
}

// onCallback routes a button press.
func (u *UI) onCallback(ctx context.Context, client *bot.Bot, update *models.Update) {
	query := update.CallbackQuery
	uid := u.caller(&query.From)
	data := query.Data

	// Acknowledged first and unconditionally: Telegram spins the button until
	// it is, and some of what follows takes half a minute.
	if _, err := client.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{
		CallbackQueryID: query.ID,
	}); err != nil {
		u.log.Debug("could not acknowledge a callback", "error", err)
	}

	// Self-service actions need approval. Checked here rather than per branch
	// because a button missing from someone's keyboard is still callable by
	// anyone who knows its data.
	if needsApproval(data) && !u.access.IsAllowed(uid) {
		u.access.RequestAccess(uid)
		u.edit(ctx, query, u.text("access_pending", formatID(uid)), nil)
		u.notifyAdminsOfRequest(ctx, uid)
		return
	}

	switch {
	case data == cbNoop:
		// A disabled button; a client old enough to let it be pressed gets
		// nothing, which is what the button says.

	case data == cbMenu:
		u.edit(ctx, query, u.cfg.UI.Hello, u.mainMenu(uid))

	case data == cbMenuNew:
		u.reply(ctx, queryChat(query), u.cfg.UI.Hello, u.mainMenu(uid))

	case data == cbGetConfig:
		menu, err := u.protoMenu(ctx)
		if err != nil {
			u.fail(ctx, query, err)
			return
		}
		u.edit(ctx, query, u.label("choose_protocol"), menu)

	case data == cbAllMethods:
		u.deliverSubscription(ctx, query, uid)

	case data == cbAPK:
		u.deliverAPK(ctx, query, uid)

	case data == cbMyStats:
		u.showMyStats(ctx, query, uid)

	case strings.HasPrefix(data, cbPick):
		kind, tag, ok := splitCallback(data, cbPick)
		if !ok {
			u.edit(ctx, query, u.label("unavailable"), u.backKeyboard())
			return
		}
		u.edit(ctx, query, u.pickText(kind, tag), u.pickKeyboard(kind, tag))

	case strings.HasPrefix(data, cbGen):
		kind, tag, ok := splitCallback(data, cbGen)
		if !ok {
			u.edit(ctx, query, u.label("unavailable"), u.backKeyboard())
			return
		}
		u.deliver(ctx, query, uid, kind, tag)

	// Admin branches re-check, because the keyboard is not the authority.
	case data == cbUsers && u.access.IsAdmin(uid):
		u.showUsers(ctx, query)

	case data == cbAllStats && u.access.IsAdmin(uid):
		u.showAllStats(ctx, query)

	case data == cbAccess && u.access.IsAdmin(uid):
		u.edit(ctx, query, u.label("access_title"), u.accessMenu())

	case strings.HasPrefix(data, cbWL) && u.access.IsAdmin(uid):
		u.handleAccessDecision(ctx, query, data)

	case isServerCallback(data) && u.access.IsAdmin(uid):
		u.handleServer(ctx, query, uid, data)

	default:
		u.edit(ctx, query, u.label("unavailable"), u.backKeyboard())
	}
}

// needsApproval lists the actions that hand out access to the VPN itself.
func needsApproval(data string) bool {
	switch {
	case data == cbGetConfig, data == cbMyStats, data == cbAllMethods, data == cbAPK:
		return true
	case strings.HasPrefix(data, cbPick), strings.HasPrefix(data, cbGen):
		return true
	}
	return false
}

// splitCallback reads the kind and tag out of callback data. A tag may contain
// no colon for this to work, which is true of every tag the core allows.
func splitCallback(data, prefix string) (kind, tag string, ok bool) {
	rest := strings.TrimPrefix(data, prefix)
	kind, tag, ok = strings.Cut(rest, ":")
	return kind, tag, ok && kind != "" && tag != ""
}

// notifyAdminsOfRequest asks the admins to decide, with the decision attached.
func (u *UI) notifyAdminsOfRequest(ctx context.Context, uid int64) {
	text := u.text("access_request", formatID(uid), u.access.DisplayName(uid))
	for _, admin := range u.access.Admins() {
		if _, err := u.client.SendMessage(ctx, &bot.SendMessageParams{
			ChatID:             admin,
			Text:               text,
			ParseMode:          telegram.DefaultParseMode,
			LinkPreviewOptions: noPreview(),
			ReplyMarkup:        u.requestKeyboard(uid),
		}); err != nil {
			u.log.Warn("could not pass on an access request", "admin", admin, "error", err)
		}
	}
}

// NotifyAccessRequest is notifyAdminsOfRequest for the Mini App, which has
// no way to reach the admins on its own.
func (u *UI) NotifyAccessRequest(ctx context.Context, uid int64) { u.notifyAdminsOfRequest(ctx, uid) }

// Tell is the courtesy notice for the Mini App's access decisions.
func (u *UI) Tell(ctx context.Context, uid int64, text string) { u.tell(ctx, uid, text) }

// handleAccessDecision applies an approve, reject or revoke.
func (u *UI) handleAccessDecision(ctx context.Context, query *models.CallbackQuery, data string) {
	action, target, ok := splitCallback(data, cbWL)
	if !ok {
		u.edit(ctx, query, u.label("unavailable"), u.backKeyboard())
		return
	}
	uid, err := parseID(target)
	if err != nil {
		u.edit(ctx, query, u.label("unavailable"), u.backKeyboard())
		return
	}

	var outcome string
	switch action {
	case "add":
		if err := u.access.Approve(uid); err != nil {
			u.fail(ctx, query, err)
			return
		}
		outcome = u.label("access_approved")
		u.tell(ctx, uid, u.cfg.UI.AccessGranted)
	case "no":
		if err := u.access.Reject(uid); err != nil {
			u.fail(ctx, query, err)
			return
		}
		outcome = u.label("access_rejected")
		u.tell(ctx, uid, u.cfg.UI.AccessRefused)
	case "del":
		if err := u.access.Revoke(uid); err != nil {
			u.fail(ctx, query, err)
			return
		}
		outcome = u.label("access_revoked")
	default:
		u.edit(ctx, query, u.label("unavailable"), u.backKeyboard())
		return
	}
	u.edit(ctx, query, u.text("access_decided", outcome, formatID(uid)), u.accessMenu())
}

// --- sending ---

// reply sends a message to a user.
func (u *UI) reply(ctx context.Context, chat int64, text string, markup models.ReplyMarkup) {
	u.send(ctx, chat, text, markup, false)
}

// replyProtected sends a message that carries credentials: Telegram will not
// let it be forwarded or saved from the chat. Copying is still possible, by
// design -- the copy buttons are how the text reaches a client -- so this
// stops the casual forward, not a determined leak.
func (u *UI) replyProtected(ctx context.Context, chat int64, text string, markup models.ReplyMarkup) {
	u.send(ctx, chat, text, markup, true)
}

func (u *UI) send(ctx context.Context, chat int64, text string, markup models.ReplyMarkup, protect bool) {
	if _, err := u.client.SendMessage(ctx, &bot.SendMessageParams{
		ChatID:             chat,
		Text:               text,
		ParseMode:          telegram.DefaultParseMode,
		LinkPreviewOptions: noPreview(),
		ProtectContent:     protect,
		ReplyMarkup:        markup,
	}); err != nil {
		u.log.Warn("could not send a message", "chat", chat, "error", err)
	}
}

// tell sends a message and does not care whether it arrived: it is a courtesy
// notice, and the user may have blocked the bot.
func (u *UI) tell(ctx context.Context, chat int64, text string) {
	if text == "" {
		return
	}
	if _, err := u.client.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: chat, Text: text, ParseMode: telegram.DefaultParseMode,
		LinkPreviewOptions: noPreview(),
	}); err != nil {
		u.log.Debug("a courtesy notice did not arrive", "chat", chat, "error", err)
	}
}

// edit rewrites the message a button belongs to, which is how the menus
// navigate without filling the chat with screens.
func (u *UI) edit(ctx context.Context, query *models.CallbackQuery, text string, markup models.ReplyMarkup) {
	if query.Message.Message == nil {
		return
	}
	if _, err := u.client.EditMessageText(ctx, &bot.EditMessageTextParams{
		ChatID:             query.Message.Message.Chat.ID,
		MessageID:          query.Message.Message.ID,
		Text:               text,
		ParseMode:          telegram.DefaultParseMode,
		LinkPreviewOptions: noPreview(),
		ReplyMarkup:        markup,
	}); err != nil {
		// Editing fails when the text is unchanged, which happens whenever
		// someone presses the same button twice. Not worth a warning.
		u.log.Debug("could not edit a message", "error", err)
	}
}

// fail reports an error to the user who caused it.
//
// The message carries the cause: these are operational failures -- an endpoint
// gone, a registration refused -- and an admin reading over a user's shoulder
// is the fastest path to a diagnosis. Nothing secret reaches here, because
// credentials are not part of any error this layer produces.
func (u *UI) fail(ctx context.Context, query *models.CallbackQuery, err error) {
	u.log.Error("a button failed", "data", query.Data, "error", err)
	u.edit(ctx, query, u.text("error", err.Error()), u.backKeyboard())
}

// text renders a configured message with its arguments.
func (u *UI) text(key string, args ...any) string {
	format := u.cfg.UI.Messages[key]
	if format == "" {
		// A message nobody configured is shown as its key and arguments rather
		// than as an empty bubble, so the gap is visible instead of silent.
		return fmt.Sprintf("%s %v", key, args)
	}
	return fmt.Sprintf(format, args...)
}

// pickText describes the chosen method before it is generated.
func (u *UI) pickText(kind, tag string) string {
	client := u.cfg.UI.ClientHint[tag]
	if client == "" {
		client = u.cfg.UI.ClientHint[kind]
	}
	if client == "" {
		client = u.label("default_client")
	}
	return u.text("pick", u.tagLabel(tag, tag), client)
}
