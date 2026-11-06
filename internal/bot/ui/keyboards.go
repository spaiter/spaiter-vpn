package ui

import (
	"context"
	"fmt"
	"strconv"

	"github.com/go-telegram/bot/models"
)

// Callback data. Short because Telegram caps it at 64 bytes, and a tag travels
// in some of them.
const (
	cbMenu       = "menu"
	cbGetConfig  = "getcfg"
	cbAllMethods = "allsub"
	cbMyStats    = "mystats"
	cbAPK        = "apk"
	cbUsers      = "a:list"
	cbAllStats   = "a:stats"
	cbAccess     = "a:wl"

	// cbPick and cbGen carry a kind and a tag: "pick:i:vless-reality-in".
	cbPick = "pick:"
	cbGen  = "gen:"
	// cbWL carries an action and a user id: "wl:add:4242".
	cbWL = "wl:"

	// cbMenuNew opens the menu as a fresh message rather than by editing the
	// one the button is on. Rich messages (the /help page) are not edited into
	// a plain menu.
	cbMenuNew = "menu:new"
	// cbNoop is the data on a disabled button. Never delivered, because the
	// client does not let it be pressed; present because the API requires
	// every button to have some action.
	cbNoop = "noop"
)

// Kinds of method, which decide how a configuration is delivered and which
// client the user is pointed at.
const (
	kindInbound  = "i" // a share link or a config file
	kindEndpoint = "e" // an AmneziaWG profile
	kindWARP     = "w" // the Cloudflare entry chain
	kindWDTT     = "v" // WG-over-VK
)

// button is a shorthand for an inline button.
func button(text, data string) models.InlineKeyboardButton {
	return models.InlineKeyboardButton{Text: text, CallbackData: data}
}

// urlButton opens a link instead of calling back.
func urlButton(text, url string) models.InlineKeyboardButton {
	return models.InlineKeyboardButton{Text: text, URL: url}
}

func keyboard(rows ...[]models.InlineKeyboardButton) *models.InlineKeyboardMarkup {
	return &models.InlineKeyboardMarkup{InlineKeyboard: rows}
}

func row(buttons ...models.InlineKeyboardButton) []models.InlineKeyboardButton {
	return buttons
}

// label reads a caption from the configuration, falling back to the key so a
// caption nobody has translated shows up as itself rather than as blank.
func (u *UI) label(key string) string {
	if text := u.cfg.UI.Buttons[key]; text != "" {
		return text
	}
	return key
}

// mainMenu is what a user sees after /start.
//
// The admin rows are added by what the caller is, not hidden by it: a button
// that is merely absent from the keyboard is still callable by anyone who knows
// its data, so every admin action checks again when it runs.
func (u *UI) mainMenu(uid int64) *models.InlineKeyboardMarkup {
	rows := [][]models.InlineKeyboardButton{
		row(styled(button(u.label("getcfg"), cbGetConfig), stylePrimary)),
		row(button(u.label("allsub"), cbAllMethods)),
		row(button(u.label("mystats"), cbMyStats)),
	}

	switch {
	case u.apk.Available():
		rows = append(rows, row(button(u.label("apk"), cbAPK)))
	case u.cfg.Paths.APKURL != "":
		// No file to upload, but a published build to point at: better than a
		// button that fails.
		rows = append(rows, row(urlButton(u.label("apk"), u.cfg.Paths.APKURL)))
	default:
		// Shown greyed out rather than hidden: a user who installed the
		// client last month should see that the download exists and is
		// merely out right now, not conclude the feature was removed.
		rows = append(rows, row(disabledButton(u.label("apk_unavailable"))))
	}

	if u.access.IsAdmin(uid) {
		rows = append(rows, row(
			button(u.label("a:list"), cbUsers),
			button(u.label("a:stats"), cbAllStats),
		))
		access := u.label("a:wl")
		if waiting := len(u.access.Pending()); waiting > 0 {
			access = fmt.Sprintf("%s (%d)", access, waiting)
		}
		rows = append(rows, row(button(access, cbAccess)))
		rows = append(rows, u.serverRows()...)
	}
	return keyboard(rows...)
}

// backKeyboard is the single way out of every leaf screen.
func (u *UI) backKeyboard() *models.InlineKeyboardMarkup {
	return keyboard(row(button(u.label("menu"), cbMenu)))
}

// protoMenu lists every method, built from what the core is actually serving.
//
// A protocol added to the deployment appears here with no change to the bot,
// and one removed stops being offered. The two chain methods are appended
// because they are not inbounds -- nothing in the core's list describes them.
func (u *UI) protoMenu(ctx context.Context) (*models.InlineKeyboardMarkup, error) {
	inbounds, err := u.svc.UserInbounds(ctx)
	if err != nil {
		return nil, err
	}
	endpoints, err := u.svc.OfferedEndpoints(ctx)
	if err != nil {
		return nil, err
	}

	var rows [][]models.InlineKeyboardButton
	for _, inbound := range inbounds {
		rows = append(rows, row(button(
			u.tagLabel(inbound.Tag, inbound.Type),
			cbPick+kindInbound+":"+inbound.Tag,
		)))
	}
	for _, endpoint := range endpoints {
		rows = append(rows, row(button(
			u.tagLabel(endpoint.Tag, "awg"),
			cbPick+kindEndpoint+":"+endpoint.Tag,
		)))
	}
	rows = append(rows,
		row(button(u.label("warp"), cbPick+kindWARP+":warp")),
		row(button(u.label("wdtt"), cbPick+kindWDTT+":wdtt")),
		row(button(u.label("menu"), cbMenu)),
	)
	return keyboard(rows...), nil
}

// tagLabel names a method, preferring the per-tag caption and falling back
// through the per-protocol one to the raw type.
func (u *UI) tagLabel(tag, protocol string) string {
	if label := u.cfg.UI.TagLabel[tag]; label != "" {
		return label
	}
	if label := u.cfg.UI.ProtoLabel[protocol]; label != "" {
		return label
	}
	return protocol
}

// accessMenu is the admin's view of who is waiting and who is in.
func (u *UI) accessMenu() *models.InlineKeyboardMarkup {
	var rows [][]models.InlineKeyboardButton
	for _, uid := range u.access.Pending() {
		rows = append(rows, row(
			styled(button(truncate(fmt.Sprintf("✅ %d %s", uid, u.access.DisplayName(uid)), 60),
				cbWL+"add:"+strconv.FormatInt(uid, 10)), styleSuccess),
			styled(button("🚫", cbWL+"no:"+strconv.FormatInt(uid, 10)), styleDanger),
		))
	}
	for _, uid := range u.access.Whitelist() {
		rows = append(rows, row(styled(button(
			truncate(fmt.Sprintf("🗑 %d %s", uid, u.access.DisplayName(uid)), 60),
			cbWL+"del:"+strconv.FormatInt(uid, 10),
		), styleDanger)))
	}
	rows = append(rows, row(button(u.label("menu"), cbMenu)))
	return keyboard(rows...)
}

// requestKeyboard is attached to the notice an admin gets when someone asks for
// access, so it can be answered without opening a menu.
func (u *UI) requestKeyboard(uid int64) *models.InlineKeyboardMarkup {
	id := strconv.FormatInt(uid, 10)
	return keyboard(row(
		styled(button(u.label("approve"), cbWL+"add:"+id), styleSuccess),
		styled(button(u.label("deny"), cbWL+"no:"+id), styleDanger),
	))
}

// pickKeyboard offers to generate the method the user just chose.
func (u *UI) pickKeyboard(kind, tag string) *models.InlineKeyboardMarkup {
	rows := [][]models.InlineKeyboardButton{
		row(styled(button(u.label("generate"), cbGen+kind+":"+tag), styleSuccess)),
	}
	if kind == kindWDTT {
		// Whoever reaches for the censorship-bypass method is the user most
		// helped by the auto-updating subscription, which carries it and
		// everything else and follows the server when the pool rotates.
		rows = append(rows, row(button(u.label("allsub"), cbAllMethods)))
	}
	rows = append(rows, row(button(u.label("back"), cbGetConfig)))
	return keyboard(rows...)
}

// truncate cuts a button caption to what Telegram will show, by runes rather
// than bytes: cutting mid-rune produces a caption the API rejects outright.
func truncate(text string, limit int) string {
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit])
}
