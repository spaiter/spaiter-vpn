package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	qrcode "github.com/skip2/go-qrcode"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/clientcfg"
	"github.com/spaiter/spaiter-vpn/internal/bot/telegram"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

// deliver hands over one method.
//
// What arrives depends on what the client can read, not on preference: a share
// URI where one exists, a config file where the protocol has no usable URI, and
// an ini profile for Amnezia. The QR is a convenience on top -- scanning beats
// copying a 300-character link on a phone.
func (u *UI) deliver(ctx context.Context, query *models.CallbackQuery, uid int64, kind, tag string) {
	chat := queryChat(query)
	if chat == 0 {
		return
	}
	name := strconv.FormatInt(uid, 10)

	switch kind {
	case kindEndpoint:
		u.edit(ctx, query, u.text("generating"), nil)
		conf, err := u.svc.AWGConf(ctx, tag, name)
		if err != nil {
			u.fail(ctx, query, err)
			return
		}
		u.sendPhoto(ctx, chat, conf, u.text("caption_awg"), nil)
		// WireGuard and Amnezia take the tunnel's name from the filename and
		// accept at most 15 characters of [a-zA-Z0-9_=+.-], so a full numeric
		// id does not fit and the import fails with "Invalid name".
		u.sendDocument(ctx, chat, []byte(conf), shortProfileName(name)+".conf", "")

	case kindWARP:
		u.edit(ctx, query, u.text("registering_warp"), nil)
		config, err := u.svc.WARPChainConfig(ctx, name)
		if err != nil {
			u.fail(ctx, query, err)
			return
		}
		u.sendDocument(ctx, chat, config, "warp-"+name+".json", u.text("caption_warp"))

	case kindWDTT:
		u.edit(ctx, query, u.text("provisioning_wdtt"), nil)
		config, err := u.svc.WDTTConfig(ctx, name)
		if err != nil {
			u.fail(ctx, query, err)
			return
		}
		u.sendDocument(ctx, chat, config, "wdtt-"+name+".json", u.text("caption_wdtt"))

	default:
		u.edit(ctx, query, u.text("generating"), nil)
		if botcfg.JSONTags()[tag] {
			config, err := u.svc.JSONConfig(ctx, tag, name)
			if err != nil {
				u.fail(ctx, query, err)
				return
			}
			client := u.clientHint(tag)
			u.sendPhoto(ctx, chat, string(config),
				u.text("caption_json", u.tagLabel(tag, tag), client), nil)
			u.sendDocument(ctx, chat, config, tag+"-"+name+".json", "")
			break
		}
		link, err := u.svc.Link(ctx, tag, name)
		if err != nil {
			u.fail(ctx, query, err)
			return
		}
		// The link travels in the caption as well as the QR: a desktop user
		// copies it, a phone user scans it.
		caption := u.text("caption_link", u.tagLabel(tag, tag), link)
		u.sendPhoto(ctx, chat, link, truncate(caption, 1024),
			withRows(nil, copyRow(copyEntry{u.label("copy"), link})))
	}

	u.reply(ctx, chat, u.readyText(tag), u.mainMenu(uid))
}

// readyText closes the delivery with what the method is and what to open it in.
func (u *UI) readyText(tag string) string {
	var description string
	if desc := u.cfg.UI.ProtoDesc[tag]; desc != "" {
		description = u.text("proto_desc", desc)
	}
	return u.text("ready", description, u.clientApps(tag))
}

// clientApps names the applications that can read this method, per platform.
func (u *UI) clientApps(tag string) string {
	if apps := u.cfg.UI.ClientApps[tag]; apps != "" {
		return apps
	}
	return u.cfg.UI.ClientApps["default"]
}

// clientHint is the application a user is pointed at for one method.
func (u *UI) clientHint(tag string) string {
	if hint := u.cfg.UI.ClientHint[tag]; hint != "" {
		return hint
	}
	return u.label("default_client")
}

// deliverSubscription hands over the auto-updating all-methods subscription.
//
// This is the one delivery that provisions everything at once, so it is also
// the slowest -- the notice goes out first, because thirty silent seconds after
// a button press reads as a broken bot.
func (u *UI) deliverSubscription(ctx context.Context, query *models.CallbackQuery, uid int64) {
	chat := queryChat(query)
	if chat == 0 {
		return
	}
	u.edit(ctx, query, u.text("preparing_sub"), nil)

	name := strconv.FormatInt(uid, 10)
	bundle, err := u.svc.Bundle(ctx, name, true)
	if err != nil {
		u.fail(ctx, query, err)
		return
	}
	token, err := u.store.SubscriptionToken(name)
	if err != nil {
		u.fail(ctx, query, err)
		return
	}
	// Written now rather than left to the refresh loop: the client polls as
	// soon as the link is pasted, and an empty cache is a 404 on first use.
	if err := u.store.SetBundleCache(token, bundle); err != nil {
		u.fail(ctx, query, err)
		return
	}
	// The hash is adopted at the same time, so the next refresh does not
	// announce a change to someone who just received the thing.
	if err := u.adoptHash(token, bundle); err != nil {
		u.log.Warn("could not record the subscription hash", "error", err)
	}

	cf, direct := u.SubscriptionURLs(token)
	u.replyProtected(ctx, chat, u.text("subscription", countNodes(bundle), cf, direct),
		withRows(u.backKeyboard(), copyRow(
			copyEntry{u.label("copy_cf"), cf},
			copyEntry{u.label("copy_direct"), direct},
		)))
}

// SubscriptionURLs are the two ways to the same subscription.
//
// Two of them because neither is reliable alone: the tunnelled one depends on
// a third party, and the direct one depends on a port forward through a DS-Lite
// line that moves.
func (u *UI) SubscriptionURLs(token string) (cf, direct string) {
	if host := u.cfg.Subscription.HostCF; host != "" {
		cf = "https://" + host + "/sub/" + token
	}
	if host := u.cfg.Subscription.HostDirect; host != "" {
		direct = "http://" + host + "/sub/" + token
	}
	return cf, direct
}

// showMyStats reports a user's own traffic.
func (u *UI) showMyStats(ctx context.Context, query *models.CallbackQuery, uid int64) {
	stat, found, err := u.svc.Stats(ctx, strconv.FormatInt(uid, 10))
	if err != nil {
		u.fail(ctx, query, err)
		return
	}
	if !found {
		u.edit(ctx, query, u.text("no_stats"), u.backKeyboard())
		return
	}
	u.edit(ctx, query, u.text("my_stats",
		human(stat.Upload), human(stat.Download), stat.ConnCount), u.backKeyboard())
}

// showUsers lists who actually holds a configuration, for an admin.
//
// From the accounts on the live inbounds, not from the user registry. The
// registry records everyone who ever messaged the bot, so listing it put people
// who had been refused access in a view an admin reads as "who has the VPN".
//
// Nor is it the whitelist: that says who may ask for a configuration, while
// this says who holds one. A user revoked from the whitelist keeps connecting
// until their accounts are deleted, and that is exactly what an admin needs to
// see here.
func (u *UI) showUsers(ctx context.Context, query *models.CallbackQuery) {
	accounts, err := u.svc.Accounts(ctx)
	if err != nil {
		u.fail(ctx, query, err)
		return
	}
	if len(accounts) == 0 {
		u.edit(ctx, query, u.label("no_users"), u.backKeyboard())
		return
	}
	rows, err := u.svc.AllStats(ctx)
	if err != nil {
		u.fail(ctx, query, err)
		return
	}

	stats := make(map[string]manage.UserStat, len(rows))
	for _, row := range rows {
		stats[row.User] = row
	}

	// Busiest first: with a dozen accounts an alphabetical list buries the one
	// an admin is usually looking for.
	names := make([]string, 0, len(accounts))
	for name := range accounts {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if d := stats[names[i]].Download - stats[names[j]].Download; d != 0 {
			return d > 0
		}
		return names[i] < names[j]
	})

	var out strings.Builder
	out.WriteString(u.label("users_title") + "\n")
	for _, name := range names {
		stat := stats[name]
		marker := "⚪️"
		if stat.Active > 0 {
			marker = "🟢"
		}
		// The numeric name is the account on every inbound, which is what ties
		// a person to the traffic the core counted. Traffic is the total across
		// inbounds -- the core aggregates by name and has no per-inbound
		// breakdown, so repeating it under each protocol would double-count.
		who := ""
		if display := u.displayNameOf(name); display != "" {
			who = " — " + display
		}
		fmt.Fprintf(&out, "\n%s `%s`%s  ↑%s ↓%s\n    _%s_\n",
			marker, name, who, human(stat.Upload), human(stat.Download),
			strings.Join(accounts[name], ", "))
	}
	u.edit(ctx, query, out.String(), u.backKeyboard())
}

// displayNameOf resolves an account name to a person, when the account name is
// a Telegram id. An account added by hand under an arbitrary name has nobody
// behind it, and shows as itself.
func (u *UI) displayNameOf(name string) string {
	id, err := parseID(name)
	if err != nil {
		return ""
	}
	return u.access.DisplayName(id)
}

// showAllStats reports the totals.
func (u *UI) showAllStats(ctx context.Context, query *models.CallbackQuery) {
	rows, err := u.svc.AllStats(ctx)
	if err != nil {
		u.fail(ctx, query, err)
		return
	}

	var up, down int64
	var out strings.Builder
	out.WriteString(u.label("stats_title") + "\n")
	for _, row := range rows {
		up += row.Upload
		down += row.Download
		fmt.Fprintf(&out, "`%s` ↑ %s ↓ %s\n", row.User, human(row.Upload), human(row.Download))
	}
	fmt.Fprintf(&out, "\n*Σ* ↑ %s ↓ %s", human(up), human(down))
	u.edit(ctx, query, out.String(), u.backKeyboard())
}

// --- sending artefacts ---

// sendPhoto sends a QR code of some text.
//
// A failure here is reported rather than swallowed: the QR is the part a phone
// user actually uses, and a silent miss leaves them with a caption about a
// picture that never arrived.
//
// The QR encodes credentials, so the message is protected from forwarding. The
// configuration files are deliberately not: a protected document cannot be
// opened in another application on a phone, and that is how a .conf or .json
// gets imported.
func (u *UI) sendPhoto(ctx context.Context, chat int64, encode, caption string, markup models.ReplyMarkup) {
	png, err := qrcode.Encode(encode, qrcode.Medium, 512)
	if err != nil {
		// Too much data for a QR is normal for a long config, and not worth an
		// error message: the file follows either way.
		u.log.Info("no QR for this artefact", "bytes", len(encode), "error", err)
		if caption != "" {
			u.replyProtected(ctx, chat, caption, markup)
		}
		return
	}
	if _, err := u.client.SendPhoto(ctx, &bot.SendPhotoParams{
		ChatID:         chat,
		Photo:          &models.InputFileUpload{Filename: "qr.png", Data: bytes.NewReader(png)},
		Caption:        caption,
		ParseMode:      telegram.DefaultParseMode,
		ProtectContent: true,
		ReplyMarkup:    markup,
	}); err != nil {
		u.log.Warn("could not send a QR code", "chat", chat, "error", err)
	}
}

// sendDocument sends a configuration as a file, which is how it is imported.
func (u *UI) sendDocument(ctx context.Context, chat int64, data []byte, filename, caption string) {
	if _, err := u.client.SendDocument(ctx, &bot.SendDocumentParams{
		ChatID:    chat,
		Document:  &models.InputFileUpload{Filename: filename, Data: bytes.NewReader(data)},
		Caption:   caption,
		ParseMode: telegram.DefaultParseMode,
	}); err != nil {
		u.log.Warn("could not send a configuration", "chat", chat, "file", filename, "error", err)
	}
}

// queryChat finds the chat a button press came from.
func queryChat(query *models.CallbackQuery) int64 {
	if query.Message.Message != nil {
		return query.Message.Message.Chat.ID
	}
	return query.From.ID
}

// shortProfileName keeps a WireGuard tunnel name within what the clients
// accept: at most 15 characters of a restricted alphabet.
func shortProfileName(uid string) string {
	suffix := uid
	if len(suffix) > 4 {
		suffix = suffix[len(suffix)-4:]
	}
	return "amnezia-" + suffix
}

// human renders a byte count the way a person reads one.
func human(n int64) string {
	value := float64(n)
	for _, unit := range []string{"B", "KB", "MB", "GB"} {
		if value < 1024 {
			return fmt.Sprintf("%.1f%s", value, unit)
		}
		value /= 1024
	}
	return fmt.Sprintf("%.1fTB", value)
}

// parseID reads a Telegram id out of callback data.
func parseID(text string) (int64, error) {
	return strconv.ParseInt(strings.TrimSpace(text), 10, 64)
}

// countNodes is how many methods a subscription carries, which is the one
// number a user actually wants from it.
func countNodes(bundle []byte) int {
	var parsed struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(bundle, &parsed); err != nil {
		return 0
	}
	return len(parsed.Outbounds)
}

// structuralHash identifies a bundle by what a user would have to act on.
func structuralHash(bundle []byte) (string, error) {
	return clientcfg.StructuralHash(bundle)
}
