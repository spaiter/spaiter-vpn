package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-telegram/bot/models"

	"github.com/spaiter/spaiter-vpn/internal/bot/service"
)

// whoTagLabel names the inbounds that have no menu entry of their own, so no
// TagLabel: the WireGuard endpoints behind WG-over-VK and MASQUE, and the
// inbounds a chain or a bundle reaches without a button.
var whoTagLabel = map[string]string{
	"wg-wdtt-in":          "WG-over-VK",
	"wg-masque-in":        "MASQUE + WireGuard",
	"masque-wg-in":        "MASQUE",
	"vless-xhttp-obfs-in": "VLESS · XHTTP-obfs",
	"ss-stls-in":          "ShadowTLS + SS2022",
}

// whoMessageLimit keeps the view inside one Telegram message.
const whoMessageLimit = 4000

var whoEscaper = strings.NewReplacer("_", `\_`, "*", `\*`, "`", "\\`", "[", `\[`)

func (u *UI) inboundName(tag string) string {
	if label := u.cfg.UI.TagLabel[tag]; label != "" {
		return label
	}
	if label := whoTagLabel[tag]; label != "" {
		return label
	}
	return tag
}

// whoKeyboard refreshes the view in place, which is how an admin watches
// someone switch methods.
func (u *UI) whoKeyboard() *models.InlineKeyboardMarkup {
	return keyboard(row(button("🔄", cbWho), button(u.label("menu"), cbMenu)))
}

// onWho answers /who with the same view as the button.
func (u *UI) onWho(ctx context.Context, uid int64, _ []string) {
	u.reply(ctx, uid, u.whoText(ctx), u.whoKeyboard())
}

// whoText renders who is on which method, now and today.
func (u *UI) whoText(ctx context.Context) string {
	activity, err := u.svc.Activity(ctx, time.Now())
	if err != nil {
		return u.text("error", err.Error())
	}
	return clip(u.renderWho(activity), whoMessageLimit)
}

func (u *UI) renderWho(activity service.Activity) string {
	var out strings.Builder
	out.WriteString(u.label("who_title") + "\n" + u.label("who_legend") + "\n")
	if !activity.LiveUsers && !activity.PerUserInbounds {
		// Connections exist but none names its user: a core from before the
		// field. Saying so beats an empty list that reads as "nobody".
		out.WriteString("\n" + u.label("who_old_core"))
		return out.String()
	}
	if !activity.PerUserInbounds {
		out.WriteString("\n" + u.label("who_old_core_today") + "\n")
	}

	var idle []string
	shown := 0
	for _, user := range activity.Users {
		if len(user.Live) == 0 && len(user.Today) == 0 {
			idle = append(idle, u.whoName(user.User, false))
			continue
		}
		shown++
		marker := "⚪️"
		if len(user.Live) > 0 {
			marker = "🟢"
		}
		fmt.Fprintf(&out, "\n%s %s\n", marker, u.whoName(user.User, true))
		switch {
		case len(user.Live) > 0:
			fmt.Fprintf(&out, "    %s: %s\n", u.label("who_now"), u.whoUses(user.Live, true))
		case user.LiveProbes > 0:
			fmt.Fprintf(&out, "    %s: _%s_\n", u.label("who_now"), u.label("who_probes"))
		}
		if len(user.Today) > 0 {
			line := u.whoUses(user.Today, false)
			if user.TodayProbed > 0 {
				line += fmt.Sprintf(" _(+%d: %s)_", user.TodayProbed, u.label("who_probes"))
			}
			fmt.Fprintf(&out, "    %s: %s\n", u.label("who_today"), line)
		}
	}
	if shown == 0 {
		out.WriteString("\n" + u.label("who_nobody") + "\n")
	}
	if len(idle) > 0 {
		fmt.Fprintf(&out, "\n%s: %s", u.label("who_idle"), strings.Join(idle, ", "))
	}
	return out.String()
}

// whoName is the account and, where it is a Telegram id, the person.
func (u *UI) whoName(name string, long bool) string {
	display := u.displayNameOf(name)
	switch {
	case display == "":
		return "`" + whoEscaper.Replace(name) + "`"
	case long:
		return "`" + whoEscaper.Replace(name) + "` — " + whoEscaper.Replace(display)
	default:
		return whoEscaper.Replace(display)
	}
}

// whoUses lists inbounds busiest first; the first one is the method in use,
// in bold, the rest are what the client also had open.
func (u *UI) whoUses(uses []service.InboundUse, live bool) string {
	parts := make([]string, 0, len(uses))
	for i, use := range uses {
		name := whoEscaper.Replace(u.inboundName(use.Inbound))
		if i == 0 {
			name = "*" + name + "*"
		}
		part := name + " " + human(use.Bytes)
		if live {
			part += fmt.Sprintf(" (%d)", use.Conns)
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, " · ")
}
