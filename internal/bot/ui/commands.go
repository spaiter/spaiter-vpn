package ui

import (
	"context"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

// The admin commands. They exist beside the buttons because some of what an
// admin needs -- adding an account under an arbitrary name, resetting a
// counter -- takes an argument, and a keyboard cannot ask for one.

// adminOnly runs a handler only for an administrator, and tells anyone else
// their own id so they can ask to be added.
func (u *UI) adminOnly(handler func(ctx context.Context, uid int64, args []string)) bot.HandlerFunc {
	return func(ctx context.Context, _ *bot.Bot, update *models.Update) {
		if update.Message == nil {
			return
		}
		uid := u.caller(update.Message.From)
		if !u.access.IsAdmin(uid) {
			u.reply(ctx, uid, u.text("admin_only", formatID(uid)), nil)
			return
		}
		handler(ctx, uid, commandArgs(update.Message.Text))
	}
}

// onClaim adopts a deployment that has no admin, with the one-time code its
// operator issued on the server. Open to anyone, because whoever has no role
// yet is exactly who needs it; the code, not the caller, is the credential.
func (u *UI) onClaim(ctx context.Context, _ *bot.Bot, update *models.Update) {
	if update.Message == nil {
		return
	}
	uid := u.caller(update.Message.From)
	args := commandArgs(update.Message.Text)
	if len(args) == 0 || !u.access.Claim(strings.Join(args, ""), uid) {
		u.reply(ctx, uid, u.text("claim_refused"), nil)
		return
	}
	u.reply(ctx, uid, u.text("claim_accepted"), u.mainMenu(uid))
}

// commandArgs splits a command's arguments, ignoring the command itself and the
// @botname suffix Telegram appends in groups.
func commandArgs(text string) []string {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return nil
	}
	return fields[1:]
}

// onAdd creates an account under a name of the admin's choosing.
//
// The name is not forced to be a Telegram id: this is how a device, a friend
// without Telegram, or a test account gets credentials. The core attributes
// traffic by this name, so whatever is chosen is what the statistics will show.
func (u *UI) onAdd(ctx context.Context, client *bot.Bot, update *models.Update) {
	u.adminOnly(func(ctx context.Context, uid int64, args []string) {
		if len(args) < 2 {
			u.reply(ctx, uid, u.label("usage_add"), nil)
			return
		}
		tag, name := args[0], args[1]
		link, err := u.svc.Link(ctx, tag, name)
		if err != nil {
			// Not every protocol has a link; a config file is the answer then.
			config, jsonErr := u.svc.JSONConfig(ctx, tag, name)
			if jsonErr != nil {
				u.reply(ctx, uid, u.text("error", err.Error()), nil)
				return
			}
			u.sendDocument(ctx, uid, config, tag+"-"+name+".json",
				u.text("added", name, tag))
			return
		}
		u.reply(ctx, uid, u.text("added_link", name, tag, link), nil)
	})(ctx, client, update)
}

// onDelete removes an account.
//
// Deliberately irreversible and deliberately manual: the credentials were
// generated once and only the client has them, so a deletion by mistake cannot
// be undone by re-adding the same name.
func (u *UI) onDelete(ctx context.Context, client *bot.Bot, update *models.Update) {
	u.adminOnly(func(ctx context.Context, uid int64, args []string) {
		if len(args) < 2 {
			u.reply(ctx, uid, u.label("usage_del"), nil)
			return
		}
		if err := u.svc.DeleteUser(ctx, args[0], args[1]); err != nil {
			u.reply(ctx, uid, u.text("error", err.Error()), nil)
			return
		}
		u.reply(ctx, uid, u.text("deleted", args[1], args[0]), nil)
	})(ctx, client, update)
}

// onReset clears a user's traffic counters.
func (u *UI) onReset(ctx context.Context, client *bot.Bot, update *models.Update) {
	u.adminOnly(func(ctx context.Context, uid int64, args []string) {
		if len(args) < 1 {
			u.reply(ctx, uid, u.label("usage_reset"), nil)
			return
		}
		if err := u.svc.ResetStats(ctx, args[0]); err != nil {
			u.reply(ctx, uid, u.text("error", err.Error()), nil)
			return
		}
		u.reply(ctx, uid, u.text("reset", args[0]), nil)
	})(ctx, client, update)
}

// onAllow and onDeny are the whitelist by command, for when an admin has an id
// but not the message it came from.
func (u *UI) onAllow(ctx context.Context, client *bot.Bot, update *models.Update) {
	u.adminOnly(func(ctx context.Context, uid int64, args []string) {
		target, err := u.requireID(ctx, uid, args)
		if err != nil {
			return
		}
		if err := u.access.Approve(target); err != nil {
			u.reply(ctx, uid, u.text("error", err.Error()), nil)
			return
		}
		u.reply(ctx, uid, u.text("access_decided", u.label("access_approved"), formatID(target)), nil)
		u.tell(ctx, target, u.cfg.UI.AccessGranted)
	})(ctx, client, update)
}

func (u *UI) onDeny(ctx context.Context, client *bot.Bot, update *models.Update) {
	u.adminOnly(func(ctx context.Context, uid int64, args []string) {
		target, err := u.requireID(ctx, uid, args)
		if err != nil {
			return
		}
		if err := u.access.Revoke(target); err != nil {
			u.reply(ctx, uid, u.text("error", err.Error()), nil)
			return
		}
		u.reply(ctx, uid, u.text("access_decided", u.label("access_revoked"), formatID(target)), nil)
	})(ctx, client, update)
}

// onWhitelist shows who is in and who is waiting.
func (u *UI) onWhitelist(ctx context.Context, client *bot.Bot, update *models.Update) {
	u.adminOnly(func(ctx context.Context, uid int64, _ []string) {
		u.reply(ctx, uid, u.text("whitelist",
			idList(u.access.Whitelist(), u.access.DisplayName),
			idList(u.access.Pending(), u.access.DisplayName),
		), u.accessMenu())
	})(ctx, client, update)
}

// onVKHash manages the call pool by hand: list, add, remove, check.
func (u *UI) onVKHash(ctx context.Context, client *bot.Bot, update *models.Update) {
	u.adminOnly(func(ctx context.Context, uid int64, args []string) {
		action := ""
		if len(args) > 0 {
			action = args[0]
		}
		switch action {
		case "", "list":
			pool, err := u.store.VKHashes()
			if err != nil {
				u.reply(ctx, uid, u.text("error", err.Error()), nil)
				return
			}
			var out strings.Builder
			out.WriteString(u.label("vk_pool_title") + "\n")
			for hash, entry := range pool {
				status := entry.Status
				if status == "" {
					status = "?"
				}
				out.WriteString("`" + hash + "` — " + status + " " + entry.ByName + "\n")
			}
			u.reply(ctx, uid, out.String(), u.backKeyboard())

		case "add":
			if len(args) < 2 {
				u.reply(ctx, uid, u.label("usage_vkhash"), nil)
				return
			}
			result, err := u.submitVKLink(ctx, args[1], uid)
			if err != nil {
				u.reply(ctx, uid, u.text("vk_rejected", err.Error()), nil)
				return
			}
			u.reply(ctx, uid, result, nil)

		case "del":
			if len(args) < 2 {
				u.reply(ctx, uid, u.label("usage_vkhash"), nil)
				return
			}
			hash := NormalizeVKHash(args[1])
			err := u.store.UpdateVKHashes(func(fresh state.VKHashes) error {
				delete(fresh, hash)
				return nil
			})
			if err != nil {
				u.reply(ctx, uid, u.text("error", err.Error()), nil)
				return
			}
			u.reply(ctx, uid, u.text("vk_removed", hash), nil)

		case "check":
			if u.checker == nil {
				u.reply(ctx, uid, u.label("vk_no_checker"), nil)
				return
			}
			summary, err := u.checker.Validate(ctx)
			if err != nil {
				u.reply(ctx, uid, u.text("error", err.Error()), nil)
				return
			}
			u.reply(ctx, uid, u.text("vk_checked",
				summary.Checked, summary.Live, len(summary.NewlyDead), len(summary.Pruned)), nil)

		default:
			u.reply(ctx, uid, u.label("usage_vkhash"), nil)
		}
	})(ctx, client, update)
}

// onVKCode takes the verification code for a VK relogin in progress and hands it
// to the host-side helper. Admin-only: the code finishes a sign-in to the
// account whose calls carry the whole WG-over-VK pool.
func (u *UI) onVKCode(ctx context.Context, client *bot.Bot, update *models.Update) {
	u.adminOnly(func(ctx context.Context, uid int64, args []string) {
		code := ""
		if len(args) > 0 {
			code = args[0]
		}
		if code == "" {
			u.reply(ctx, uid, u.label("usage_vkcode"), nil)
			return
		}
		u.reply(ctx, uid, u.deliverVKReloginCode(code), nil)
	})(ctx, client, update)
}

// onPushConfig rebuilds every subscription and tells whoever changed.
//
// The manual counterpart to the refresh loop, for after a change an admin knows
// about and does not want to wait out the interval for.
func (u *UI) onPushConfig(ctx context.Context, client *bot.Bot, update *models.Update) {
	u.adminOnly(func(ctx context.Context, uid int64, args []string) {
		if u.refresher == nil {
			u.reply(ctx, uid, u.label("unavailable"), nil)
			return
		}
		reason := strings.Join(args, " ")
		notified, err := u.refresher.RefreshAll(ctx, reason)
		if err != nil {
			u.reply(ctx, uid, u.text("error", err.Error()), nil)
			return
		}
		u.reply(ctx, uid, u.text("pushed", notified), nil)
	})(ctx, client, update)
}

// requireID reads the one id an access command takes, complaining usefully
// rather than silently doing nothing.
func (u *UI) requireID(ctx context.Context, uid int64, args []string) (int64, error) {
	if len(args) < 1 {
		u.reply(ctx, uid, u.label("usage_id"), nil)
		return 0, errNoArgument
	}
	target, err := parseID(args[0])
	if err != nil {
		u.reply(ctx, uid, u.label("usage_id"), nil)
		return 0, err
	}
	return target, nil
}

// errNoArgument is internal: the user has already been told.
var errNoArgument = errNoArg{}

type errNoArg struct{}

func (errNoArg) Error() string { return "no argument" }
