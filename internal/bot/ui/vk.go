package ui

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/spaiter/spaiter-vpn/internal/bot/external"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

// Validator checks a VK call link.
type Validator interface {
	Check(ctx context.Context, hashes []string) (map[string]external.HashStatus, error)
}

// SetValidator attaches the checker used for links users submit.
func (u *UI) SetValidator(v Validator) { u.validator = v }

// submitVKLink validates a link a user sent and adds it to the pool.
//
// Checked before it is accepted, because a dead link in the pool is worse than
// a missing one: it goes out in everybody's subscription and every client wastes
// a connection attempt on it.
func (u *UI) submitVKLink(ctx context.Context, raw string, uid int64) (string, error) {
	hash := NormalizeVKHash(raw)
	if hash == "" {
		return "", errors.New(u.label("vk_not_a_link"))
	}

	pool, err := u.store.VKHashes()
	if err != nil {
		return "", err
	}
	if entry, present := pool[hash]; present && entry.Status == "ok" {
		return u.text("vk_already"), nil
	}

	if u.validator == nil {
		return "", errors.New(u.label("vk_no_checker"))
	}
	verdicts, err := u.validator.Check(ctx, []string{hash})
	if err != nil {
		return "", err
	}
	verdict, answered := verdicts[hash]
	if !answered {
		return "", errors.New(u.label("vk_no_verdict"))
	}

	switch {
	case verdict.Status == "ok":
		now := state.Now()
		err := u.store.UpdateVKHashes(func(fresh state.VKHashes) error {
			previous := fresh[hash]
			added := previous.Added
			if added == "" {
				added = now
			}
			fresh[hash] = state.VKHash{
				Added: added, Status: "ok", Checked: now, Detail: verdict.Detail,
				// Attributed so the submitter can be told when it dies: they
				// are the only person who can create a replacement.
				By: uid, ByName: u.access.DisplayName(uid),
			}
			return nil
		})
		if err != nil {
			return "", err
		}
		u.log.Info("a user added a VK call link", "uid", uid)
		return u.text("vk_accepted"), nil

	case !verdict.Conclusive():
		// A captcha or a rate limit says nothing about the link. Rejecting it
		// would turn away a perfectly good call because VK was in a mood.
		return u.text("vk_try_again", verdict.Status), nil

	default:
		return "", errors.New(u.text("vk_dead", verdict.Detail))
	}
}

// vkReloginAwaitingCode reports whether the host-side relogin helper is paused
// waiting for the verification code. The helper writes its state to a file both
// sides share through the data directory; any read error means "not waiting",
// so a missing or unreadable status never makes the bot accept a stray code.
func (u *UI) vkReloginAwaitingCode() bool {
	raw, err := os.ReadFile(u.cfg.Paths.VKReloginStatus())
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(raw)) == "awaiting-code"
}

// sixDigits returns the code if raw is exactly six digits (after trimming), or
// "" otherwise. It does not strip non-digits: a message that is not a bare code
// should not be mistaken for one, so "1 2 3 4 5 6" or "code 123456" is rejected.
func sixDigits(raw string) string {
	code := strings.TrimSpace(raw)
	if len(code) != 6 {
		return ""
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return code
}

// deliverVKReloginCode hands the verification code to the waiting relogin helper
// by writing it where the helper reads it, atomically. It accepts only a
// six-digit code and only while a relogin is actually waiting, so a number typed
// at any other time is turned away instead of landing in the file. It returns
// the message to show the admin.
func (u *UI) deliverVKReloginCode(raw string) string {
	code := sixDigits(raw)
	if code == "" {
		return u.label("vk_code_bad")
	}
	if !u.vkReloginAwaitingCode() {
		return u.label("vk_code_not_waiting")
	}
	tmp := u.cfg.Paths.VKReloginCode() + ".tmp"
	if err := os.WriteFile(tmp, []byte(code+"\n"), 0o600); err != nil {
		u.log.Error("could not stage the VK relogin code", "error", err)
		return u.text("error", err.Error())
	}
	if err := os.Rename(tmp, u.cfg.Paths.VKReloginCode()); err != nil {
		u.log.Error("could not deliver the VK relogin code", "error", err)
		return u.text("error", err.Error())
	}
	u.log.Info("delivered a VK relogin code to the helper")
	return u.label("vk_code_accepted")
}

// NormalizeVKHash extracts the join code from whatever a user pasted.
//
// It mirrors the client core's normalizeVKJoinHash, and the two have to agree:
// a code the bot stores and the client cannot parse is a pool entry that fails
// for everyone. Accepts a full link or a bare code, and rejects any other URL
// rather than treating its last path segment as a code.
func NormalizeVKHash(raw string) string {
	text := strings.TrimSpace(raw)
	text = strings.Trim(text, `<>"'`)
	if text == "" {
		return ""
	}

	const marker = "/call/join/"
	lowered := strings.ToLower(text)
	if index := strings.Index(lowered, marker); index >= 0 {
		text = text[index+len(marker):]
	} else if strings.HasPrefix(lowered, "http://") || strings.HasPrefix(lowered, "https://") {
		return "" // some other link, not a call
	}

	// Anything after the code -- a query, a fragment, a trailing segment -- is
	// not part of it.
	if cut := strings.IndexAny(text, "?#/"); cut >= 0 {
		text = text[:cut]
	}
	return strings.Trim(strings.TrimSpace(text), "/")
}

// adoptHash records a bundle's structural hash so the next refresh does not
// announce a change to someone who has just been handed the thing.
func (u *UI) adoptHash(token string, bundle []byte) error {
	hash, err := structuralHash(bundle)
	if err != nil {
		return err
	}
	return u.store.UpdateSubscriptions(func(fresh state.Subscriptions) error {
		meta, ok := fresh[token]
		if !ok {
			return nil
		}
		meta.LastHash = hash
		fresh[token] = meta
		return nil
	})
}

// idList renders a list of ids for a message.
func idList(ids []int64, name func(int64) string) string {
	if len(ids) == 0 {
		return "—"
	}
	var out strings.Builder
	for _, id := range ids {
		out.WriteString("`" + strconv.FormatInt(id, 10) + "` " + name(id) + "\n")
	}
	return out.String()
}
