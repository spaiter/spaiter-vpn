// Package ui is the Telegram front end: who may ask for what, and what they
// get back.
//
// Every string shown to a user comes from the configuration rather than from
// here, which is what makes the deployment re-brandable. What stays in code is
// the part that must not be configurable: who is allowed.
package ui

import (
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

// Access decides who may ask for a configuration.
type Access struct {
	store *state.Store
	log   *slog.Logger
}

// NewAccess builds the access check.
func NewAccess(store *state.Store, log *slog.Logger) *Access {
	if log == nil {
		log = slog.Default()
	}
	return &Access{store: store, log: log}
}

// IsAdmin reports whether a user administers this deployment.
//
// A bot with no admin has none until someone presents the one-time code an
// operator issued on the server (`spaiter-vpn bot claim-code`). It used to
// hand the role to the first person who messaged it, which made anyone who
// found the bot before its owner did the owner.
func (a *Access) IsAdmin(uid int64) bool {
	admins, err := a.store.Admins()
	if err != nil {
		// Refusing is the only safe answer: an unreadable list is not an
		// empty one.
		a.log.Error("could not read the admin list; refusing admin access", "error", err)
		return false
	}
	return slices.Contains(admins, uid)
}

// HasAdmin reports whether anyone administers this deployment yet.
func (a *Access) HasAdmin() bool {
	admins, err := a.store.Admins()
	return err != nil || len(admins) > 0
}

// Claim adopts the deployment for uid if code is the outstanding claim code.
func (a *Access) Claim(code string, uid int64) bool {
	ok, err := a.store.Claim(code, uid, time.Now())
	if err != nil {
		a.log.Error("could not process an admin claim", "uid", uid, "error", err)
		return false
	}
	if ok {
		a.log.Warn("the admin role was claimed with a one-time code", "uid", uid)
	} else {
		a.log.Warn("an admin claim was refused", "uid", uid)
	}
	return ok
}

// IsAllowed reports whether a user may be handed a configuration.
func (a *Access) IsAllowed(uid int64) bool {
	if a.IsAdmin(uid) {
		return true
	}
	whitelist, err := a.store.Whitelist()
	if err != nil {
		a.log.Error("could not read the whitelist; refusing access", "error", err)
		return false
	}
	return slices.Contains(whitelist, uid)
}

// Register records who someone is, next to the numeric id used as their account
// name on every inbound.
//
// Without it an admin reviewing the user list sees a column of numbers. The
// numeric id is what the core knows them by, so this is the only place the two
// are tied together.
func (a *Access) Register(user state.User) {
	if err := a.store.Register(user); err != nil {
		// Not fatal: being unable to record a display name must not stop
		// someone from getting a working configuration.
		a.log.Warn("could not record a user", "uid", user.ID, "error", err)
	}
}

// RequestAccess records that someone is waiting for approval.
func (a *Access) RequestAccess(uid int64) {
	if err := a.store.AddPending(uid); err != nil {
		a.log.Warn("could not record an access request", "uid", uid, "error", err)
	}
}

// Approve puts a user on the whitelist and clears their request.
func (a *Access) Approve(uid int64) error {
	if err := a.store.Allow(uid); err != nil {
		return err
	}
	return a.store.PopPending(uid)
}

// Reject clears a request without granting anything.
func (a *Access) Reject(uid int64) error { return a.store.PopPending(uid) }

// Revoke takes a user off the whitelist.
//
// Their accounts stay on the server: removing them is a separate, deliberate
// act, because an account deleted by mistake cannot be restored -- the
// credentials were generated once and only the client still has them.
func (a *Access) Revoke(uid int64) error { return a.store.Deny(uid) }

// DisplayName is how a user is shown to an admin.
func (a *Access) DisplayName(uid int64) string {
	users, err := a.store.Users()
	if err != nil {
		return ""
	}
	user, ok := users[strconv.FormatInt(uid, 10)]
	if !ok {
		return ""
	}
	name := user.FirstName
	if user.LastName != "" {
		if name != "" {
			name += " "
		}
		name += user.LastName
	}
	if user.Username == "" {
		return name
	}
	if name == "" {
		return "@" + user.Username
	}
	return name + " @" + user.Username
}

// Pending lists the users waiting for approval.
func (a *Access) Pending() []int64 {
	pending, err := a.store.Pending()
	if err != nil {
		a.log.Warn("could not read the pending list", "error", err)
		return nil
	}
	ids := make([]int64, 0, len(pending))
	for key := range pending {
		id, err := strconv.ParseInt(key, 10, 64)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// Whitelist lists the approved users.
func (a *Access) Whitelist() []int64 {
	whitelist, err := a.store.Whitelist()
	if err != nil {
		a.log.Warn("could not read the whitelist", "error", err)
		return nil
	}
	slices.Sort(whitelist)
	return whitelist
}

// Admins lists the administrators without claiming the role for anyone.
func (a *Access) Admins() []int64 {
	admins, err := a.store.Admins()
	if err != nil {
		return nil
	}
	return admins
}

// formatID renders an id for a message, where it is shown as code so an admin
// can copy it.
func formatID(uid int64) string { return fmt.Sprintf("`%d`", uid) }
