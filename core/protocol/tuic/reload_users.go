package tuic

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/gofrs/uuid/v5"
)

// userName resolves an authenticated user index to a display name, bounds-
// checked: a reload may have replaced the list since authentication. //H
func (h *Inbound) userName(userID int) string {
	names := h.userNameList.Load()
	if names == nil || userID < 0 || userID >= len(*names) {
		return ""
	}
	return (*names)[userID]
}

// ReloadUsers implements adapter.UserReloader. Appends only — see
// adapter.UsersAppendOnly for why reordering cannot be done in place. //H
func (h *Inbound) ReloadUsers(options any) error {
	// The inbound registry stores options as a pointer (see
	// adapter/inbound.Register), so that is what apply hands over.
	optsPtr, ok := options.(*option.TUICInboundOptions)
	if !ok {
		return E.New("tuic: unexpected options type for user reload")
	}
	opts := *optsPtr
	current := h.userNameList.Load()
	if current == nil {
		return E.New("tuic: inbound not initialized")
	}
	names := make([]string, 0, len(opts.Users))
	ids := make([]int, 0, len(opts.Users))
	uuids := make([][16]byte, 0, len(opts.Users))
	passwords := make([]string, 0, len(opts.Users))
	for index, user := range opts.Users {
		if user.UUID == "" {
			return E.New("tuic: missing uuid for user ", index)
		}
		userUUID, err := uuid.FromString(user.UUID)
		if err != nil {
			return E.Cause(err, "tuic: invalid uuid for user ", index)
		}
		names = append(names, user.Name)
		ids = append(ids, index)
		uuids = append(uuids, userUUID)
		passwords = append(passwords, user.Password)
	}
	if !adapter.UsersAppendOnly(*current, names) {
		return E.New("tuic: user list was not append-only, cannot reload in place")
	}
	if len(names) == len(*current) {
		return nil
	}
	h.server.UpdateUsers(ids, uuids, passwords)
	h.userNameList.Store(&names)
	h.logger.Info("users reloaded: ", len(names)-len(*current), " added, ", len(names), " total")
	return nil
}
