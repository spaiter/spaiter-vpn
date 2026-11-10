package hysteria2

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
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
	optsPtr, ok := options.(*option.Hysteria2InboundOptions)
	if !ok {
		return E.New("hysteria2: unexpected options type for user reload")
	}
	opts := *optsPtr
	current := h.userNameList.Load()
	if current == nil {
		return E.New("hysteria2: inbound not initialized")
	}
	names := make([]string, 0, len(opts.Users))
	ids := make([]int, 0, len(opts.Users))
	passwords := make([]string, 0, len(opts.Users))
	for index, user := range opts.Users {
		names = append(names, user.Name)
		ids = append(ids, index)
		passwords = append(passwords, user.Password)
	}
	if !adapter.UsersAppendOnly(*current, names) {
		return E.New("hysteria2: user list was not append-only, cannot reload in place")
	}
	if len(names) == len(*current) {
		return nil
	}
	h.service.UpdateUsers(ids, passwords)
	h.userNameList.Store(&names)
	h.logger.Info("users reloaded: ", len(names)-len(*current), " added, ", len(names), " total")
	return nil
}
