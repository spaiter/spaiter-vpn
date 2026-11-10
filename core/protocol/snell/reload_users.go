package snell

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// multiUserService is implemented by the v5 and v6 MultiService variants. The
// single-user services have no user list to reload. //H
type multiUserService interface {
	UpdateUsers(users []int, keys [][]byte) error
}

func (h *Inbound) hasUsers() bool {
	users := h.users.Load()
	return users != nil && len(*users) > 0
}

// userName resolves an authenticated user index to a display name, bounds-
// checked: a reload may have replaced the list since authentication. //H
func (h *Inbound) userName(userIndex int) string {
	users := h.users.Load()
	if users == nil || userIndex < 0 || userIndex >= len(*users) {
		return ""
	}
	return (*users)[userIndex].Name
}

// ReloadUsers implements adapter.UserReloader. Appends only — see
// adapter.UsersAppendOnly for why reordering cannot be done in place. //H
func (h *Inbound) ReloadUsers(options any) error {
	// The inbound registry stores options as a pointer (see
	// adapter/inbound.Register), so that is what apply hands over.
	optsPtr, ok := options.(*option.SnellInboundOptions)
	if !ok {
		return E.New("snell: unexpected options type for user reload")
	}
	opts := *optsPtr
	current := h.users.Load()
	if current == nil {
		return E.New("snell: inbound not initialized")
	}
	// Going from no users to users (or back) swaps the service implementation
	// itself, which only a rebuild can do.
	if len(*current) == 0 || len(opts.Users) == 0 {
		return E.New("snell: cannot add or drop the user list in place")
	}
	service, ok := h.service.(multiUserService)
	if !ok {
		return E.New("snell: service does not support user updates")
	}
	if !adapter.UsersAppendOnly(*current, opts.Users) {
		return E.New("snell: user list was not append-only, cannot reload in place")
	}
	if len(opts.Users) == len(*current) {
		return nil
	}
	userList := make([]int, len(opts.Users))
	keyList := make([][]byte, len(opts.Users))
	for index, user := range opts.Users {
		userList[index] = index
		keyList[index] = []byte(user.UserKey)
	}
	if err := service.UpdateUsers(userList, keyList); err != nil {
		return err
	}
	h.users.Store(&opts.Users)
	h.logger.Info("users reloaded: ", len(opts.Users)-len(*current), " added, ", len(opts.Users), " total")
	return nil
}
