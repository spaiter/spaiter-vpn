package shadowsocks

import (
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/option"
)

// userName resolves an authenticated user index to a display name, bounds-
// checked: a reload (or the SSM UpdateUsers path) may have replaced the list
// since authentication. //H
func (h *MultiInbound) userName(userIndex int) string {
	users := h.users.Load()
	if users == nil || userIndex < 0 || userIndex >= len(*users) {
		return ""
	}
	return (*users)[userIndex].Name
}

// ReloadUsers implements adapter.UserReloader. Appends only — see
// adapter.UsersAppendOnly for why reordering cannot be done in place. //H
func (h *MultiInbound) ReloadUsers(options any) error {
	// The inbound registry stores options as a pointer (see
	// adapter/inbound.Register), so that is what apply hands over.
	optsPtr, ok := options.(*option.ShadowsocksInboundOptions)
	if !ok {
		return E.New("shadowsocks: unexpected options type for user reload")
	}
	opts := *optsPtr
	current := h.users.Load()
	if current == nil {
		return E.New("shadowsocks: inbound not initialized")
	}
	if !adapter.UsersAppendOnly(*current, opts.Users) {
		return E.New("shadowsocks: user list was not append-only, cannot reload in place")
	}
	if len(opts.Users) == len(*current) {
		return nil
	}
	err := h.service.UpdateUsersWithPasswords(
		common.MapIndexed(opts.Users, func(index int, _ option.ShadowsocksUser) int {
			return index
		}),
		common.Map(opts.Users, func(it option.ShadowsocksUser) string { return it.Password }),
	)
	if err != nil {
		return err
	}
	h.users.Store(&opts.Users)
	h.logger.Info("users reloaded: ", len(opts.Users)-len(*current), " added, ", len(opts.Users), " total")
	return nil
}
