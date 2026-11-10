package shadowsocks

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

// ReloadUsers implements adapter.UserReloader. Appends only — see
// adapter.UsersAppendOnly for why reordering cannot be done in place. The user
// list is the one UpdateUsers (SSM API) and userName share, under usersAccess. //H
func (h *MultiInbound) ReloadUsers(options any) error {
	// The inbound registry stores options as a pointer (see
	// adapter/inbound.Register), so that is what apply hands over.
	optsPtr, ok := options.(*option.ShadowsocksInboundOptions)
	if !ok {
		return E.New("shadowsocks: unexpected options type for user reload")
	}
	opts := *optsPtr
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	current := h.users
	if !adapter.UsersAppendOnly(current, opts.Users) {
		return E.New("shadowsocks: user list was not append-only, cannot reload in place")
	}
	if len(opts.Users) == len(current) {
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
	h.users = opts.Users
	h.logger.Info("users reloaded: ", len(opts.Users)-len(current), " added, ", len(opts.Users), " total")
	return nil
}
