package vless

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

// pushUsers programs a user list into the running service. The service keys
// users by index, which is also what it hands back to the connection handlers
// through the auth context. //H
func pushUsers(service *vless.Service[int], users []option.VLESSUser) {
	service.UpdateUsers(
		common.MapIndexed(users, func(index int, _ option.VLESSUser) int {
			return index
		}),
		common.Map(users, func(it option.VLESSUser) string { return it.UUID }),
		common.Map(users, func(it option.VLESSUser) string { return it.Flow }),
	)
}

// userName resolves the index the service authenticated to a display name.
// Reads the snapshot once and bounds-checks it: a reload may have replaced the
// list between authentication and this call. //H
func (h *Inbound) userName(userIndex int) string {
	users := h.users.Load()
	if users == nil || userIndex < 0 || userIndex >= len(*users) {
		return ""
	}
	return (*users)[userIndex].Name
}

// ReloadUsers implements adapter.UserReloader: it adds users to the running
// inbound without dropping its connections. Only appends are accepted —
// reordering or removing would invalidate the indexes in-flight connections
// are already holding (see adapter.UsersAppendOnly), so for those the caller
// falls back to recreating the inbound. //H
func (h *Inbound) ReloadUsers(options any) error {
	// The inbound registry stores options as a pointer (see
	// adapter/inbound.Register), so that is what apply hands over.
	optsPtr, ok := options.(*option.VLESSInboundOptions)
	if !ok {
		return E.New("vless: unexpected options type for user reload")
	}
	opts := *optsPtr
	current := h.users.Load()
	if current == nil {
		return E.New("vless: inbound not initialized")
	}
	if !adapter.UsersAppendOnly(*current, opts.Users) {
		return E.New("vless: user list was not append-only, cannot reload in place")
	}
	if len(opts.Users) == len(*current) {
		return nil
	}
	// Program the service first: until it knows the credentials the new users
	// cannot authenticate, and the names are only needed once they can.
	pushUsers(h.service, opts.Users)
	h.users.Store(&opts.Users)
	h.logger.Info(F.ToString("users reloaded: ", len(opts.Users)-len(*current), " added, ", len(opts.Users), " total"))
	return nil
}
