package anytls

import (
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spaiter/spaiter-vpn/core/option"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/sing-anytls"
)

// ReloadUsers implements adapter.UserReloader.
//
// Unlike the index-based inbounds this accepts any edit, including removals:
// anytls hands the user's name to the handler through the auth context, so
// there is no index for an in-flight connection to misresolve. //H
func (h *Inbound) ReloadUsers(options any) error {
	// The inbound registry stores options as a pointer.
	optsPtr, ok := options.(*option.AnyTLSInboundOptions)
	if !ok {
		return E.New("anytls: unexpected options type for user reload")
	}
	users := common.Map(optsPtr.Users, func(it option.AnyTLSUser) anytls.User {
		return (anytls.User)(it)
	})
	h.service.UpdateUsers(users)
	h.logger.Info("users reloaded: ", len(users), " total")
	return nil
}
