package shadowtls

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

// ReloadUsers implements adapter.UserReloader.
//
// Accepts any edit, including removals: shadowtls resolves the user during the
// ClientHello check and passes the name through the auth context, so no
// in-flight connection is holding an index into the list. //H
func (h *Inbound) ReloadUsers(options any) error {
	// The inbound registry stores options as a pointer.
	optsPtr, ok := options.(*option.ShadowTLSInboundOptions)
	if !ok {
		return E.New("shadowtls: unexpected options type for user reload")
	}
	// v1/v2 authenticate with a single password and carry no user list;
	// swapping one in would not take effect.
	if optsPtr.Version < 3 {
		return E.New("shadowtls: version ", optsPtr.Version, " has no user list to reload")
	}
	if len(optsPtr.Users) == 0 {
		return E.New("shadowtls: refusing to reload an empty user list")
	}
	users := common.Map(optsPtr.Users, func(it option.ShadowTLSUser) shadowtls.User {
		return (shadowtls.User)(it)
	})
	h.service.UpdateUsers(users)
	h.logger.Info("users reloaded: ", len(users), " total")
	return nil
}
