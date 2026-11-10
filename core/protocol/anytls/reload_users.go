package anytls

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

// ReloadUsers implements adapter.UserReloader.
//
// Unlike the index-based inbounds this accepts any edit, including removals:
// anytls hands the user's name to the handler through the auth context, so
// there is no index for an in-flight connection to misresolve. The service
// publishes the new map in one atomic store. //H
func (h *Inbound) ReloadUsers(options any) error {
	// The inbound registry stores options as a pointer.
	optsPtr, ok := options.(*option.AnyTLSInboundOptions)
	if !ok {
		return E.New("anytls: unexpected options type for user reload")
	}
	err := h.service.UpdateUsers(
		common.Map(optsPtr.Users, func(it option.AnyTLSUser) string { return it.Name }),
		common.Map(optsPtr.Users, func(it option.AnyTLSUser) string { return it.Password }),
	)
	if err != nil {
		return err
	}
	h.logger.Info("users reloaded: ", len(optsPtr.Users), " total")
	return nil
}
