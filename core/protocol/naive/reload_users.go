package naive

import (
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spaiter/spaiter-vpn/core/option"
)

// ReloadUsers implements adapter.UserReloader.
//
// Any edit is safe: a naive request is authenticated by user name and
// password and carries the name itself, so there is no index into the list
// for an in-flight connection to misresolve. A naive inbound cannot run with
// no users, so an empty list is refused and the inbound keeps its old one. //H
func (n *Inbound) ReloadUsers(options any) error {
	opts, ok := options.(*option.NaiveInboundOptions)
	if !ok {
		return E.New("naive: unexpected options type for user reload")
	}
	if len(opts.Users) == 0 {
		return E.New("naive: refusing to reload to an empty user list")
	}
	n.authenticator.Store(auth.NewAuthenticator(opts.Users))
	n.logger.Info("users reloaded: ", len(opts.Users), " total")
	return nil
}
