//go:build with_dnstt

package include

import (
	"github.com/spaiter/spaiter-vpn/core/adapter/outbound"
	"github.com/spaiter/spaiter-vpn/core/adapter/service"
	"github.com/spaiter/spaiter-vpn/core/protocol/hiddify/dnstt"
	smartdnspool "github.com/spaiter/spaiter-vpn/core/service/smart_dns_pool"
)

// dnstt and smart_dns_pool are the only consumers of
// github.com/hiddify/hmrd_multi_resolver_dns, which carries no license grant
// (see THIRD-PARTY-NOTICES.md §6). They are therefore excluded from the default
// build and from every published artifact, and are compiled only on request.
func registerDNSTTOutbound(registry *outbound.Registry) {
	dnstt.RegisterOutbound(registry)
}

func registerSmartDNSPoolService(registry *service.Registry) {
	smartdnspool.RegisterService(registry)
}
