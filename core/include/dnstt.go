//go:build with_dnstt

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/hiddify/dnstt"
	"github.com/sagernet/sing-box/protocol/hiddify/masterdns"
	"github.com/sagernet/sing-box/protocol/hiddify/soar"
)

// dnstt, masterdns and soar are the consumers of
// github.com/hiddify/hmrd_multi_resolver_dns (through common/dnspool), which
// carries no license grant (see THIRD-PARTY-NOTICES.md §6). They are therefore
// excluded from the default build and from every published artifact, and are
// compiled only on request. //H
func registerDNSResolverOutbounds(registry *outbound.Registry) {
	dnstt.RegisterOutbound(registry)
	masterdns.RegisterOutbound(registry)
	soar.RegisterOutbound(registry)
}
