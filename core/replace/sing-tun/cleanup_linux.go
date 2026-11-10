//go:build linux

package tun

import (
	"github.com/sagernet/nftables"
)

// CleanupLeftovers takes down what a TUN with these options set up in the host and could not take
// down itself, because its process was killed: the policy rules of auto_route, and the redirect
// rules and the nftables table (or iptables chains) of auto_redirect. Left behind, they keep the
// host's traffic going to a TUN and a listener that are gone: the host has no network until a TUN
// starts again. The TUN device itself goes with the process.
//
// Only the fields that name these are read: IPRoute2RuleIndex, IPRoute2AutoRedirectFallbackRuleIndex,
// AutoRedirectMarkMode and AutoRedirectTProxyMark; tableName is the auto_redirect table's name.
func CleanupLeftovers(options Options, tableName string) {
	if options.IPRoute2RuleIndex == 0 {
		options.IPRoute2RuleIndex = DefaultIPRoute2RuleIndex
	}
	if options.IPRoute2AutoRedirectFallbackRuleIndex == 0 {
		options.IPRoute2AutoRedirectFallbackRuleIndex = DefaultIPRoute2AutoRedirectFallbackRuleIndex
	}
	options.AutoRoute = true
	options.FileDescriptor = 0
	_ = (&NativeTun{options: options}).unsetRules()
	if !options.AutoRedirectMarkMode || tableName == "" {
		return
	}
	redirect := &autoRedirect{tunOptions: &options, tableName: tableName}
	redirect.cleanupStaleRouteRules(redirectRouteRulePriority, 0)
	if options.AutoRedirectTProxyMark != 0 {
		redirect.cleanupStaleRouteRules(redirectRouteRulePriority, options.AutoRedirectTProxyMark)
	}
	if nft, err := nftables.New(); err == nil {
		nft.DelTable(&nftables.Table{Name: tableName, Family: nftables.TableFamilyINet})
		_ = nft.Flush()
		_ = nft.CloseLasting()
	}
	redirect.cleanupIPTables()
}
