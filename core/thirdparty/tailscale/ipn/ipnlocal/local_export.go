package ipnlocal

import (
	"sync/atomic"

	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/wgengine"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/wgengine/filter"
)

func (b *LocalBackend) ExportFilter() *atomic.Pointer[filter.Filter] {
	return &b.currentNode().filterAtomic
}

func (b *LocalBackend) ExportEngine() wgengine.Engine {
	return b.e
}
