//go:build with_gvisor && tvos

package tailscale

import (
	_ "unsafe"

	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/types/lazy"
)

//go:linkname isAppleTV github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/version.isAppleTV
var isAppleTV lazy.SyncValue[bool]

func init() {
	isAppleTV.Set(true)
}
