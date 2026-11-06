package version

import "github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/types/lazy"

func SetVersion(version string) {
	short = lazy.SyncValue[string]{}
	short.MustSet(version)
	long = lazy.SyncValue[string]{}
	long.MustSet(version)
}
