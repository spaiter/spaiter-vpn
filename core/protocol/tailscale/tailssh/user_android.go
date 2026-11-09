//go:build with_gvisor && android

package tailssh

import (
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spaiter/spaiter-vpn/core/adapter"
)

func resolveLocalUserNative(username string) (*adapter.PlatformUser, error) {
	return nil, E.New("native user resolution not supported on android")
}

func defaultShell() string {
	return "/system/bin/sh"
}
