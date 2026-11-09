package libbox

import (
	"context"
	"math"
	"runtime/debug"

	"github.com/spaiter/spaiter-vpn/core/adapter"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/service/oomkiller"
)

func FromContext(ctx context.Context, platformInterface PlatformInterface) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return baseContextWithParent(ctx, platformInterface)
}

func WrapPlatformInterface(platformInterface PlatformInterface) adapter.PlatformInterface {
	if platformInterface == nil {
		return nil
	}
	return &platformInterfaceWrapper{
		iif:       platformInterface,
		useProcFS: platformInterface.UseProcFS(),
	}
}

func SetMemoryLimit(enabled bool) {
	if !enabled {
		debug.SetMemoryLimit(math.MaxInt64)
		return
	}
	limit := sOOMMemoryLimit
	if limit == 0 && C.IsIos {
		limit = oomkiller.DefaultAppleNetworkExtensionMemoryLimit
	}
	if limit > 0 {
		debug.SetMemoryLimit(limit * 3 / 4)
	} else {
		debug.SetMemoryLimit(math.MaxInt64)
	}
}
