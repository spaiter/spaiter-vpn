package awg

import (
	awgTun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/sagernet/sing/common/network"
	"github.com/spaiter/spaiter-vpn/core/adapter"
)

type tunAdapter interface {
	network.Dialer
	awgTun.Device
	adapter.SimpleLifecycle
}
