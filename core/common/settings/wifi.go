package settings

import "github.com/spaiter/spaiter-vpn/core/adapter"

type WIFIMonitor interface {
	ReadWIFIState() adapter.WIFIState
	Start() error
	Close() error
}
