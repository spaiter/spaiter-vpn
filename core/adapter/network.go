package adapter

import (
	"encoding/hex"
	"net"
	"strings"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	C "github.com/spaiter/spaiter-vpn/core/constant"
)

type NetworkManager interface {
	Lifecycle
	Initialize(ruleSets []RuleSet)
	InterfaceFinder() control.InterfaceFinder
	UpdateInterfaces() error
	DefaultNetworkInterface() *NetworkInterface
	NetworkInterfaces() []NetworkInterface
	AutoDetectInterface() bool
	AutoDetectInterfaceFunc() control.Func
	ProtectFunc() control.Func
	DefaultOptions() NetworkOptions
	RegisterAutoRedirectOutputMark(mark uint32) error
	AutoRedirectOutputMark() uint32
	AutoRedirectOutputMarkFunc() control.Func
	NetworkMonitor() tun.NetworkUpdateMonitor
	InterfaceMonitor() tun.DefaultInterfaceMonitor
	PackageManager() tun.PackageManager
	NeedWIFIState() bool
	WIFIState() WIFIState
	UpdateWIFIState()
	ResetNetwork()
}

type NetworkOptions struct {
	BindInterface        string
	RoutingMark          uint32
	DomainResolver       string
	DomainResolveOptions DNSQueryOptions
	NetworkStrategy      *C.NetworkStrategy
	NetworkType          []C.InterfaceType
	FallbackNetworkType  []C.InterfaceType
	FallbackDelay        time.Duration
}

type InterfaceUpdateListener interface {
	InterfaceUpdated()
}

type WIFIState struct {
	SSID  string
	BSSID string
}

func NormalizeWIFIBSSID(bssid string) string {
	bssid = strings.TrimSpace(bssid)
	if bssid == "" {
		return ""
	}
	parsed, err := net.ParseMAC(bssid)
	if err == nil && len(parsed) == 6 {
		return parsed.String()
	}
	if len(bssid) == 12 {
		decoded, err := hex.DecodeString(bssid)
		if err == nil {
			return net.HardwareAddr(decoded).String()
		}
	}
	return bssid
}

type NetworkInterface struct {
	control.Interface
	Type        C.InterfaceType
	DNSServers  []string
	Expensive   bool
	Constrained bool
}
