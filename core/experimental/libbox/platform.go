package libbox

import C "github.com/spaiter/spaiter-vpn/core/constant"

type PlatformInterface interface {
	LocalDNSTransport() LocalDNSTransport
	UsePlatformAutoDetectInterfaceControl() bool
	AutoDetectInterfaceControl(fd int32) error
	OpenTun(options TunOptions) (int32, error)
	UseProcFS() bool
	FindConnectionOwner(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) (*ConnectionOwner, error)
	StartDefaultInterfaceMonitor(listener InterfaceUpdateListener) error
	CloseDefaultInterfaceMonitor(listener InterfaceUpdateListener) error
	GetInterfaces() (NetworkInterfaceIterator, error)
	UnderNetworkExtension() bool
	IncludeAllNetworks() bool
	ReadWIFIState() *WIFIState
	SystemCertificates() StringIterator
	ClearDNSCache()
	SendNotification(notification *Notification) error
	StartNeighborMonitor(listener NeighborUpdateListener) error
	CloseNeighborMonitor(listener NeighborUpdateListener) error
	RegisterMyInterface(name string)
}

type NeighborUpdateListener interface {
	UpdateNeighborTable(entries NeighborEntryIterator)
}

type ConnectionOwner struct {
	UserId              int32
	UserName            string
	ProcessPath         string
	androidPackageNames []string
}

func (c *ConnectionOwner) SetAndroidPackageNames(names StringIterator) {
	c.androidPackageNames = iteratorToArray[string](names)
}

func (c *ConnectionOwner) AndroidPackageNames() StringIterator {
	return newIterator(c.androidPackageNames)
}

type InterfaceUpdateListener interface {
	UpdateDefaultInterface(interfaceName string, interfaceIndex int32, isExpensive bool, isConstrained bool)
}

const (
	InterfaceTypeWIFI     = int32(C.InterfaceTypeWIFI)
	InterfaceTypeCellular = int32(C.InterfaceTypeCellular)
	InterfaceTypeEthernet = int32(C.InterfaceTypeEthernet)
	InterfaceTypeOther    = int32(C.InterfaceTypeOther)
)

type NetworkInterface struct {
	Index     int32
	MTU       int32
	Name      string
	Addresses StringIterator
	Flags     int32

	Type      int32
	DNSServer StringIterator
	Metered   bool
}

type WIFIState struct {
	SSID  string
	BSSID string
}

func NewWIFIState(wifiSSID string, wifiBSSID string) *WIFIState {
	return &WIFIState{wifiSSID, wifiBSSID}
}

type NetworkInterfaceIterator interface {
	Next() *NetworkInterface
	HasNext() bool
}

type Notification struct {
	Identifier string
	TypeName   string
	TypeID     int32
	Title      string
	Subtitle   string
	Body       string
	OpenURL    string
}

type OnDemandRule interface {
	Target() int32
	DNSSearchDomainMatch() StringIterator
	DNSServerAddressMatch() StringIterator
	InterfaceTypeMatch() int32
	SSIDMatch() StringIterator
	ProbeURL() string
}

type OnDemandRuleIterator interface {
	Next() OnDemandRule
	HasNext() bool
}

// BridgeOptions and BridgeSession are libbox-local, gomobile-safe mirrors of
// adapter.BridgeOptions and adapter.BridgeSession.
//
// They were removed by bf92faff ("feat(libbox): wire RoutedFlow, WARP/MASQUE
// cache slots, and shell/bridge stubs") while bridge_service_linux.go and
// bridge_stub.go kept using them, which left `go build ./...` broken on linux
// from 2026-07-11 onwards. It went unnoticed because the server binary is
// built from cmd/sing-box, which does not import libbox.
//
// They cannot simply be replaced by the adapter types: gomobile cannot export
// netip.Addr or plain int across the language boundary, so the bridge ports are
// strings to be parsed on this side and the widths are fixed at int32. That is
// exactly what bridge_service_linux.go expects -- string ports it parses with
// netip.ParseAddr, and FileDescriptor() returning int32.
//
// Note that bridge_service_darwin.go was migrated to the adapter types instead,
// so the two platforms currently expose different signatures for
// NewBridgeService. Only linux (and Android, which carries the linux build tag)
// is built here, so that inconsistency is left alone rather than fixed blind.
type BridgeOptions struct {
	BridgeName string
	MTU        int32
	Inet4Port  string
	Inet6Port  string
	Interface  string
	RuleIndex  int32
	RouteTable int32
}

type BridgeSession interface {
	FileDescriptor() int32
	Name() string
	Inet6Active() bool
	SetEgress(interfaceName string) error
	Close() error
}
