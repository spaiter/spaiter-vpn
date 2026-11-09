package selftest

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// These tests drive the host's real WireGuard, so they need root and the
// wireguard module. Anywhere else they skip: the run's logic is covered
// against a scripted tunnel in run_full_test.go, and
// test/acceptance/run-unit-tests-in-vm.sh runs these in a guest that has both.
func needWireGuard(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("creating a WireGuard interface needs root")
	}
	probe := netlink.NewLinkAttrs()
	probe.Name = "wgt-probe"
	link := &netlink.GenericLink{LinkAttrs: probe, LinkType: "wireguard"}
	if err := netlink.LinkAdd(link); err != nil {
		t.Skipf("no usable wireguard here: %v", err)
	}
	netlink.LinkDel(link)
}

func keyPair(t *testing.T) (wgtypes.Key, wgtypes.Key) {
	t.Helper()
	private, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return private, private.PublicKey()
}

// peerDevice is a second WireGuard interface standing in for the core's
// endpoint: it listens on a port and knows the client's key.
func peerDevice(t *testing.T, name string, port int, private, clientPublic wgtypes.Key, allowed netip.Prefix) {
	t.Helper()
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	link := &netlink.GenericLink{LinkAttrs: attrs, LinkType: "wireguard"}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() { netlink.LinkDel(link) })
	client, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, ipnet, _ := net.ParseCIDR(allowed.String())
	if err := client.ConfigureDevice(name, wgtypes.Config{
		PrivateKey: &private, ListenPort: &port, ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{PublicKey: clientPublic, ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{*ipnet}}},
	}); err != nil {
		t.Fatalf("configure %s: %v", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
}

func TestTunnelHandshakesWithARealPeerAndIsRemovedOnClose(t *testing.T) {
	needWireGuard(t)
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	port := int(freeUDPPort(t))
	subnet := netip.MustParsePrefix("10.98.0.0/24")
	peerDevice(t, "wgt-srv", port, serverPrivate, clientPublic, netip.MustParsePrefix("10.98.0.3/32"))

	tunnel, err := CreateTunnel(TunnelConfig{
		Name: "wgt-cli", MTU: 1280, PrivateKey: clientPrivate, ServerPublicKey: serverPublic,
		ServerEndpoint: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
		Address:        netip.MustParsePrefix("10.98.0.3/24"), AllowedIPs: subnet,
	})
	if err != nil {
		t.Fatal(err)
	}
	if link, err := netlink.LinkByName("wgt-cli"); err != nil || link.Attrs().MTU != 1280 || link.Attrs().OperState == netlink.OperDown && link.Attrs().Flags&net.FlagUp == 0 {
		t.Errorf("interface not as configured: %v, %v", link, err)
	}
	addrs, _ := netlink.AddrList(mustLink(t, "wgt-cli"), netlink.FAMILY_V4)
	found := false
	for _, a := range addrs {
		found = found || a.IPNet.String() == "10.98.0.3/24"
	}
	if !found {
		t.Errorf("tunnel address missing: %v", addrs)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := tunnel.WaitHandshake(ctx, 15*time.Second); err != nil {
		t.Fatalf("no handshake with a peer that knows our key: %v", err)
	}

	// A datagram from the tunnel address goes out without error.
	if err := tunnel.Send(netip.MustParseAddrPort("10.98.0.1:6881"), []byte("hello")); err != nil {
		t.Errorf("send: %v", err)
	}

	if err := tunnel.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := netlink.LinkByName("wgt-cli"); err == nil {
		t.Error("the interface survived Close")
	}
	// Closing again is harmless.
	if err := tunnel.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
}

func mustLink(t *testing.T, name string) netlink.Link {
	t.Helper()
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestTunnelReportsAPeerThatNeverAnswers(t *testing.T) {
	needWireGuard(t)
	_, serverPublic := keyPair(t)
	clientPrivate, _ := keyPair(t)
	tunnel, err := CreateTunnel(TunnelConfig{
		Name: "wgt-lone", MTU: 1280, PrivateKey: clientPrivate, ServerPublicKey: serverPublic,
		// Nothing listens here, so there can be no handshake.
		ServerEndpoint: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(freeUDPPort(t))},
		Address:        netip.MustParsePrefix("10.97.0.2/24"), AllowedIPs: netip.MustParsePrefix("10.97.0.0/24"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()

	err = tunnel.WaitHandshake(context.Background(), 600*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "no handshake on wgt-lone") {
		t.Errorf("err = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := tunnel.WaitHandshake(cancelled, time.Hour); err == nil {
		t.Error("a cancelled wait returned nil")
	}
}

func TestCreateTunnelRefusesAnInterfaceThatAlreadyExists(t *testing.T) {
	needWireGuard(t)
	_, serverPublic := keyPair(t)
	clientPrivate, _ := keyPair(t)
	cfg := TunnelConfig{
		Name: "wgt-dup", MTU: 1280, PrivateKey: clientPrivate, ServerPublicKey: serverPublic,
		ServerEndpoint: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9},
		Address:        netip.MustParsePrefix("10.96.0.2/24"), AllowedIPs: netip.MustParsePrefix("10.96.0.0/24"),
	}
	first, err := CreateTunnel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := CreateTunnel(cfg); err == nil || !strings.Contains(err.Error(), "already exists") || !strings.Contains(err.Error(), "ip link del wgt-dup") {
		t.Errorf("second create: %v", err)
	}
	// The failed attempt must not have removed the first interface.
	if _, err := netlink.LinkByName("wgt-dup"); err != nil {
		t.Errorf("the existing interface was disturbed: %v", err)
	}
}

func TestCreateTunnelRemovesWhatItHalfBuilt(t *testing.T) {
	needWireGuard(t)
	_, serverPublic := keyPair(t)
	clientPrivate, _ := keyPair(t)
	// An IPv6 address on an interface below the IPv6 minimum MTU: the kernel
	// refuses it after the interface exists, and the interface must be taken
	// down again or the next run finds it and refuses to start.
	_, err := CreateTunnel(TunnelConfig{
		Name: "wgt-half", MTU: 1000, PrivateKey: clientPrivate, ServerPublicKey: serverPublic,
		ServerEndpoint: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9},
		Address:        netip.MustParsePrefix("fd95::2/64"), AllowedIPs: netip.MustParsePrefix("fd95::/64"),
	})
	if err == nil {
		t.Skip("this kernel accepts an IPv6 address on a 1000-byte MTU; nothing half-built to clean up")
	}
	if _, linkErr := netlink.LinkByName("wgt-half"); linkErr == nil {
		t.Errorf("a failed CreateTunnel (err=%v) left its interface behind", err)
		netlink.LinkDel(mustLink(t, "wgt-half"))
	}
}
