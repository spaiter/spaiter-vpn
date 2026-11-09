package selftest

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
)

func TestSendWritesFromTheTunnelAddress(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback UDP: %v", err)
	}
	defer listener.Close()

	tunnel := &Tunnel{Name: "t", Address: netip.MustParsePrefix("127.0.0.1/8")}
	destination := listener.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := tunnel.Send(destination, []byte("probe")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	listener.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, from, err := listener.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "probe" || !from.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("received %q from %v, %v", buf[:n], from, err)
	}
}

func TestSendFromAnAddressTheHostDoesNotHaveFails(t *testing.T) {
	tunnel := &Tunnel{Name: "t", Address: netip.MustParsePrefix("203.0.113.9/24")}
	err := tunnel.Send(netip.MustParseAddrPort("127.0.0.1:9"), []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "dial") {
		t.Errorf("error = %v", err)
	}
}

func TestClosingATunnelThatWasNeverBuiltIsHarmless(t *testing.T) {
	tunnel := &Tunnel{Name: "t"}
	for range 2 {
		if err := tunnel.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}
}

func TestWaitingForAHandshakeOnAMissingInterfaceTimesOutWithTheCause(t *testing.T) {
	client, err := wgctrl.New()
	if err != nil {
		t.Skipf("no wireguard control socket: %v", err)
	}
	tunnel := &Tunnel{Name: "spaiter-absent0", client: client}
	defer tunnel.Close()

	err = tunnel.WaitHandshake(context.Background(), 300*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "no handshake on spaiter-absent0") {
		t.Errorf("timeout: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := tunnel.WaitHandshake(ctx, time.Minute); err != context.Canceled {
		t.Errorf("cancelled: %v", err)
	}
}

func TestCreatingAnInterfaceNeedsRootAndSaysSo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root would really create the interface; the VM run covers that")
	}
	_, err := CreateTunnel(TunnelConfig{Name: "spaiter-nonroot0", MTU: 1280})
	if err == nil || !strings.Contains(err.Error(), "needs root") {
		t.Errorf("error = %v", err)
	}
}
