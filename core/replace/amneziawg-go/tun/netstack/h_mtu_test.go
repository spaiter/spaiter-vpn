package netstack

import (
	"net/netip"
	"testing"
)

func TestHUpdateMTU(t *testing.T) {
	device, net, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("172.16.0.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	net.UpdateMTU(1200)
	if net.StackMTU() != 1200 {
		t.Fatalf("stack MTU %d, want 1200", net.StackMTU())
	}
}
