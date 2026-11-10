package netstack

import (
	"net/netip"
	"testing"
	"time"
)

// Replies that came before ReadFrom is called are read, not waited for.
func TestHPingReadQueued(t *testing.T) {
	device, net, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	conn, err := net.DialPingAddr(netip.Addr{}, netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for sequence := range 3 {
		request := make([]byte, 64)
		request[0], request[7] = 8, byte(sequence)
		if _, err := conn.Write(request); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond) // the replies are queued
	conn.SetReadDeadline(time.Now().Add(time.Second))
	reply := make([]byte, 64)
	for i := range 3 {
		if _, _, err := conn.ReadFrom(reply); err != nil {
			t.Fatalf("reply %d: %v", i, err)
		}
	}
}
