package netstack

import (
	"net/netip"
	"sync"
	"testing"
)

func TestCloseWhileWriting(t *testing.T) {
	for i := 0; i < 50; i++ {
		dev, tnet, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil, 1420)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := tnet.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.0.0.2:53"))
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; k < 100; k++ {
					if _, err := conn.Write([]byte("ping")); err != nil {
						return
					}
				}
			}()
		}
		buf := [][]byte{make([]byte, 2048)}
		sizes := []int{0}
		dev.Read(buf, sizes, 0)
		dev.Close()
		dev.Close()
		wg.Wait()
		if _, err := dev.Read(buf, sizes, 0); err == nil {
			t.Fatal("read after close succeeded")
		}
	}
}
