package awg

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/assert"
)

// A UAPI dump as produced by device.IpcGetOperation: a flat key=value list in
// which `public_key` opens a peer section. //H
const uapiDump = `private_key=e8c1a0f1a0f1a0f1a0f1a0f1a0f1a0f1a0f1a0f1a0f1a0f1a0f1a0f1a0f1a0f1
listen_port=10863
public_key=aaaa0000000000000000000000000000000000000000000000000000000000aa
endpoint=203.0.113.7:51820
last_handshake_time_sec=1761000000
tx_bytes=1024
rx_bytes=2048
allowed_ip=10.10.0.2/32
public_key=bbbb0000000000000000000000000000000000000000000000000000000000bb
endpoint=[2001:db8::1]:1234
tx_bytes=0
rx_bytes=0
allowed_ip=10.10.0.3/32
allowed_ip=10.10.0.64/26
public_key=cccc0000000000000000000000000000000000000000000000000000000000cc
tx_bytes=0
rx_bytes=0
allowed_ip=10.10.0.9/32
`

func TestParsePeerRoutes(t *testing.T) {
	routes := parsePeerRoutes(uapiDump)

	// The third peer never completed a handshake, so it has no endpoint line
	// and must not contribute a route.
	assert.Len(t, routes, 3)

	byPrefix := make(map[string]string, len(routes))
	for _, route := range routes {
		byPrefix[route.prefix.String()] = route.endpoint.String()
	}
	assert.Equal(t, "203.0.113.7", byPrefix["10.10.0.2/32"])
	assert.Equal(t, "2001:db8::1", byPrefix["10.10.0.3/32"])
	assert.Equal(t, "2001:db8::1", byPrefix["10.10.0.64/26"])
	assert.NotContains(t, byPrefix, "10.10.0.9/32")
}

func TestParsePeerRoutesLongestPrefixWins(t *testing.T) {
	// 10.10.0.65 is matched by both the /26 and a more specific /32; the /32
	// must win, as it does in WireGuard's own allowed_ips lookup.
	dump := `public_key=aaaa
endpoint=203.0.113.7:51820
allowed_ip=10.10.0.64/26
public_key=bbbb
endpoint=198.51.100.9:51820
allowed_ip=10.10.0.65/32
`
	routes := parsePeerRoutes(dump)

	var (
		best     netip.Addr
		bestBits = -1
	)
	target := netip.MustParseAddr("10.10.0.65")
	for _, route := range routes {
		if route.prefix.Bits() > bestBits && route.prefix.Contains(target) {
			best, bestBits = route.endpoint, route.prefix.Bits()
		}
	}
	assert.Equal(t, "198.51.100.9", best.String())
}

func TestParsePeerRoutesMalformed(t *testing.T) {
	// Garbage, bare lines and unparseable values must be skipped, not panic.
	routes := parsePeerRoutes("public_key=aaaa\nendpoint=not-an-address\nallowed_ip=10.0.0.1/32\n" +
		"no-equals-sign\n\nallowed_ip=also-garbage\n")
	assert.Empty(t, routes)
}

func TestPeerEndpointForNilDevice(t *testing.T) {
	// Before Start() there is no device to query; must report "unknown"
	// rather than dereference nil.
	d := &Device{}
	_, ok := d.PeerEndpointFor(netip.MustParseAddr("10.10.0.2"))
	assert.False(t, ok)
}

func TestBlockablePeerEndpoint(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"203.0.113.7", true},
		{"2001:db8::1", true},
		// Private is allowed: a peer may legitimately sit on the LAN.
		{"192.168.1.50", true},
		// Loopback means a local shim (masque-wg / wdtt relay), not a peer.
		{"127.0.0.1", false},
		{"::1", false},
		{"0.0.0.0", false},
	} {
		assert.Equal(t, tc.want, adapter.BlockablePeerEndpoint(netip.MustParseAddr(tc.addr)), tc.addr)
	}
	assert.False(t, adapter.BlockablePeerEndpoint(netip.Addr{}), "zero value")
}
