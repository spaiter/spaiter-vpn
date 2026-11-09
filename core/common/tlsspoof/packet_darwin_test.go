package tlsspoof

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildSpoofTCPSegment only exists on darwin, where the raw socket wants a TCP
// segment rather than a whole IP frame, so its test lives beside it.
func TestBuildSpoofTCPSegment_EncodesWithoutIPHeader(t *testing.T) {
	t.Parallel()
	src := netip.MustParseAddrPort("[fe80::1]:54321")
	dst := netip.MustParseAddrPort("[2606:4700::1]:443")
	payload := []byte("fake-client-hello")
	segment, err := buildSpoofTCPSegment(MethodWrongSequence, src, dst, 1000, 2000, 0, payload)
	require.NoError(t, err)
	require.Equal(t, tcpHeaderLen+len(payload), len(segment),
		"segment must be TCP header + payload, no IP header")
}
