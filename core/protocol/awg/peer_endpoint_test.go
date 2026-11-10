package awg

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

// The router reaches the peer-endpoint lookup through a type assertion on the
// endpoint, and Endpoint only satisfies it via the embedded *awg.Device — so
// dropping that embedding would silently disable XDP blocking for WireGuard
// peers instead of failing to build. //H
func TestEndpointImplementsPeerEndpointResolver(t *testing.T) {
	var _ adapter.PeerEndpointResolver = (*Endpoint)(nil)
}
