package awg

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/json/badoption"
	"github.com/spaiter/spaiter-vpn/core/option"

	"github.com/stretchr/testify/assert"
)

func peer(name string, prefixes ...string) option.AwgPeerOptions {
	var allowed badoption.Listable[netip.Prefix]
	for _, prefix := range prefixes {
		allowed = append(allowed, netip.MustParsePrefix(prefix))
	}
	return option.AwgPeerOptions{Name: name, AllowedIPs: allowed}
}

func TestPeerNameTableLookup(t *testing.T) {
	table := newPeerNameTable([]option.AwgPeerOptions{
		peer("alice", "10.10.0.4/32"),
		peer("bob", "10.10.0.8/32", "fd00::8/128"),
	})

	assert.Equal(t, "alice", table.Lookup(netip.MustParseAddr("10.10.0.4")))
	assert.Equal(t, "bob", table.Lookup(netip.MustParseAddr("10.10.0.8")))
	assert.Equal(t, "bob", table.Lookup(netip.MustParseAddr("fd00::8")))
	// An address belonging to no named peer stays unattributed rather than
	// being misreported as someone else's traffic.
	assert.Empty(t, table.Lookup(netip.MustParseAddr("10.10.0.9")))
	assert.Empty(t, table.Lookup(netip.Addr{}))
}

func TestPeerNameTableLongestPrefixWins(t *testing.T) {
	// A peer holding a wide range must not shadow a peer with a specific /32.
	table := newPeerNameTable([]option.AwgPeerOptions{
		peer("router", "10.10.0.0/24"),
		peer("laptop", "10.10.0.7/32"),
	})

	assert.Equal(t, "laptop", table.Lookup(netip.MustParseAddr("10.10.0.7")))
	assert.Equal(t, "router", table.Lookup(netip.MustParseAddr("10.10.0.8")))
}

func TestPeerNameTableEmptyWhenNoNames(t *testing.T) {
	// Existing configs name no peers at all; the table must then be nil so the
	// lookup costs nothing and metadata.User stays empty, as before.
	assert.Nil(t, newPeerNameTable([]option.AwgPeerOptions{peer("", "10.10.0.2/32")}))
	assert.Nil(t, newPeerNameTable(nil))
}

func TestPeerNameTableNilLookup(t *testing.T) {
	var table *peerNameTable
	assert.Empty(t, table.Lookup(netip.MustParseAddr("10.10.0.2")))
}

func TestPeerNameTableIgnoresUnnamedPeers(t *testing.T) {
	table := newPeerNameTable([]option.AwgPeerOptions{
		peer("", "10.10.0.2/32"),
		peer("named", "10.10.0.3/32"),
	})

	assert.Empty(t, table.Lookup(netip.MustParseAddr("10.10.0.2")))
	assert.Equal(t, "named", table.Lookup(netip.MustParseAddr("10.10.0.3")))
}
