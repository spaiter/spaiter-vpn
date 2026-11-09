//go:build with_xdp && linux

package xdp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing/service"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestMap creates a standalone eBPF hash map matching the blocked_ips spec (IPv4).
func createTestMap(t *testing.T) *ebpf.Map {
	t.Helper()
	spec := &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4, // __u32 IPv4 addr
		ValueSize:  8, // __u64 expiration timestamp
		MaxEntries: 1000,
	}
	m, err := ebpf.NewMap(spec)
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })
	return m
}

// createTestMapV6 creates a standalone eBPF hash map matching the blocked_ips_v6 spec (IPv6).
func createTestMapV6(t *testing.T) *ebpf.Map {
	t.Helper()
	spec := &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    16, // [16]byte IPv6 addr
		ValueSize:  8,  // __u64 expiration timestamp
		MaxEntries: 1000,
	}
	m, err := ebpf.NewMap(spec)
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })
	return m
}

func nopLogger() log.ContextLogger {
	return log.NewNOPFactory().Logger()
}

// ---------------------------------------------------------------------------
// IPMapManager tests — IPv4
// ---------------------------------------------------------------------------

func TestIPMapManager_AddAndBlock(t *testing.T) {
	m := createTestMap(t)
	m6 := createTestMapV6(t)
	mgr := NewIPMapManager(m, m6, nopLogger(), false)

	ip := netip.MustParseAddr("192.168.1.1")
	require.NoError(t, mgr.AddIP(ip, 10*time.Minute))

	assert.True(t, mgr.IsBlocked(ip))
	assert.Equal(t, 1, mgr.BlockedCount())
}

func TestIPMapManager_RemoveIP(t *testing.T) {
	m := createTestMap(t)
	m6 := createTestMapV6(t)
	mgr := NewIPMapManager(m, m6, nopLogger(), false)

	ip := netip.MustParseAddr("10.0.0.1")
	require.NoError(t, mgr.AddIP(ip, 10*time.Minute))
	require.True(t, mgr.IsBlocked(ip))

	require.NoError(t, mgr.RemoveIP(ip))
	assert.False(t, mgr.IsBlocked(ip))
	assert.Equal(t, 0, mgr.BlockedCount())
}

func TestIPMapManager_Expiration(t *testing.T) {
	m := createTestMap(t)
	m6 := createTestMapV6(t)
	mgr := NewIPMapManager(m, m6, nopLogger(), false)

	ip := netip.MustParseAddr("172.16.0.1")
	require.NoError(t, mgr.AddIP(ip, 1*time.Millisecond))

	time.Sleep(10 * time.Millisecond)
	assert.False(t, mgr.IsBlocked(ip), "IP should be expired")
}

func TestIPMapManager_CleanupExpired(t *testing.T) {
	m := createTestMap(t)
	m6 := createTestMapV6(t)
	mgr := NewIPMapManager(m, m6, nopLogger(), false)

	ip1 := netip.MustParseAddr("10.1.0.1")
	ip2 := netip.MustParseAddr("10.1.0.2")
	ipKeep := netip.MustParseAddr("10.1.0.3")

	// Add two IPs with very short expiration
	require.NoError(t, mgr.AddIP(ip1, 1*time.Millisecond))
	require.NoError(t, mgr.AddIP(ip2, 1*time.Millisecond))
	// Add one IP with long expiration
	require.NoError(t, mgr.AddIP(ipKeep, 10*time.Minute))

	time.Sleep(10 * time.Millisecond)

	removed := mgr.CleanupExpired(context.Background())
	assert.Equal(t, 2, removed)
	assert.Equal(t, 1, mgr.BlockedCount())
	assert.True(t, mgr.IsBlocked(ipKeep))
	assert.False(t, mgr.IsBlocked(ip1))
	assert.False(t, mgr.IsBlocked(ip2))

	// Verify the BPF map was also cleaned up
	var val uint64
	key1, key2, keyKeep := ipToKey(ip1), ipToKey(ip2), ipToKey(ipKeep)
	assert.Error(t, m.Lookup(&key1, &val), "expired IP should be removed from BPF map")
	assert.Error(t, m.Lookup(&key2, &val), "expired IP should be removed from BPF map")
	assert.NoError(t, m.Lookup(&keyKeep, &val), "kept IP should still be in BPF map")
}

func TestIPMapManager_MultipleIPs(t *testing.T) {
	m := createTestMap(t)
	m6 := createTestMapV6(t)
	mgr := NewIPMapManager(m, m6, nopLogger(), false)

	ips := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2.2.2.2"),
		netip.MustParseAddr("3.3.3.3"),
	}

	for _, ip := range ips {
		require.NoError(t, mgr.AddIP(ip, 10*time.Minute))
	}
	assert.Equal(t, 3, mgr.BlockedCount())
	for _, ip := range ips {
		assert.True(t, mgr.IsBlocked(ip))
	}

	// Remove the middle one
	require.NoError(t, mgr.RemoveIP(ips[1]))
	assert.Equal(t, 2, mgr.BlockedCount())
	assert.True(t, mgr.IsBlocked(ips[0]))
	assert.False(t, mgr.IsBlocked(ips[1]))
	assert.True(t, mgr.IsBlocked(ips[2]))
}

func TestIPMapManager_OverwriteIP(t *testing.T) {
	m := createTestMap(t)
	m6 := createTestMapV6(t)
	mgr := NewIPMapManager(m, m6, nopLogger(), false)

	ip := netip.MustParseAddr("192.0.2.1")

	// Add with short duration
	require.NoError(t, mgr.AddIP(ip, 1*time.Millisecond))
	time.Sleep(10 * time.Millisecond)
	assert.False(t, mgr.IsBlocked(ip), "should be expired after first add")

	// Overwrite with long duration — second write wins
	require.NoError(t, mgr.AddIP(ip, 10*time.Minute))
	assert.True(t, mgr.IsBlocked(ip), "should be blocked after overwrite")
	assert.Equal(t, 1, mgr.BlockedCount())
}

// ipToKey converts a v4 address to the BPF map key format (matches map_manager encoding).
func ipToKey(ip netip.Addr) uint32 {
	raw := ip.As4()
	return binary.NativeEndian.Uint32(raw[:])
}

// ---------------------------------------------------------------------------
// IPMapManager tests — IPv6
// ---------------------------------------------------------------------------

func TestIPMapManager_IPv6_AddAndBlock(t *testing.T) {
	m := createTestMap(t)
	m6 := createTestMapV6(t)
	mgr := NewIPMapManager(m, m6, nopLogger(), false)

	ip6 := netip.MustParseAddr("2001:db8::1")
	require.NoError(t, mgr.AddIP(ip6, 10*time.Minute))

	assert.True(t, mgr.IsBlocked(ip6))
	assert.Equal(t, 1, mgr.BlockedCount())

	// Verify BPF v6 map has the entry
	var val uint64
	key := ip6.As16()
	assert.NoError(t, m6.Lookup(&key, &val), "IPv6 should be in BPF v6 map")

	// Verify BPF v4 map is empty
	assert.Equal(t, 0, mapLen(m), "IPv4 BPF map should be empty")
}

func TestIPMapManager_IPv6_RemoveIP(t *testing.T) {
	m := createTestMap(t)
	m6 := createTestMapV6(t)
	mgr := NewIPMapManager(m, m6, nopLogger(), false)

	ip6 := netip.MustParseAddr("2001:db8::2")
	require.NoError(t, mgr.AddIP(ip6, 10*time.Minute))
	require.True(t, mgr.IsBlocked(ip6))

	require.NoError(t, mgr.RemoveIP(ip6))
	assert.False(t, mgr.IsBlocked(ip6))
	assert.Equal(t, 0, mgr.BlockedCount())

	// Verify BPF v6 map is empty
	var val uint64
	key := ip6.As16()
	assert.Error(t, m6.Lookup(&key, &val), "removed IPv6 should not be in BPF map")
}

func TestIPMapManager_IPv6_Expiration(t *testing.T) {
	m := createTestMap(t)
	m6 := createTestMapV6(t)
	mgr := NewIPMapManager(m, m6, nopLogger(), false)

	ip6 := netip.MustParseAddr("fd00::1")
	require.NoError(t, mgr.AddIP(ip6, 1*time.Millisecond))

	time.Sleep(10 * time.Millisecond)
	assert.False(t, mgr.IsBlocked(ip6), "IPv6 should be expired")
}

func TestIPMapManager_IPv6_CleanupExpired(t *testing.T) {
	m := createTestMap(t)
	m6 := createTestMapV6(t)
	mgr := NewIPMapManager(m, m6, nopLogger(), false)

	ip6expire := netip.MustParseAddr("2001:db8::10")
	ip6keep := netip.MustParseAddr("2001:db8::20")

	require.NoError(t, mgr.AddIP(ip6expire, 1*time.Millisecond))
	require.NoError(t, mgr.AddIP(ip6keep, 10*time.Minute))

	time.Sleep(10 * time.Millisecond)

	removed := mgr.CleanupExpired(context.Background())
	assert.Equal(t, 1, removed)
	assert.Equal(t, 1, mgr.BlockedCount())
	assert.False(t, mgr.IsBlocked(ip6expire))
	assert.True(t, mgr.IsBlocked(ip6keep))

	// Verify BPF v6 map state
	var val uint64
	keyExpire := ip6expire.As16()
	keyKeep := ip6keep.As16()
	assert.Error(t, m6.Lookup(&keyExpire, &val), "expired IPv6 should be removed from BPF map")
	assert.NoError(t, m6.Lookup(&keyKeep, &val), "kept IPv6 should still be in BPF map")
}

func TestIPMapManager_MixedV4V6(t *testing.T) {
	m := createTestMap(t)
	m6 := createTestMapV6(t)
	mgr := NewIPMapManager(m, m6, nopLogger(), false)

	ip4 := netip.MustParseAddr("192.168.1.100")
	ip6 := netip.MustParseAddr("2001:db8::100")

	require.NoError(t, mgr.AddIP(ip4, 10*time.Minute))
	require.NoError(t, mgr.AddIP(ip6, 10*time.Minute))

	assert.Equal(t, 2, mgr.BlockedCount())
	assert.True(t, mgr.IsBlocked(ip4))
	assert.True(t, mgr.IsBlocked(ip6))

	// Each should be in the correct BPF map
	var val uint64
	key4 := ipToKey(ip4)
	key6 := ip6.As16()
	assert.NoError(t, m.Lookup(&key4, &val), "IPv4 should be in v4 BPF map")
	assert.NoError(t, m6.Lookup(&key6, &val), "IPv6 should be in v6 BPF map")

	// Remove IPv4 only
	require.NoError(t, mgr.RemoveIP(ip4))
	assert.Equal(t, 1, mgr.BlockedCount())
	assert.False(t, mgr.IsBlocked(ip4))
	assert.True(t, mgr.IsBlocked(ip6))
}

// mapLen returns the number of entries in a BPF map by iterating.
func mapLen(m *ebpf.Map) int {
	count := 0
	var key, nextKey []byte
	key = make([]byte, int(m.KeySize()))
	nextKey = make([]byte, int(m.KeySize()))
	for {
		if err := m.NextKey(key, nextKey); err != nil {
			break
		}
		count++
		copy(key, nextKey)
	}
	return count
}

// ---------------------------------------------------------------------------
// Filter tests
// ---------------------------------------------------------------------------

func TestFilter_AttachLoopback(t *testing.T) {
	logger := nopLogger()
	f, err := NewFilter("lo", logger, false)
	require.NoError(t, err)
	defer f.Close()

	mgr := f.MapManager()
	require.NotNil(t, mgr)

	// Verify the map manager is functional
	ip := netip.MustParseAddr("127.0.0.2")
	require.NoError(t, mgr.AddIP(ip, time.Minute))
	assert.True(t, mgr.IsBlocked(ip))
}

func TestFilter_InvalidInterface(t *testing.T) {
	_, err := NewFilter("nonexistent_iface_xyz", nopLogger(), false)
	require.Error(t, err)
}

func TestFilter_BlockViaFilter(t *testing.T) {
	f, err := NewFilter("lo", nopLogger(), false)
	require.NoError(t, err)
	defer f.Close()

	ip := netip.MustParseAddr("10.99.0.1")
	mgr := f.MapManager()

	require.NoError(t, mgr.AddIP(ip, 5*time.Minute))
	assert.True(t, mgr.IsBlocked(ip))

	require.NoError(t, mgr.RemoveIP(ip))
	assert.False(t, mgr.IsBlocked(ip))
}

func TestFilter_BlockIPv6ViaFilter(t *testing.T) {
	f, err := NewFilter("lo", nopLogger(), false)
	require.NoError(t, err)
	defer f.Close()

	ip6 := netip.MustParseAddr("2001:db8::99")
	mgr := f.MapManager()

	require.NoError(t, mgr.AddIP(ip6, 5*time.Minute))
	assert.True(t, mgr.IsBlocked(ip6))

	require.NoError(t, mgr.RemoveIP(ip6))
	assert.False(t, mgr.IsBlocked(ip6))
}

// ---------------------------------------------------------------------------
// Service tests
// ---------------------------------------------------------------------------

func newTestCtx() context.Context {
	return service.ContextWithDefaultRegistry(context.Background())
}

func TestService_NewService_Defaults(t *testing.T) {
	svc, err := NewService(newTestCtx(), nopLogger(), "test-xdp", option.XDPBlockerServiceOptions{
		Interfaces: []string{"lo"},
	})
	require.NoError(t, err)

	s := svc.(*Service)
	assert.Equal(t, 5*time.Hour, s.banDuration)
	assert.Equal(t, 5*time.Minute, s.cleanupInterval)
	assert.True(t, s.logBlocked)
}

func TestService_NewService_NoInterfaces(t *testing.T) {
	_, err := NewService(newTestCtx(), nopLogger(), "test-xdp", option.XDPBlockerServiceOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one interface")
}

func TestService_BlockUnblock(t *testing.T) {
	ctx := newTestCtx()
	svc, err := NewService(ctx, nopLogger(), "test-xdp", option.XDPBlockerServiceOptions{
		Interfaces: []string{"lo"},
	})
	require.NoError(t, err)

	s := svc.(*Service)

	// Start the service (skip Initialize which calls MustRegister — we test lifecycle separately)
	require.NoError(t, s.Start(adapter.StartStateStart))
	defer s.Close()

	ip := netip.MustParseAddr("198.51.100.1")

	require.NoError(t, s.BlockIP(ip, 10*time.Minute, ""))
	assert.True(t, s.IsBlocked(ip))
	assert.Equal(t, 1, s.BlockedCount())

	require.NoError(t, s.UnblockIP(ip))
	assert.False(t, s.IsBlocked(ip))
	assert.Equal(t, 0, s.BlockedCount())
}

func TestService_IPv6_BlockUnblock(t *testing.T) {
	ctx := newTestCtx()
	svc, err := NewService(ctx, nopLogger(), "test-xdp", option.XDPBlockerServiceOptions{
		Interfaces: []string{"lo"},
	})
	require.NoError(t, err)

	s := svc.(*Service)
	require.NoError(t, s.Start(adapter.StartStateStart))
	defer s.Close()

	ip6 := netip.MustParseAddr("2001:db8::1")

	require.NoError(t, s.BlockIP(ip6, 10*time.Minute, ""))
	assert.True(t, s.IsBlocked(ip6))
	assert.Equal(t, 1, s.BlockedCount())

	require.NoError(t, s.UnblockIP(ip6))
	assert.False(t, s.IsBlocked(ip6))
	assert.Equal(t, 0, s.BlockedCount())
}

func TestService_MixedV4V6_BlockUnblock(t *testing.T) {
	ctx := newTestCtx()
	svc, err := NewService(ctx, nopLogger(), "test-xdp", option.XDPBlockerServiceOptions{
		Interfaces: []string{"lo"},
	})
	require.NoError(t, err)

	s := svc.(*Service)
	require.NoError(t, s.Start(adapter.StartStateStart))
	defer s.Close()

	ip4 := netip.MustParseAddr("198.51.100.50")
	ip6 := netip.MustParseAddr("2001:db8::50")

	require.NoError(t, s.BlockIP(ip4, 10*time.Minute, ""))
	require.NoError(t, s.BlockIP(ip6, 10*time.Minute, ""))
	assert.True(t, s.IsBlocked(ip4))
	assert.True(t, s.IsBlocked(ip6))
	assert.Equal(t, 2, s.BlockedCount())

	// Unblock only IPv4
	require.NoError(t, s.UnblockIP(ip4))
	assert.False(t, s.IsBlocked(ip4))
	assert.True(t, s.IsBlocked(ip6))
	assert.Equal(t, 1, s.BlockedCount())
}

func TestService_DefaultBanDuration(t *testing.T) {
	ctx := newTestCtx()
	svc, err := NewService(ctx, nopLogger(), "test-xdp", option.XDPBlockerServiceOptions{
		Interfaces: []string{"lo"},
	})
	require.NoError(t, err)

	s := svc.(*Service)
	require.NoError(t, s.Start(adapter.StartStateStart))
	defer s.Close()

	ip := netip.MustParseAddr("203.0.113.1")

	// duration=0 should use the service default (5h)
	require.NoError(t, s.BlockIP(ip, 0, ""))
	assert.True(t, s.IsBlocked(ip))
}

// ---------------------------------------------------------------------------
// User-IP tracking tests
// ---------------------------------------------------------------------------

func TestService_TrackUserIP(t *testing.T) {
	ctx := newTestCtx()
	svc, err := NewService(ctx, nopLogger(), "test-xdp", option.XDPBlockerServiceOptions{
		Interfaces: []string{"lo"},
	})
	require.NoError(t, err)

	s := svc.(*Service)
	require.NoError(t, s.Start(adapter.StartStateStart))
	defer s.Close()

	// Track IPs for a user
	s.TrackUserIP("alice", netip.MustParseAddr("10.0.0.1"))
	s.TrackUserIP("alice", netip.MustParseAddr("2001:db8::1"))

	s.userIPsMu.RLock()
	ips := s.userIPs["alice"]
	s.userIPsMu.RUnlock()

	assert.Equal(t, 2, len(ips))
	_, ok4 := ips[netip.MustParseAddr("10.0.0.1")]
	_, ok6 := ips[netip.MustParseAddr("2001:db8::1")]
	assert.True(t, ok4, "IPv4 should be tracked")
	assert.True(t, ok6, "IPv6 should be tracked")
}

func TestService_TrackUserIP_EmptyUser(t *testing.T) {
	ctx := newTestCtx()
	svc, err := NewService(ctx, nopLogger(), "test-xdp", option.XDPBlockerServiceOptions{
		Interfaces: []string{"lo"},
	})
	require.NoError(t, err)

	s := svc.(*Service)

	// Empty user should be a no-op
	s.TrackUserIP("", netip.MustParseAddr("10.0.0.1"))

	s.userIPsMu.RLock()
	assert.Equal(t, 0, len(s.userIPs))
	s.userIPsMu.RUnlock()
}

func TestService_TrackUserIP_Dedup(t *testing.T) {
	ctx := newTestCtx()
	svc, err := NewService(ctx, nopLogger(), "test-xdp", option.XDPBlockerServiceOptions{
		Interfaces: []string{"lo"},
	})
	require.NoError(t, err)

	s := svc.(*Service)

	ip := netip.MustParseAddr("10.0.0.1")
	s.TrackUserIP("bob", ip)
	s.TrackUserIP("bob", ip)
	s.TrackUserIP("bob", ip)

	s.userIPsMu.RLock()
	assert.Equal(t, 1, len(s.userIPs["bob"]), "duplicate IPs should be deduplicated")
	s.userIPsMu.RUnlock()
}

func TestService_BlockUserIPs(t *testing.T) {
	ctx := newTestCtx()
	svc, err := NewService(ctx, nopLogger(), "test-xdp", option.XDPBlockerServiceOptions{
		Interfaces: []string{"lo"},
	})
	require.NoError(t, err)

	s := svc.(*Service)
	require.NoError(t, s.Start(adapter.StartStateStart))
	defer s.Close()

	ip4 := netip.MustParseAddr("10.0.0.1")
	ip6 := netip.MustParseAddr("2001:db8::1")

	// Track both IPs for user
	s.TrackUserIP("alice", ip4)
	s.TrackUserIP("alice", ip6)

	// Block all of alice's IPs
	require.NoError(t, s.BlockUserIPs("alice", 10*time.Minute))

	// Both should be blocked
	assert.True(t, s.IsBlocked(ip4), "IPv4 should be blocked via BlockUserIPs")
	assert.True(t, s.IsBlocked(ip6), "IPv6 should be blocked via BlockUserIPs")
	assert.Equal(t, 2, s.BlockedCount())
}

func TestService_BlockUserIPs_EmptyUser(t *testing.T) {
	ctx := newTestCtx()
	svc, err := NewService(ctx, nopLogger(), "test-xdp", option.XDPBlockerServiceOptions{
		Interfaces: []string{"lo"},
	})
	require.NoError(t, err)

	s := svc.(*Service)
	require.NoError(t, s.Start(adapter.StartStateStart))
	defer s.Close()

	// Should be a no-op, no error
	require.NoError(t, s.BlockUserIPs("", 10*time.Minute))
	assert.Equal(t, 0, s.BlockedCount())
}

func TestService_BlockUserIPs_UnknownUser(t *testing.T) {
	ctx := newTestCtx()
	svc, err := NewService(ctx, nopLogger(), "test-xdp", option.XDPBlockerServiceOptions{
		Interfaces: []string{"lo"},
	})
	require.NoError(t, err)

	s := svc.(*Service)
	require.NoError(t, s.Start(adapter.StartStateStart))
	defer s.Close()

	// Unknown user should be a no-op
	require.NoError(t, s.BlockUserIPs("nonexistent", 10*time.Minute))
	assert.Equal(t, 0, s.BlockedCount())
}

func TestService_BlockUserIPs_CrossBlock(t *testing.T) {
	ctx := newTestCtx()
	svc, err := NewService(ctx, nopLogger(), "test-xdp", option.XDPBlockerServiceOptions{
		Interfaces: []string{"lo"},
	})
	require.NoError(t, err)

	s := svc.(*Service)
	require.NoError(t, s.Start(adapter.StartStateStart))
	defer s.Close()

	aliceV4 := netip.MustParseAddr("10.0.0.1")
	aliceV6 := netip.MustParseAddr("2001:db8::1")
	bobV4 := netip.MustParseAddr("10.0.0.2")

	s.TrackUserIP("alice", aliceV4)
	s.TrackUserIP("alice", aliceV6)
	s.TrackUserIP("bob", bobV4)

	// Simulate: BT detected on alice's IPv4 → block source IP + cross-block all alice IPs
	require.NoError(t, s.BlockIP(aliceV4, 10*time.Minute, ""))
	require.NoError(t, s.BlockUserIPs("alice", 10*time.Minute))

	// Alice's both IPs should be blocked
	assert.True(t, s.IsBlocked(aliceV4))
	assert.True(t, s.IsBlocked(aliceV6))

	// Bob should not be affected
	assert.False(t, s.IsBlocked(bobV4))
}

func TestService_BlockUserIPs_MultipleUsers(t *testing.T) {
	ctx := newTestCtx()
	svc, err := NewService(ctx, nopLogger(), "test-xdp", option.XDPBlockerServiceOptions{
		Interfaces: []string{"lo"},
	})
	require.NoError(t, err)

	s := svc.(*Service)
	require.NoError(t, s.Start(adapter.StartStateStart))
	defer s.Close()

	s.TrackUserIP("alice", netip.MustParseAddr("10.0.0.1"))
	s.TrackUserIP("alice", netip.MustParseAddr("2001:db8::1"))
	s.TrackUserIP("bob", netip.MustParseAddr("10.0.0.2"))
	s.TrackUserIP("bob", netip.MustParseAddr("2001:db8::2"))

	// Block alice only
	require.NoError(t, s.BlockUserIPs("alice", 10*time.Minute))

	assert.True(t, s.IsBlocked(netip.MustParseAddr("10.0.0.1")))
	assert.True(t, s.IsBlocked(netip.MustParseAddr("2001:db8::1")))
	assert.False(t, s.IsBlocked(netip.MustParseAddr("10.0.0.2")))
	assert.False(t, s.IsBlocked(netip.MustParseAddr("2001:db8::2")))

	// Now block bob too
	require.NoError(t, s.BlockUserIPs("bob", 10*time.Minute))
	assert.True(t, s.IsBlocked(netip.MustParseAddr("10.0.0.2")))
	assert.True(t, s.IsBlocked(netip.MustParseAddr("2001:db8::2")))
	assert.Equal(t, 4, s.BlockedCount())
}

// ---------------------------------------------------------------------------
// Packet-level XDP drop tests (veth pair + netns)
// ---------------------------------------------------------------------------

func TestXDP_PacketDrop(t *testing.T) {
	const (
		nsName   = "xdp-test-ns"
		vethHost = "veth-xdp"
		vethPeer = "veth-peer"
		hostIP   = "10.0.0.1/24"
		peerIP   = "10.0.0.2/24"
		peerAddr = "10.0.0.2"
		hostAddr = "10.0.0.1"
	)

	// Clean up any leftover state from previous runs
	cleanup := func() {
		exec.Command("ip", "netns", "del", nsName).Run()
		exec.Command("ip", "link", "del", vethHost).Run()
	}
	cleanup()
	t.Cleanup(cleanup)

	// Create network namespace
	runCmd(t, "ip", "netns", "add", nsName)

	// Create veth pair
	runCmd(t, "ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethPeer)

	// Move peer to namespace
	runCmd(t, "ip", "link", "set", vethPeer, "netns", nsName)

	// Configure host side
	runCmd(t, "ip", "addr", "add", hostIP, "dev", vethHost)
	runCmd(t, "ip", "link", "set", vethHost, "up")

	// Configure peer side (inside namespace)
	runCmd(t, "ip", "netns", "exec", nsName, "ip", "addr", "add", peerIP, "dev", vethPeer)
	runCmd(t, "ip", "netns", "exec", nsName, "ip", "link", "set", vethPeer, "up")

	// Verify baseline connectivity: peer can ping host
	requirePing(t, nsName, hostAddr, true, "baseline connectivity check failed")

	// Attach XDP filter to the host-side veth
	f, err := NewFilter(vethHost, nopLogger(), false)
	require.NoError(t, err, "failed to attach XDP filter to %s", vethHost)
	defer f.Close()

	// Block the peer IP (source IP of traffic from the namespace)
	peerNetIP := netip.MustParseAddr(peerAddr)
	require.NoError(t, f.MapManager().AddIP(peerNetIP, 10*time.Minute))

	// Ping from namespace should now fail — XDP drops packets from peerAddr
	requirePing(t, nsName, hostAddr, false, "ping should fail when IP is blocked by XDP")

	// Unblock the peer IP
	require.NoError(t, f.MapManager().RemoveIP(peerNetIP))

	// Ping should succeed again
	requirePing(t, nsName, hostAddr, true, "ping should succeed after unblocking IP")
}

func TestXDP_IPv6_PacketDrop(t *testing.T) {
	const (
		nsName   = "xdp6-test-ns"
		vethHost = "veth-xdp6"
		vethPeer = "veth-peer6"
		hostIP6  = "fd00::1/64"
		peerIP6  = "fd00::2/64"
		peerAddr = "fd00::2"
		hostAddr = "fd00::1"
	)

	cleanup := func() {
		exec.Command("ip", "netns", "del", nsName).Run()
		exec.Command("ip", "link", "del", vethHost).Run()
	}
	cleanup()
	t.Cleanup(cleanup)

	// Create network namespace
	runCmd(t, "ip", "netns", "add", nsName)

	// Create veth pair
	runCmd(t, "ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethPeer)

	// Move peer to namespace
	runCmd(t, "ip", "link", "set", vethPeer, "netns", nsName)

	// Configure host side (IPv6)
	runCmd(t, "ip", "addr", "add", hostIP6, "dev", vethHost)
	runCmd(t, "ip", "link", "set", vethHost, "up")

	// Configure peer side (inside namespace, IPv6)
	runCmd(t, "ip", "netns", "exec", nsName, "ip", "addr", "add", peerIP6, "dev", vethPeer)
	runCmd(t, "ip", "netns", "exec", nsName, "ip", "link", "set", vethPeer, "up")

	// Wait for IPv6 DAD (duplicate address detection) to complete
	time.Sleep(2 * time.Second)

	// Verify baseline connectivity
	requirePing6(t, nsName, hostAddr, true, "baseline IPv6 connectivity check failed")

	// Attach XDP filter
	f, err := NewFilter(vethHost, nopLogger(), false)
	require.NoError(t, err, "failed to attach XDP filter to %s", vethHost)
	defer f.Close()

	// Block the peer IPv6 address
	peerNetIP := netip.MustParseAddr(peerAddr)
	require.NoError(t, f.MapManager().AddIP(peerNetIP, 10*time.Minute))

	// Ping6 from namespace should now fail
	requirePing6(t, nsName, hostAddr, false, "ping6 should fail when IPv6 is blocked by XDP")

	// Unblock
	require.NoError(t, f.MapManager().RemoveIP(peerNetIP))

	// Ping6 should succeed again
	requirePing6(t, nsName, hostAddr, true, "ping6 should succeed after unblocking IPv6")
}

// runCmd runs a command and fails the test on error.
func runCmd(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "command %q failed: %s", fmt.Sprintf("%s %s", name, strings.Join(args, " ")), string(out))
}

// requirePing pings targetIP from inside the given network namespace.
// If expectSuccess is true, the test fails if the ping fails; if false, it fails if the ping succeeds.
func requirePing(t *testing.T, nsName, targetIP string, expectSuccess bool, msg string) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", nsName, "ping", "-c", "1", "-W", "2", targetIP)
	out, err := cmd.CombinedOutput()
	if expectSuccess {
		require.NoError(t, err, "%s: ping output: %s", msg, string(out))
	} else {
		require.Error(t, err, "%s: ping should have failed but succeeded: %s", msg, string(out))
	}
}

// requirePing6 pings an IPv6 targetIP from inside the given network namespace.
func requirePing6(t *testing.T, nsName, targetIP string, expectSuccess bool, msg string) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", nsName, "ping", "-6", "-c", "1", "-W", "2", targetIP)
	out, err := cmd.CombinedOutput()
	if expectSuccess {
		require.NoError(t, err, "%s: ping6 output: %s", msg, string(out))
	} else {
		require.Error(t, err, "%s: ping6 should have failed but succeeded: %s", msg, string(out))
	}
}
