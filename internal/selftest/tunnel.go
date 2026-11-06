package selftest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Tunnel is a plain WireGuard interface on the host, used as the test client.
//
// Plain WireGuard, not AmneziaWG: the test endpoint is created without
// obfuscation parameters precisely so that the host's own wg(4) can be the
// client and no fork-specific userspace is needed.
type Tunnel struct {
	Name    string
	Address netip.Prefix

	link   netlink.Link
	client *wgctrl.Client
}

// TunnelConfig describes the interface to build.
type TunnelConfig struct {
	Name string
	MTU  int

	PrivateKey      wgtypes.Key
	ServerPublicKey wgtypes.Key
	// ServerEndpoint is where the handshake is sent. For a self-test this is
	// loopback, which is also why the XDP ban cannot be exercised: the fork
	// refuses to ban a loopback peer.
	ServerEndpoint *net.UDPAddr
	// Address is the client's address inside the tunnel, carrying the tunnel
	// subnet's prefix length so the whole subnet is on-link.
	Address netip.Prefix
	// AllowedIPs is the subnet routed to the peer.
	AllowedIPs netip.Prefix
}

// CreateTunnel brings up the interface. Note that configuring a peer installs
// no routes — only wg-quick does that — which is deliberate here: everything
// the test addresses is inside the on-link tunnel subnet.
func CreateTunnel(cfg TunnelConfig) (*Tunnel, error) {
	if _, err := netlink.LinkByName(cfg.Name); err == nil {
		return nil, fmt.Errorf("interface %s already exists; a previous run did not clean up, remove it with `ip link del %s`", cfg.Name, cfg.Name)
	} else if !errors.As(err, new(netlink.LinkNotFoundError)) {
		return nil, fmt.Errorf("look up interface %s: %w", cfg.Name, err)
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = cfg.Name
	attrs.MTU = cfg.MTU
	link := &netlink.GenericLink{LinkAttrs: attrs, LinkType: "wireguard"}
	if err := netlink.LinkAdd(link); err != nil {
		return nil, fmt.Errorf("create wireguard interface %s (needs root and the wireguard module): %w", cfg.Name, err)
	}

	tunnel := &Tunnel{Name: cfg.Name, Address: cfg.Address, link: link}
	// From here on any failure must take the interface down with it, or the
	// host is left with a half-configured interface and the next run refuses
	// to start.
	cleanup := func(err error) (*Tunnel, error) {
		tunnel.Close()
		return nil, err
	}

	client, err := wgctrl.New()
	if err != nil {
		return cleanup(fmt.Errorf("open wireguard control socket: %w", err))
	}
	tunnel.client = client

	keepalive := 5 * time.Second
	allowed := net.IPNet{
		IP:   cfg.AllowedIPs.Masked().Addr().AsSlice(),
		Mask: net.CIDRMask(cfg.AllowedIPs.Bits(), cfg.AllowedIPs.Addr().BitLen()),
	}
	err = client.ConfigureDevice(cfg.Name, wgtypes.Config{
		PrivateKey:   &cfg.PrivateKey,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   cfg.ServerPublicKey,
			Endpoint:                    cfg.ServerEndpoint,
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  []net.IPNet{allowed},
			PersistentKeepaliveInterval: &keepalive,
		}},
	})
	if err != nil {
		return cleanup(fmt.Errorf("configure %s: %w", cfg.Name, err))
	}

	addr := &netlink.Addr{IPNet: &net.IPNet{
		IP:   cfg.Address.Addr().AsSlice(),
		Mask: net.CIDRMask(cfg.Address.Bits(), cfg.Address.Addr().BitLen()),
	}}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return cleanup(fmt.Errorf("add %s to %s: %w", cfg.Address, cfg.Name, err))
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return cleanup(fmt.Errorf("bring %s up: %w", cfg.Name, err))
	}
	return tunnel, nil
}

// WaitHandshake blocks until the peer completes a handshake.
//
// The handshake is the only available proof that the tunnel works: the awg
// endpoint answers no ICMP on its own tunnel address, so a failing ping says
// nothing either way.
func (t *Tunnel) WaitHandshake(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		device, err := t.client.Device(t.Name)
		if err != nil {
			lastErr = err
		} else if len(device.Peers) == 0 {
			lastErr = fmt.Errorf("interface %s has no peers", t.Name)
		} else if !device.Peers[0].LastHandshakeTime.IsZero() {
			return nil
		} else {
			lastErr = fmt.Errorf("no handshake yet")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no handshake on %s within %s: %w", t.Name, timeout, lastErr)
		}
	}
}

// Send writes one datagram from the tunnel address to the given destination
// inside the tunnel.
//
// The source address is bound explicitly so that the packet enters the tunnel
// rather than taking the host's default route, and so that the detection log
// line's `source=` identifies this test.
func (t *Tunnel) Send(destination netip.AddrPort, payload []byte) error {
	local := &net.UDPAddr{IP: t.Address.Addr().AsSlice(), Port: 0}
	remote := &net.UDPAddr{IP: destination.Addr().AsSlice(), Port: int(destination.Port())}

	conn, err := net.DialUDP("udp4", local, remote)
	if err != nil {
		return fmt.Errorf("dial %s from %s: %w", remote, local.IP, err)
	}
	defer conn.Close()

	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("send %d bytes to %s: %w", len(payload), remote, err)
	}
	return nil
}

// Close removes the interface. It is safe to call more than once.
func (t *Tunnel) Close() error {
	var firstErr error
	if t.client != nil {
		if err := t.client.Close(); err != nil {
			firstErr = fmt.Errorf("close wireguard control socket: %w", err)
		}
		t.client = nil
	}
	if t.link != nil {
		if err := netlink.LinkDel(t.link); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("delete interface %s: %w", t.Name, err)
		}
		t.link = nil
	}
	return firstErr
}
