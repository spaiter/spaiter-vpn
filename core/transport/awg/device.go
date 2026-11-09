package awg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"

	singTun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/exceptions"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
	"github.com/spaiter/spaiter-vpn/core/adapter"
)

type DeviceOpts struct {
	UseIntegratedTun bool
	Address          []netip.Prefix
	AllowedIps       []netip.Prefix
	ExcludedIps      []netip.Prefix
	MTU              uint32
	Handler          singTun.Handler
	UDPTimeout       time.Duration
	Context          context.Context
	// Bind, when non-nil, replaces the default UDP-socket bind. Used by the
	// masque-wg outbound to ride WireGuard over a MASQUE CONNECT-UDP flow. The
	// server-side awg endpoint leaves this nil and keeps its normal bind. //H
	Bind conn.Bind
}

type Device struct {
	awgDevice     *device.Device
	tun           tunAdapter
	bind          conn.Bind
	logger        *device.Logger
	ipcConfig     string
	peerEndpoints peerEndpointCache //H tunnel address → peer's external IP
}

func NewDevice(ctx context.Context, logger logger.ContextLogger, dial network.Dialer, ipcConfig string, opts DeviceOpts) (*Device, error) {
	var (
		tun tunAdapter
		err error
	)

	if opts.UseIntegratedTun {
		tun, err = newSystemTun(ctx, opts.Address, opts.AllowedIps, opts.ExcludedIps, opts.MTU, logger)
		if err != nil {
			return nil, exceptions.Cause(err, "create tunnel")
		}
	} else if opts.Handler != nil {
		tun, err = newStackTun(ctx, opts.Address, opts.MTU, opts.Handler, opts.UDPTimeout)
		if err != nil {
			return nil, exceptions.Cause(err, "create stack tunnel")
		}
	} else {
		tun, err = newNetworkTun(opts.Address, opts.MTU)
		if err != nil {
			return nil, err
		}
	}

	awgLogger := &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...interface{}) {
			logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}

	bnd := opts.Bind //H allow injecting a custom bind (masque-wg); default otherwise
	if bnd == nil {
		bnd = newBind(ctx, dial)
	}
	return &Device{
		tun:       tun,
		bind:      bnd,
		logger:    awgLogger,
		ipcConfig: ipcConfig,
	}, nil
}

func (d *Device) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	d.awgDevice = device.NewDevice(d.tun, d.bind, d.logger)
	if err := d.awgDevice.IpcSet(d.ipcConfig); err != nil {
		return E.Cause(err, "set ipc config")
	}

	if err := d.tun.Start(); err != nil {
		return E.Cause(err, "tun start")
	}

	return d.awgDevice.Up()
}

// IpcSetDelta applies a partial UAPI config to the running device. Unlike the
// IpcSet done at startup this must NOT carry `replace_peers`, so peers the
// delta does not mention are left exactly as they are — keys, handshake and
// all. Invalidates the peer-endpoint cache, whose contents the delta may have
// just changed. //H
func (d *Device) IpcSetDelta(ipcConfig string) error {
	if d.awgDevice == nil {
		return E.New("awg: device not started")
	}
	if err := d.awgDevice.IpcSet(ipcConfig); err != nil {
		return err
	}
	d.peerEndpoints.mu.Lock()
	d.peerEndpoints.expires = time.Time{}
	d.peerEndpoints.mu.Unlock()
	return nil
}

func (d *Device) IsUnderLoad() bool {
	if d.awgDevice == nil {
		return false
	}
	return d.awgDevice.IsUnderLoad()
}

func (d *Device) Close() error {
	if d.awgDevice != nil {
		d.awgDevice.Close()
	}
	return nil
}

func (d *Device) DialContext(ctx context.Context, network string, destination metadata.Socksaddr) (net.Conn, error) {
	return d.tun.DialContext(ctx, network, destination)
}

func (d *Device) ListenPacket(ctx context.Context, destination metadata.Socksaddr) (net.PacketConn, error) {
	return d.tun.ListenPacket(ctx, destination)
}
