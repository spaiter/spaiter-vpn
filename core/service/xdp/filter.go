//go:build with_xdp && linux

package xdp

import (
	"net"

	"github.com/sagernet/sing/common/logger"

	"github.com/cilium/ebpf/link"
)

type Filter struct {
	ifaceName string
	objs      *bpfObjects
	link      link.Link
	mapMgr    *IPMapManager
}

func NewFilter(ifaceName string, logger logger.ContextLogger, logBlocked bool) (*Filter, error) {
	objs := &bpfObjects{}
	if err := loadBpfObjects(objs, nil); err != nil {
		return nil, err
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		_ = objs.Close()
		return nil, err
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpBlocker,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		_ = objs.Close()
		return nil, err
	}

	mapMgr := NewIPMapManager(objs.BlockedIps, objs.BlockedIpsV6, logger, logBlocked)

	return &Filter{
		ifaceName: ifaceName,
		objs:      objs,
		link:      l,
		mapMgr:    mapMgr,
	}, nil
}

func (f *Filter) MapManager() *IPMapManager {
	return f.mapMgr
}

func (f *Filter) Close() error {
	if f.link != nil {
		f.link.Close()
	}
	if f.objs != nil {
		f.objs.Close()
	}
	return nil
}
