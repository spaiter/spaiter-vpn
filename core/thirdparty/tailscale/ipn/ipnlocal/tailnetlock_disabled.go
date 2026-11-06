// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_tailnetlock

package ipnlocal

import (
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/ipn"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/ipn/ipnstate"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/tka"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/types/netmap"
)

type tkaState struct {
	authority *tka.Authority
}

func (b *LocalBackend) initTKALocked() error {
	return nil
}

func (b *LocalBackend) tkaSyncIfNeeded(nm *netmap.NetworkMap, prefs ipn.PrefsView) error {
	return nil
}

func (b *LocalBackend) tkaFilterNetmapLocked(nm *netmap.NetworkMap) {}

func (b *LocalBackend) NetworkLockStatus() *ipnstate.NetworkLockStatus {
	return &ipnstate.NetworkLockStatus{Enabled: false}
}
