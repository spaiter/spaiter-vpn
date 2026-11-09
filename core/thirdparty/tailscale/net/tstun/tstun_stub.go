// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build aix || solaris || illumos

package tstun

import (
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/types/logger"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/wireguard-go/tun"
)

func New(logf logger.Logf, tunName string) (tun.Device, string, error) {
	panic("not implemented")
}

func Diagnose(logf logger.Logf, tunName string, err error) {
	panic("not implemented")
}
