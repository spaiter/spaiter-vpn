// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package controlclient

import (
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/tailcfg"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/types/key"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/util/syspolicy/policyclient"
)

// signRegisterRequest on non-supported platforms always returns errNoCertStore.
func signRegisterRequest(polc policyclient.Client, req *tailcfg.RegisterRequest, serverURL string, serverPubKey, machinePubKey key.MachinePublic) error {
	return errNoCertStore
}
