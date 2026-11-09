// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package sockopts

import (
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/types/nettype"
)

// SetICMPErrImmunity is no-op on non-Windows.
func SetICMPErrImmunity(pconn nettype.PacketConn) error {
	return nil
}
