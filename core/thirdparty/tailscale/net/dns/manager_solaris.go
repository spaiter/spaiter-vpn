// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/control/controlknobs"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/health"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/types/logger"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/util/syspolicy/policyclient"
)

func NewOSConfigurator(logf logger.Logf, health *health.Tracker, _ policyclient.Client, _ *controlknobs.Knobs, iface string) (OSConfigurator, error) {
	return newDirectManager(logf, health), nil
}
