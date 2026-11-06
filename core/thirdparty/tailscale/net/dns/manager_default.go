// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (!linux || android) && !freebsd && !openbsd && !windows && !darwin && !illumos && !solaris && !plan9

package dns

import (
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/control/controlknobs"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/health"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/types/logger"
	"github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/util/syspolicy/policyclient"
)

// NewOSConfigurator creates a new OS configurator.
//
// The health tracker and the knobs may be nil and are ignored on this platform.
func NewOSConfigurator(logger.Logf, *health.Tracker, policyclient.Client, *controlknobs.Knobs, string) (OSConfigurator, error) {
	return NewNoopManager()
}
