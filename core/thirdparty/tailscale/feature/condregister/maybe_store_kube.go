// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (ts_kube || (linux && (arm64 || amd64) && !android)) && !ts_omit_kube

package condregister

import _ "github.com/spaiter/spaiter-vpn/core/thirdparty/tailscale/ipn/store/kubestore"
