# Provenance and licensing

This repository is a fork of
[`hiddify/hiddify-sing-box`](https://github.com/hiddify/hiddify-sing-box),
itself a fork of [`SagerNet/sing-box`](https://github.com/SagerNet/sing-box).
It is **GPL-3.0-or-later**; see [LICENSE](LICENSE).

## ⚠️ The LICENSE has an extra clause beyond GPL-3.0

> In addition, no derivative work may use the name or imply association with
> this application without prior consent.

Downstream projects built on this fork must therefore not use the upstream
names or marks in their own name, branding or domain, and must not claim
endorsement by or association with the upstream projects. Factual attribution
("derived from sing-box, GPL-3.0") is required by the GPL and is *not* what
that clause restricts. This is why the deployment project built on top of this
fork is named neutrally rather than after sing-box or Hiddify.

## Local additions (ours, GPL-3.0-or-later)

Copyright © 2026 spaiter. On top of the upstream core:

- **XDP BitTorrent blocking** — kernel-space detection and IP blocking wired
  into the route hook, including IPv6 and per-user cross-IP blocking, plus
  per-user block reporting.
- **Granular BitTorrent sub-protocol sniffing** (`SniffDetector`).
- **`masque-wg`** — a self-hosted MASQUE (CONNECT-UDP) + WireGuard protocol,
  inbound and outbound.
- **AmneziaWG 3.x support** (`amneziawg-go` v3.1), a real listening UDP socket
  on `listen_port` in server mode, and a back-compatible flat→nested schema
  migration for `AwgEndpointOptions`.
- **MTProto proxy inbound** integrating `9seconds/mtg`.
- **Clash API `/manage` extensions** — user CRUD including snell users, hot
  reload of anytls/shadowtls users, and applying config changes without
  restarting (keeping an inbound alive when a new config is rejected).
- **AWG peer traffic attribution** and related stats plumbing.

The XDP BitTorrent detection core originates from
[`spaiter/BitTorrentBlocker`](https://github.com/spaiter/BitTorrentBlocker),
which is MIT. MIT → GPL-3.0 is a permitted direction, so it is incorporated
here under GPL-3.0; the standalone project remains MIT.

## Absorbed modules under `core/thirdparty/`

Nothing is reached through a `replace` directive; each former replacement was
absorbed with its upstream `LICENSE` kept beside it. Pins are in `PROVENANCE.md`.

| Directory | Upstream | License |
|---|---|---|
| `connect-ip-go` | `shtorm-7/connect-ip-go` (← `Diniboy1123`) | MIT (Copyright 2024 Marten Seemann) |
| `dnscrypt/v2` | `shtorm-7/dnscrypt` (← `ameshkov`) | Unlicense (public domain) |
| `gooserelay` | `kianmhz/GooseRelayVPN` | MIT |
| `sing-anytls` | `anytls/sing-anytls` | **GPL-3.0** |
| `sing-shadowtls` | `sagernet/sing-shadowtls` | **GPL-3.0** |
| `sing-snell` | `reF1nd/sing-snell` | **GPL-3.0** |
| `sing-vmess` | `starifly/sing-vmess` | **GPL-3.0** |
| `tailscale` | `hiddify/tailscale` | BSD-3-Clause (Copyright © 2020 Tailscale Inc & AUTHORS); its `derp/xdp/headers` are libbpf, LGPL-2.1 OR BSD-2-Clause |
| `vaydns` | `hiddify/vaydns` (← `net2share`) | CC0-1.0 |
| `wireguard-go` | `hiddify/wireguard-go` | MIT |

Note: `tailscale` is pinned to commit `788aa623` on purpose — v5's `3c228839`
is a broken `hiddify/tailscale` merge with half-applied batched
`InputPackets`. Do not "update" that pin without re-testing.

`psiphon-quic-go` and `psiphon-tls` are gone together with `protocol/psiphon`
(dropped at absorption; see `PROVENANCE.md`).

## Notable copyleft Go dependencies

`enfein/mieru` (GPL-3.0) and the `sagernet/*` libraries — `sing`, `sing-tun`,
`sing-mux`, `sing-quic`, `sing-shadowsocks`, `sing-shadowsocks2`,
`sing-cloudflared`, `fswatch` (all GPL-3.0-or-later). Together with the
sing-box ancestry these make GPL-3.0 unavoidable for any distribution of this
fork or anything linking it. `Psiphon-Labs/psiphon-tunnel-core` is no longer a
dependency.

## Excluded from the default build: an unlicensed dependency

`github.com/hiddify/hmrd_multi_resolver_dns` carries no license grant (checked
at the pinned commit and at upstream `HEAD`, 2026-11-06). Its only consumers,
the `dnstt` outbound and the `smart_dns_pool` service, are therefore compiled
only with `-tags with_dnstt` (`include/dnstt.go` / `include/dnstt_stub.go`),
which no published build sets. Without the tag the module is not linked.

For the full cross-component licensing picture of the deployment, see
`THIRD-PARTY-NOTICES.md` in the `spaiter-vpn` umbrella repository.
