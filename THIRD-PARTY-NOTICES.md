# Third-Party Notices

`spaiter-vpn` is licensed under **GPL-3.0-or-later** (see [LICENSE](LICENSE)).

This file lists every third-party work the project incorporates, links to, or
derives from, together with its license. It is the authoritative provenance
record: if you add a dependency or copy code from anywhere, add it here in the
same commit.

Audited 2026-10-22; re-audited 2026-11-06 against the export tree, the module
graphs of every shipped binary (`go list -deps` of the core with its production
tags, of the installer, and of the relay), and each `LICENSE` file in the Go
module cache. Each license below was verified against the upstream
`LICENSE`/`COPYING` file (or the GitHub license API) at that date, not from
memory. Where upstream licensing is ambiguous, that is stated explicitly rather
than rounded to the nearest well-known license.

---

## 1. Why the project as a whole is GPL-3.0

The server core derives from `sing-box` (GPL-3.0) via `hiddify-sing-box`, the
WG-over-VK relay derives from `qWDTT` (GPL-3.0), and the Go module graph pulls
in `mieru` and the `sagernet/*` libraries (all GPL-3.0-or-later). GPL-3.0 is
therefore not a choice here — it is inherited, and the combined work cannot be
distributed under any weaker terms.

AGPL-3.0 is **not** available as an alternative: GPL-3.0 code cannot be
relicensed to AGPL-3.0. GPL-3.0 §13 permits *combining* with AGPL-3.0 code, but
the GPL-3.0 parts stay GPL-3.0.

### Naming restriction — read this before renaming anything

`sing-box`'s LICENSE carries an additional clause beyond plain GPL-3.0:

> In addition, no derivative work may use the name or imply association with
> this application without prior consent.

Accordingly this project is **not** named after `sing-box` or `hiddify`, does
not use their names or marks in its own name, branding, or domain, and does not
claim endorsement by or association with them. Factual attribution ("derived
from sing-box, which is GPL-3.0, see Third-Party Notices") is required by
GPL-3.0 and is not what that clause prohibits.

---

## 2. Copyleft components — these set the project's license

| Component | Upstream | License | How it is used |
|---|---|---|---|
| sing-box | `SagerNet/sing-box` | **GPL-3.0** + naming clause (above) | Proxy/VPN core. Ancestor of our fork. |
| hiddify-sing-box | `hiddify/hiddify-sing-box` | **GPL-3.0** + naming clause (inherited) | Direct fork parent of our core, absorbed as `core/` (pin in `core/PROVENANCE.md`). |
| qWDTT | `kostfuciy/qWDTT` | **GPL-3.0** | `relay/` is a fork of its `server.go`; the WRAP/RTP/DTLS codec is reused verbatim, so qWDTT clients stay wire-compatible. See `relay/NOTICE.md`. |
| mieru | `enfein/mieru` | **GPL-3.0** | Go dependency of the core (mieru protocol support). |
| sing, sing-tun, sing-mux, sing-quic, sing-shadowsocks, sing-shadowsocks2, sing-cloudflared, fswatch | `SagerNet/*` | **GPL-3.0-or-later** | Go dependencies of the core (the standard sing-box library set). |
| sing-anytls | `SagerNet/sing-anytls` | **GPL-3.0** | Go dependency of the core (pinned module). |
| sing-shadowtls | `SagerNet/sing-shadowtls` | **GPL-3.0** | Fork in `core/replace/sing-shadowtls` (adds `UpdateUsers`). |
| sing-snell | `SagerNet/sing-snell` | **GPL-3.0** | Go dependency of the core (pinned module). |
| sing-vmess | `SagerNet/sing-vmess` | **GPL-3.0** | hiddify's fork in `core/replace/sing-vmess`. |
| podkop | `itdoginfo/podkop` | **GPL-2.0** | OpenWrt-side routing controller, referenced for the router path. GPL-2.0-only is *not* upward-compatible with GPL-3.0 — keep it as a separate, independently-installed package and do not link or merge its code into the GPL-3.0 tree. |
| nDPI test captures | `ntop/nDPI` | **LGPL-3.0** | Packet captures used as sniffer test fixtures. See §5. |

`psiphon-tunnel-core` (GPL-3.0) is a dependency again since the 2026-11-10
rebase onto hiddify/v5, which registers `protocol/psiphon` unconditionally;
`psiphon-quic-go` and `psiphon-tls` are hiddify's forks under `core/replace/`.

Forked dependencies are reached through `replace` directives: `core/go.mod`
points them at `core/replace/<name>/` and the root `go.mod` mirrors every one
of them (only the main module's replaces count). Each keeps its own `LICENSE`.

---

## 3. Permissive components

These impose no license obligation on the combined work beyond preserving their
copyright notices and license text. Forked modules live under
`core/replace/<name>/` with their upstream `LICENSE` beside them.

| Component | Upstream | License |
|---|---|---|
| amneziawg-go | `amnezia-vpn/amneziawg-go` | MIT (Copyright © 2017-2025 WireGuard LLC) |
| wireguard-go | `hiddify/wireguard-go`, absorbed as `core/thirdparty/wireguard-go` | MIT |
| tailscale | `hiddify/tailscale`, absorbed as `core/thirdparty/tailscale` | BSD-3-Clause (Copyright © 2020 Tailscale Inc & AUTHORS) |
| libbpf headers (in tailscale `derp/xdp/headers`) | `libbpf/libbpf` | LGPL-2.1 **OR** BSD-2-Clause — taken under BSD-2-Clause; `LICENSE.BSD-2-Clause` is beside them |
| gooserelay | `kianmhz/GooseRelayVPN`, absorbed as `core/thirdparty/gooserelay` | MIT |
| connect-ip-go | `shtorm-7/connect-ip-go` (upstream `Diniboy1123/connect-ip-go`), absorbed | MIT (Copyright 2024 Marten Seemann) |
| dnscrypt | `shtorm-7/dnscrypt/v2` (upstream `ameshkov/dnscrypt`), absorbed | Unlicense (public domain) |
| vaydns | `hiddify/vaydns` (upstream `net2share/vaydns`), absorbed | CC0-1.0 |
| masque-go | `quic-go/masque-go` | MIT |
| mtg (MTProto proxy) | `9seconds/mtg` | MIT |
| MasterDnsVPN | `masterking32/MasterDnsVPN` | MIT |
| byedpi | `hufrea/byedpi` | MIT |
| uTLS | `metacubex/utls` | BSD-3-Clause (Copyright © 2009 The Go Authors) |
| ja3 | `open-ch/ja3` (`core/common/ja3`) | BSD-3-Clause (Copyright © 2018 Open Systems AG) |
| WinDivert | `basil00/WinDivert` (`core/common/windivert/assets`) | LGPL-3.0 **OR** GPL-2.0 — Windows-only (`//go:build windows`), not part of the Linux core |
| gopacket | `google/gopacket` | BSD-3-Clause |
| cilium/ebpf | `cilium/ebpf` | MIT |
| go-nfqueue | `florianl/go-nfqueue` | MIT |
| suricata-verify DHT capture | `OISF/suricata-verify` | MIT |

### The shipped binaries and what each links

Measured 2026-11-06 with `go list -deps`, classifying every module's `LICENSE`
from the module cache:

| Binary | External modules | Licenses |
|---|---:|---|
| core (`core/cmd/sing-box`, production tags) | 122 | 49 MIT, 38 BSD, 19 Apache-2.0, 9 GPL-3.0(-or-later), 3 Unlicense, 2 ISC, 1 MPL-2.0, 1 CC0 |
| installer (`cmd/spaiter-vpn`) | 99 | the same profile — it imports `core/include` and so links the core's registry and the GPL set above |
| relay (`relay/`) | 8 | 4 MIT (pion, wireguard-go, wintun), 3 BSD (`golang.org/x/*`) — plus `relay/rtpopus{2,3}` (MIT) |

The earlier claim that the installer links "only `wgctrl`, `netlink`, `netns`
and `mdlayher/*`" was wrong and is withdrawn: because it embeds the core's
registry it links the full core graph, GPL parts included. That changes
nothing about the license (the installer is GPL-3.0-or-later either way) but
it does mean the installer tarball carries the same obligations as the core
image, which is why `scripts/release.sh --source` exists.

Apache-2.0 is one-way compatible with GPL-3.0: Apache-2.0 code may be linked
into this GPL-3.0 work, not the reverse.

Note on `suricata-verify`: its capture is MIT even though Suricata itself is
GPL-2.0, because the test corpus lives in a separately-licensed repository. Do
not assume the GPL-2.0 of the main project applies to it — it does not.

---

## 4. `rtpopus2` / `rtpopus3` obfuscation codecs — provenance is unusual, read carefully

**What we ship:** byte-identical copies of the `rtpopus2` and `rtpopus3` wire
codecs, vendored into two places:

- `wdtt-relay/rtpopus2/`, `wdtt-relay/rtpopus3/` (server shim)
- `sing-box/transport/wdtt/rtpopus2/`, `.../rtpopus3/` (client, in the Android
  core fork)

Local additions (`IsRTPOpus2`/`IsRTPOpus3` profile detection and a
non-in-place `UnwrapTo`) are marked as such below the vendored block in each
file and are GPL-3.0 like the rest of this project.

**Upstream:** the FreeTurn project, originally
`samosvalishe/free-turn-proxy`, now **`hackdiaz-dev/free-turn-proxy`**. The
original account was deleted in October 2026 and maintainership was publicly
handed over; the old URL is dead. Any attribution still pointing at
`samosvalishe` must be updated.

**License — and its ambiguity:** each upstream codec source file carries

```
// SPDX-License-Identifier: MIT
```

which is the grant we rely on. However:

1. The upstream repository's root `LICENSE` is **not** a plain MIT file. It is a
   "Happy Bunny License (HBL)" — MIT's text plus the added condition *"You must
   be kind to bunnies."* This is why GitHub reports the repository as
   `NOASSERTION`.
2. Neither the repository `LICENSE` nor the codec files name a copyright
   holder; the root file says only `Copyright (c) 2026`.

We therefore treat the per-file `SPDX-License-Identifier: MIT` as the operative
license for these two directories, attribute them to the FreeTurn project, and
preserve a verbatim copy of the upstream file header as evidence of the grant
as it stood when we copied it. MIT's requirement to preserve a copyright notice
is satisfied as far as it can be: there is no upstream notice to preserve, so
the attribution below stands in its place.

MIT is GPL-3.0-compatible, so vendoring these into a GPL-3.0 work is fine. The
reverse is not true — do not copy our GPL-3.0 modifications back upstream
without relicensing them.

---

## 5. BitTorrent detection — what is ours and what is not

### Detector code: ours

The XDP BitTorrent detection core originates from `spaiter/BitTorrentBlocker`,
an independent Go implementation released under **MIT**, and was incorporated
into the GPL-3.0 core fork (MIT → GPL-3.0 is a permitted direction). The
standalone project remains MIT; keeping it separate is deliberate, so unrelated
projects can still reuse it.

No source code was copied from nDPI, Suricata, libtorrent, or sing-box into the
detectors. The detection logic was reimplemented from protocol specifications
(BEP-3, BEP-15, BEP-29) and from studying those projects' published approaches,
and diverges substantially in practice (explicit false-positive guards for DNS,
DHCP/BOOTP, STUN and DTLS that the sing-box sniffer does not have).

### Test captures: NOT ours — `core/common/sniff/testdata/pcap/`

The sniffer's fixture corpus lives **in this repository**, at
`core/common/sniff/testdata/pcap/` (about 64 MB, 677 files), and ships with the
source. Its per-file provenance is `core/common/sniff/testdata/pcap/NOTICE.md`,
which is authoritative for that directory; the summary:

| Origin | License | Notes |
|---|---|---|
| `ntop/nDPI` (the bulk of `false-positive/` and `true-positive/`) | **LGPL-3.0** | `LICENSE.LGPL-3.0` and `LICENSE.GPL-3.0` sit beside them (LGPL-3.0 is additional permissions on GPL-3.0, so both texts are needed). |
| `zeek/zeek` (`zeek_tracker.pcap`) | BSD-3-Clause | |
| `OISF/suricata-verify` (`suricata-dht.pcap`) | MIT | |
| `camp0/incc` (`torrent-dht.pcap`) | LGPL-2.0-or-later | identified by content hash |
| `tcoppi/BittorrentReconstituter` (`mippo.pcap`) | GPL-3.0 | identified by content hash |
| USTC-TFC2016 via `echowei/DeepTraffic` (`ustc_bittorrent.pcap`) | **MPL-2.0** | checked at the authoritative source — *not* the research-use-only terms an academic dataset might suggest |
| `own_*.pcap` | ours, GPL-3.0-or-later | generated in an isolated lab by `gen-protocol-captures.sh` |

**Resolved on 2026-10-22:** four captures from `goncalo-rodrigues/360BitScoping`
(`bt_6k`, `bt_middle`, `two_torrents`, `small_torrent_mse`) had no license
grant at all and also carried a real person's residential addresses and
unrelated home traffic. They were **deleted** and the coverage they provided
was regenerated in-house. Their absence from the export tree was re-verified on
2026-11-06. There are **no unresolved captures** left.

These are inert test data consumed only by the test suite — not compiled into,
linked into, or shipped inside any binary. LGPL-3.0 therefore does not reach
the detector code. The notice exists so the upstream authors get the
attribution their licenses require, and so nobody has to reconstruct this.

---

## 6. Deliberately NOT used

| Project | License | Why it is excluded |
|---|---|---|
| `amurcanov/csqtt` | **PolyForm Noncommercial 1.0.0** | The author explicitly forbids commercial use. Incompatible with GPL-3.0 and cannot be vendored here. It has been **read for protocol research only**; no code was taken. Keep it that way. |
| `hiddify/hiddify-app` | GPL-3.0 + additional §7 terms | Its extra conditions include **NonCommercial use only**, a requirement to publish derivatives as a GitHub fork of `hiddify-app`, and release-process and naming constraints. Present in the client lab checkout as a UX *reference* only. **Verify by grep that no `hiddify-app` code reaches any build before publishing** — the NonCommercial term is the most invasive obligation in this entire audit. |
| `hiddify/hmrd_multi_resolver_dns` | **none** | No `LICENSE` anywhere in the repository — checked at the pinned commit `8d809dc` (2026-04-29) and at `HEAD` on 2026-11-06 (repository active, last push 2026-11-02, GitHub reports `NONE`). Absent a grant there is no right to redistribute it, so its two consumers — the `dnstt` outbound and the `smart_dns_pool` service — are compiled **only** behind `-tags with_dnstt` (`core/include/dnstt.go` / `dnstt_stub.go`). That tag is in no published build: the production core image and the installer link neither package nor this module (verified with `go list -deps`). It remains a `go.mod` requirement, which is a pointer, not a copy. If upstream adds a license, re-evaluate before enabling the tag by default. |
| `starifly/libneko` | **none** | No license file in the repository and none reported by GitHub. Absent a grant, no redistribution right exists, regardless of the GPL-3.0 licensing of its `MatsuriDayo/libneko` ancestor. Affects the Android client only. Before shipping a client, either take `libneko` from `MatsuriDayo` upstream or obtain an explicit grant from `starifly`. |

---

## 7. Maintenance rules

1. **One commit, one notice.** Adding or vendoring third-party code without
   updating this file is a licensing regression, not a documentation gap.
2. **Verify, do not assume.** Read the upstream `LICENSE` file at the pinned
   commit. GitHub's detected license is a hint; `NOASSERTION` means a human has
   to read it (see §4 — it turned out to be a joke license, and §6 — it turned
   out to be GPL plus NonCommercial).
3. **Record the pin.** Vendored code must record the upstream commit it came
   from, so a future reader can diff it and see what we changed.
4. **Watch the direction.** Permissive → GPL-3.0 is fine. GPL-3.0 → permissive
   and anything → NonCommercial are not.
5. **Dead upstreams still bind you.** A deleted account does not void a license,
   but it does destroy your evidence. Keep a copy of the grant as it stood when
   you copied the code (§4).
