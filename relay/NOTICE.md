# Provenance and licensing

`wdtt-relay` is licensed **GPL-3.0-or-later** ([LICENSE](LICENSE)), and that is
inherited rather than chosen.

## Derived from qWDTT (GPL-3.0)

This program is a fork of `server.go` from
[`kostfuciy/qWDTT`](https://github.com/kostfuciy/qWDTT), which is GPL-3.0.
The WDTT cryptographic and framing layer — `listenWrapped`, the WRAP/RTP/DTLS
codec and `buildClientConfig` — is reused **verbatim**, deliberately: that is
what keeps stock qWDTT clients wire-compatible with this relay.

Removed from the upstream program: its userspace WireGuard implementation, NAT
layer, Telegram bot and web UI. Added here: `shim.go` (a new `main` plus
`shimHandleConn`, doing GETCONF lookup and pooling onto a sing-box WireGuard
endpoint), making this a plain UDP relay that needs neither TUN nor
`NET_ADMIN`.

Because the reused codec is GPL-3.0, this program cannot be distributed under
any weaker license. Note that qWDTT upstream has been effectively dormant since
August 2026 — dormancy does not affect its license or our obligations under it.

## Vendored under a different license

| Directory | Origin | License |
|---|---|---|
| [`rtpopus2/`](rtpopus2/) | FreeTurn, `internal/wire/rtpopus2/` | **MIT** (per-file SPDX) — see [`rtpopus2/LICENSE`](rtpopus2/LICENSE) |
| [`rtpopus3/`](rtpopus3/) | FreeTurn, `internal/wire/rtpopus3/` | **MIT** (per-file SPDX) — see [`rtpopus3/LICENSE`](rtpopus3/LICENSE) |

MIT → GPL-3.0 is a permitted direction, so vendoring these is fine. The
upstream project moved from `samosvalishe/free-turn-proxy` to
`hackdiaz-dev/free-turn-proxy` in October 2026 after the original account was
deleted; each vendored file's header records the copy date, the upstream path,
and a caveat about the upstream repository's unusual root LICENSE. Local
additions in those directories (`IsRTPOpus2`/`IsRTPOpus3`, `UnwrapTo`) are ours
and are GPL-3.0-or-later.

## Scope

Anything in this repository not covered above is original work,
Copyright © 2026 spaiter, GPL-3.0-or-later.

For the full dependency and licensing picture across the whole deployment, see
`THIRD-PARTY-NOTICES.md` in the `spaiter-vpn` umbrella repository.
