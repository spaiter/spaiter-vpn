# Provenance of `core/`

> **Newest chapter: "2026-11-10: re-based onto hiddify/v5" at the end.** It supersedes the
> statements below that `core/` has zero `replace` directives, that `core/thirdparty/`
> holds the forks and that a rebase is no longer possible; the sections above it are the
> history that led there.

This directory is not a copy kept in sync with somewhere else. It is the
project's source of truth for the VPN core, absorbed here on **2026-10-23** so
that one repository builds everything and resolves nothing over the network
beyond ordinary Go modules.

## What was absorbed, and from where

| Path | Taken from | At |
|---|---|---|
| `core/` | `github.com/spaiter/hiddify-sing-box`, branch `extended` | `95c4dcb7eba3688b42b7543ad6d2b3bd70ecc5b4` |
| `core/thirdparty/tailscale` | `github.com/hiddify/tailscale` | `788aa623edebf3e9918919cee4c590b177c61ec4` |
| `core/thirdparty/wireguard-go` | `github.com/hiddify/wireguard-go` | `d85b8f2cc4e47d9590a71f95b65d4408d98fe39c` |
| `core/thirdparty/gooserelay` | vendored in the fork (upstream `github.com/kianmhz/GooseRelayVPN`) | as of the fork commit |
| `core/thirdparty/sing-anytls` | vendored in the fork (upstream `github.com/anytls/sing-anytls`) | as of the fork commit |
| `core/thirdparty/sing-shadowtls` | vendored in the fork (upstream `github.com/sagernet/sing-shadowtls`) | as of the fork commit |
| `core/thirdparty/sing-vmess` | `github.com/starifly/sing-vmess` | `v0.2.7-mod.9` |
| `core/thirdparty/connect-ip-go` | `github.com/shtorm-7/connect-ip-go` | `v1.0.0-extended-1.0.0` |
| `core/thirdparty/dnscrypt/v2` | `github.com/shtorm-7/dnscrypt/v2` | `v2.4.0-extended-1.0.0` |
| `core/thirdparty/vaydns` | `github.com/hiddify/vaydns` | `v0.0.0-20260401180616-890dc987a6a9` |
| `core/thirdparty/sing-snell` | `github.com/reF1nd/sing-snell` | `v0.0.0-20260713132549-9711346e2b35` |

Only git-tracked files were taken. An earlier attempt with `rsync` pulled in
three built binaries (262 MB of `sing-box`, `sing-box-new`, `sing-box-static`)
that happened to be sitting in the fork's working tree.

## Why the module paths were rewritten

Eleven module paths were rewritten so that nothing is reached through a
`replace` directive — the repository had **zero** of them until 2026-11-06,
when three public forks were pinned (see the entry of that date). A `replace` exists
precisely because some module imports a path that has to be substituted, so the
only way to remove one is to absorb every module in that import chain and
rename it.

| Was | Is now |
|---|---|
| `github.com/sagernet/sing-box` | `github.com/spaiter/spaiter-vpn/core` |
| `github.com/sagernet/tailscale` | `…/core/thirdparty/tailscale` |
| `github.com/sagernet/wireguard-go` | `…/core/thirdparty/wireguard-go` |
| `github.com/kianmhz/GooseRelayVPN` | `…/core/thirdparty/gooserelay` |
| `github.com/anytls/sing-anytls` | `…/core/thirdparty/sing-anytls` |
| `github.com/sagernet/sing-shadowtls` | `…/core/thirdparty/sing-shadowtls` |
| `github.com/sagernet/sing-vmess` | `…/core/thirdparty/sing-vmess` |
| `github.com/Diniboy1123/connect-ip-go` | `…/core/thirdparty/connect-ip-go` |
| `github.com/ameshkov/dnscrypt/v2` | `…/core/thirdparty/dnscrypt/v2` |
| `github.com/net2share/vaydns` | `…/core/thirdparty/vaydns` |
| `github.com/sagernet/sing-snell` | `…/core/thirdparty/sing-snell` |

`github.com/sagernet/sing-dns` was replaced in the fork but imported by
nothing, so it was simply dropped.

### kcp-go: the replace that never did anything

`core/thirdparty/vaydns` carries, in its own `go.mod`,
`replace github.com/xtaci/kcp-go/v5 => github.com/net2share/kcp-go/v5`. That
replace was **never in effect**, before or after the absorption, because a
replace directive in a dependency's `go.mod` is ignored — only the main
module's count. `go.sum` is the proof: the fork's has zero entries for
`net2share/kcp-go` and pins `xtaci/kcp-go/v5 v5.6.70` with the same hashes this
repository now has. The deployed core has always used upstream kcp-go.

It was deliberately **not** absorbed, and that is a decision rather than
inertia. The fork sits on an older base — vaydns asks for v5.6.61 where the
build resolves v5.6.70 — so adopting it would downgrade kcp-go by nine patch
releases. Its content is also not a dnstt fix: 1,755 changed lines that are
overwhelmingly cosmetic (added comments, reflowed constant blocks,
`defer mu.Unlock()` rewritten as an explicit `Unlock()` before each return).

This is recorded because the dead replace is a landmine: it reads like a patch
someone forgot to apply. It is not. `vaydns/client` — the only part of vaydns
the core imports, for the dnstt outbound — does use kcp, so the dependency is
real even though the patch is not.

## What this costs, and it is the main thing to understand

**Rebasing onto upstream is gone.** The fork carried 32 commits on top of
`hiddify/v5` and they were replayed onto a moving upstream; upstream keeps its
own module path, so every future rebase would now conflict in ~2,500 files.
Taking an upstream change means porting it by hand into this tree.

The fork repository remains the historical record — its 219 MB of history was
deliberately not imported, because after a path rewrite that moves and edits
every file the history is no longer usable for a rebase anyway.

## What was removed to get to zero replaces

`protocol/psiphon`, and with it the two `replace` directives for
`github.com/Psiphon-Labs/{psiphon-tls,quic-go}`. Those existed to patch what an
**external** module (`psiphon-tunnel-core`, 616 files, four replaces of its
own) imports, and renaming our copies could not have removed them.

Checked before deleting, because psiphon was a capability someone might rely
on: `include/registry.go` registers it as an **outbound only**, so a server can
never use it; `vpn-bot` emits it in no subscription; the live config contains
it nowhere; and the Android client that actually gets built references it in no
file. The only remaining mentions anywhere were `u_prng.go` in uTLS, whose
copyright header credits Psiphon Inc. for a PRNG, and the `hiddify-app`
checkout that `THIRD-PARTY-NOTICES.md` §6 excludes from every build.

Side effect worth knowing: psiphon-tls hard-coded the memory layout of
`crypto/tls.ConnectionState` through `unsafe`, and Go 1.26 changed it, so the
fork panics in `init` when built with Go 1.26. **Dropping psiphon is what
unblocks Go 1.26 for this core** — verified by building and running it on both
1.25.6 and 1.26.5.

## Local changes to the absorbed code

Kept deliberately few, and each marked `//H` in the source:

- `experimental/clashapi/userstats.go` — `Close`/`Start` now tolerate a nil
  receiver. The stats database lives beside `config.json`, so when that
  directory is not writable the manager is never built, yet the typed nil stays
  in the clash API's closer list and the process died on shutdown *after* a
  successful `sing-box check`. Reproduced on the published image's own binary
  first, so this is a fix and not an accommodation of something local.
- Generated protobuf files (`*.pb.go`) had their serialised file descriptors
  repaired. A textual path rewrite changed the `go_package` string inside
  `rawDesc` without its length prefix, which made the descriptor unparseable
  and panicked every binary in `init`. The prefixes were recomputed (+7 bytes,
  the delta between the old and new module path); `protoc` is not installed on
  this host, so regeneration was not an option.

## Rebuilding the core

    docker build -f Dockerfile.core --build-arg VERSION=<version> -t <tag> .

or directly, with the production tag set:

    CGO_ENABLED=0 GOTOOLCHAIN=go1.27.0 go build -trimpath \
      -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_ccm,with_ocm,with_cloudflared,badlinkname,tfogo_checklinkname0,with_grpc,with_awg,with_xdp,with_masque" \
      -ldflags "-X 'github.com/spaiter/spaiter-vpn/core/constant.Version=<version>' -checklinkname=0 -s -w" \
      -o sing-box ./core/cmd/sing-box

`with_dnstt` is deliberately **absent** from that set. It is the only tag that
compiles the `dnstt` outbound and the `smart_dns_pool` service, and with them
`github.com/hiddify/hmrd_multi_resolver_dns`, which has no license grant (see
`NOTICE.md` and `THIRD-PARTY-NOTICES.md` §6). Leave it out of every published
build; the module then stays a `go.mod` requirement only and is not linked.

⚠️ Dependency versions are pinned to the set the fork actually built with (781
modules, captured from its build list). Do not let `go mod tidy` drift them
casually: freed from the fork's pruned module graph, tidy pulls newer releases
that require Go 1.26 — `protobuf` 1.36.12, `x/sys` 0.48.0 and
`raft-boltdb` 2.4.2 each did — and the `-checklinkname=0` layer is only valid
against the standard library it was written against.

### Dependencies added since, and what was checked

`scripts/check.sh deps` fails whenever `go.mod` or `go.sum` changes, so each
addition below had to be argued for rather than noticed later. The check that
matters is not "does it build" but "did the graph move": a dependency with
transitives of its own can bump a module the core links, and the
`-checklinkname=0` layer is only valid against the exact standard library and
module set it was written against.

| module | version | added | transitives |
|---|---|---|---|
| `github.com/go-telegram/bot` | v1.27.0 | 2026-11-03 | none |
| `github.com/skip2/go-qrcode` | v0.0.0-20200617195104 | 2026-11-03 | none |
| `filippo.io/age` | v1.2.1 | 2026-11-05 | none in the build (`golang.org/x/crypto`, already required) |

age encrypts `spaiter-vpn backup`. Chosen over a construction of our own
because it is reviewed and because an operator can open a backup with the stock
`age -d` when this binary is gone, which is exactly when a backup is needed.
The diff is one go.mod line and two go.sum lines; `go mod tidy` was not used,
since it would also prune requirements the core needs under its build tags.
It is linked into the CLI's backup and restore commands, not the core.

The QR encoder is there because a phone user scans a config rather than
retyping a 300-character link. Same criterion, same check: one line in go.mod,
two in go.sum, nothing else in the diff, and it is linked into the bot alone.

The Telegram library was chosen for having no dependencies at all — the only
criterion that protects the graph. Verified by building the core with the
production tags before and after the addition and comparing symbol tables
(`go tool nm -size`):

- 116 880 symbols on both sides, and comparing by name and size alone shows a
  single difference: `runtime.modinfo.str` grew by 5 bytes.
- Those 5 bytes are `+dirty` appended to the main module's version in the build
  info, because the working tree had an uncommitted `go.mod`. `go version -m`
  on the two binaries differs only in that and `vcs.modified`.
- The library does not appear in the core binary's build info at all, which is
  the expected outcome: the core does not import it. It is linked into the bot,
  which is the same binary only in the sense that `spaiter-vpn` has a `bot`
  subcommand.

A rebuild after committing cannot be byte-identical to either, since the module
version embedded in the build info contains the commit. Comparing symbol names
and sizes is the stable form of this check; comparing addresses is not, as
read-only data shifts by an alignment boundary whenever `modinfo` changes
length.

## 2026-11-10: dependency refresh after govulncheck (deps digest refreshed)

`govulncheck` in source mode, run with the production build tags from
`Dockerfile.core`, reached 17 known vulnerabilities from the core binary and
10 from `cmd/spaiter-vpn`. The ones that matter here are the five HTTP/2
server issues in `golang.org/x/net` 0.57 (GO-2026-6603, -6610, -6611, -6612,
-6617: memory exhaustion via trailers, CPU burn via window changes, a double
flow-control refund and an HPACK encoder race), reachable through
`transport/v2rayhttp`, `transport/v2raygrpclite`, `protocol/naive` and the
API server, and the gRPC transport issues in `google.golang.org/grpc` 1.79
(GO-2026-6348 OOM, -6443 panic, -4762 path bypass, -6061) reachable through
`transport/v2raygrpc`. The rest: `klauspost/compress` (panic on two-block
frames), `andybalholm/brotli` (decompression memory), `go-chi/chi` (RealIP
spoofing, used by the Clash API), `cilium/ebpf` (BTF integer overflow, the XDP
blocker), `go-jose` (JWE panic, cloudflared), `insomniacslk/dhcp` (malformed
IPv4 packet), `x/crypto/ssh` (channel deadlocks), `x/text/secure/precis` and
`x/mod/sumdb`.

Moved, each to the first release the Go vulnerability database names as fixed
or the current one: `golang.org/x/net` 0.57.0 → 0.62.0, `x/crypto` 0.54.0 →
0.58.0, `x/text` 0.40.0 → 0.44.0, `x/mod` 0.37.0 → 0.43.0,
`google.golang.org/grpc` 1.79.1 → 1.85.0, `klauspost/compress` 1.18.3 →
1.20.4, `andybalholm/brotli` 1.2.0 → 1.2.8, `go-chi/chi/v5` 5.2.5 → 5.5.0,
`cilium/ebpf` 0.20.0 → 0.22.0, `go-jose/v4` 4.1.3 → 4.1.9,
`insomniacslk/dhcp` to the 2026-10-14 pseudo-version. Transitives that `go
mod tidy` pulled along: `x/oauth2`, `x/sync`, `x/sys`, `x/term`, `x/tools`,
`google.golang.org/protobuf` 1.36.12, `genproto/googleapis/rpc`,
`spf13/pflag` 1.0.10. Upstream sing-box (`testing`, 2026-11) still pins
x/net 0.57, grpc 1.79.1 and chi 5.2.5, so this tree is ahead of it here.

The go1.27 variant of `transport/v2rayhttp/force_close.go` links against
x/net 0.62's `http2.Transport` unchanged: the core built with the full tag set
and `-checklinkname=0`, `go vet` and the unit tests passed on go1.27.2, and a
second `govulncheck` run on the result reports only GO-2026-6809
(`crypto/x509`), which is a toolchain matter fixed in go1.27.3, the version
the core image builds with.

## 2026-11-09: Go 1.27 (deps digest refreshed)

The `go` directive went from `1.25.6` to `1.27.0` in `go.mod`, `relay/go.mod`
and `core/test/go.mod`. One dependency moved with it:
`github.com/go-json-experiment/json` from the 2025-08-13 pseudo-version to
`v1.27.2`. That module aliases itself to the standard library's
`encoding/json/v2` under the `goexperiment.jsonv2` tag, which Go 1.27 sets by
default, and the old snapshot named `json.SkipFunc` and
`json.DiscardUnknownMembers`, both gone from the 1.27 standard library; the
project now tags releases after the Go version they track. Only
`core/thirdparty/tailscale/drive` imports it, which no published build links
(`with_tailscale` is absent), but `go build ./...`, vet and the tests compile
it. `go get` under Go 1.27 also merged the six `require` blocks into two, the
form `go mod tidy` produces for `go 1.27` modules; no other version changed
(checked by diffing the sorted `module version` pairs). The digest covers
`go.mod` and `go.sum`.

Go 1.27 also broke the link of every binary: `golang.org/x/net/http2` now
wraps the standard library's `net/http/internal/http2` on go1.27, so the
`(*Transport).connPool` method that `transport/v2rayhttp/force_close.go`
pulled in with `//go:linkname` no longer exists ("relocation target ... not
defined"). Three upstream sing-box commits were ported verbatim:
`f50ca2244` (force_close split into `_legacy` / `_go127` / `_go127_stub`;
the go1.27 variant reaches the standard library's pool and needs the
`badlinkname` tag, which every core build carries, while a build without it
falls back to `CloseIdleConnections`), `4658dfc6c` (a `var _ *tls.Conn`
anchor in `common/badtls/registry.go` so the compiler records the method
symbols before the linkname pulls), and `a25ad8ce5` (sing-mux `v0.3.6`, the
h2mux fix for 1.27). The go1.27 variant needs `(*Transport).init` to return
the inner `*http.Transport`, which x/net gained in `v0.57.0` (upstream's
version), so `golang.org/x/net` moved `v0.56.0` → `v0.57.0` and pulled its
siblings along: x/crypto `v0.54.0`, x/mod `v0.37.0`, x/sync `v0.22.0`,
x/sys `v0.47.0`, x/term `v0.45.0`, x/text `v0.40.0`, x/tools `v0.47.0`.
Nothing else in the graph changed. Dockerfile.core and relay/Dockerfile build on
`golang:1.27-alpine` (GOTOOLCHAIN=local as before). The reason is the
`goroutineleak` profile, generally available in `runtime/pprof` since Go 1.27
and served by the core through `experimental.debug.listen`. The directive also
puts goroutine labels into traceback headers (`tracebacklabels`); nothing in
this module sets goroutine labels, so nothing new appears there. The
`//go:linkname` sites that make `-checklinkname=0` necessary (common/badtls,
common/ktls, experimental/libbox/internal/oomprofile, service/oomkiller,
transport/v2rayhttp) were built and tested against go1.27.2 on 2026-11-09.

## 2026-11-06: `godebug multipathtcp=0` in go.mod (deps digest refreshed)

The module graph did not move; `go.mod` gained a `godebug multipathtcp=0`
directive, which the digest covers. Go 1.24+ listens on Multipath TCP by
default and CVE-2026-98432 made an IPv4 MPTCP listener a remote root. The
`-X internal/godebug.defaultGODEBUG=multipathtcp=0` link flag inherited from
upstream named a symbol that does not exist, so every published core listened
on MPTCP; the directive reaches every build of the module, and
`common/listener` now sets MPTCP off explicitly unless `tcp_multi_path` asks.
Ported from hiddify-sing-box `9aca6c8c1`.

## 2026-11-06: three pinned forks and mieru 3.38.2 (deps digest refreshed)

Nine server-side fixes were ported from hiddify-sing-box v5 (`6a545ead1`).
Six are in this tree: the XHTTP stream-down handler closes its connection when
the client goes away and `uploadQueue.Close` no longer waits for a `Push`
blocked on a full queue (`transport/v2rayxhttp`); TCP dials through the awg,
masque and wireguard netstacks get `C.TCPTimeout` instead of waiting for a SYN
answer forever; `Router.RoutePacketConnection` returns after a failed route
instead of parking a goroutine until shutdown; Reality rejects a `short_id`
longer than 16 hex digits on both sides instead of panicking in `hex.Decode`;
and DNS waiters rejoin the per-question lock after a failed query so they share
one new query. `github.com/enfein/mieru/v3` moved from v3.27.0 to v3.38.2,
which dropped its docker and raft dependencies from the graph (that is the
large negative diff in go.sum).

Three fixes live in libraries, so `go.mod` gained its first `replace`
directives. Each fork keeps the upstream module path, starts from the exact
commit that was pinned before, and carries exactly one commit:

| Upstream pin | Fork | Fix |
|---|---|---|
| `sagernet/gvisor` `20b7e9b2d7e2` | `github.com/spaiter/gvisor@3dd6df2` | `tcp.handleConnecting` returns when a failed handshake already cleared `ep.h` (nil deref crash) |
| `sagernet/sing` `2ded2af32d3d` | `github.com/spaiter/sing@4ae1b43` | `bufio.CachedConn` buffer is taken under a mutex (double release on concurrent Close) |
| `amnezia-vpn/amneziawg-go/v3` `1b86b2ae0e49` | `github.com/spaiter/amneziawg-go@69ea60a` | `netstack.Close` no longer closes `incomingPacket` under a concurrent writer (send on closed channel) |

The forks are public so that a clean `git clone` + `go build` still works
without any local path. `git diff <upstream pin>..main` in each fork shows the
single fix and its test, nothing else. The hiddify versions of `cache.go` and
`tun.go` were not taken verbatim: theirs sit on sing 0.9.7 and on
`sagernet/gvisor` respectively, so only the fix hunks were applied to our
pinned bases. The DNS fix was likewise re-applied to this tree's older
`dns/client.go`, whose exchange path hiddify has since restructured.

## 2026-11-06: client-side fixes from hiddify v5 (no dependency change)

The second batch from the same review, all in this tree. `protocol/wireguard`
lets the kernel fragment WireGuard's UDP (`UDPFragmentDefault`, as official
WireGuard and our AWG endpoint already did): with DF set, a tunnel inside
another tunnel dropped every packet over the path MTU. `transport/wireguard`'s
`ClientBind` bounds the detour dial by `C.TCPTimeout` and reads its
connection atomically. The absorbed `thirdparty/wireguard-go` gains the rebind
logic from `hiddify/wireguard-go` `f191d6751` and `b46c4143a`
(`device/handshake_rebind.go`, `scheduleBindUpdateAfter`): after three
unanswered handshake initiations on a dead session, or when a handshake cycle
gives up, the bind is reopened on a new ephemeral port (a configured
`listen_port` is kept), at most once per `RekeyAttemptTime`; a receive routine
that gives up on its socket also schedules a reopen instead of leaving the
tunnel deaf until a network change. `common/tls` applies `fragment` and
`record_fragment` to REALITY, which skipped them. `protocol/shadowsocks`
writes the SS2022 request header before returning the connection, so a reader
that starts during an early first write no longer fails with "bad request
salt".

Not taken from that batch: hiddify's MASQUE HTTP/3 → HTTP/2 fallback, because
it belongs to their rewritten `transport/http` layer and our MASQUE (the
Cloudflare WARP transport) picks h2 or h3 statically from the endpoint type;
and MTU discovery for WireGuard endpoints, a 500-line feature on top of
endpoint internals (`device_peer_router`) this tree does not have.

## 2026-11-10: re-based onto hiddify/v5 `e70a33ec6` (sing-box 1.15.0-alpha.13 ⊇ 1.14.4); `core/` is a nested module again

The absorbed tree sat on hiddify/v5 of 2026-07-09 (merge-base `706727617`, 1.14.0-alpha.26).
Upstream moved 979 commits (+414k lines) and rewrote the v5 history, and the zero-replace
layout above made every upgrade a rewrite of ~17 module paths plus a repair of every
`*.pb.go` descriptor. Both facts together decided the change of policy recorded here:

**`core/` is the fork itself, module `github.com/sagernet/sing-box`, with its own
`go.mod`.** The root module reaches it through `replace github.com/sagernet/sing-box =>
./core` and mirrors every replace directive of `core/go.mod` with a `./core/` prefix (only
the main module's replaces count). The forks the fork needs live in `core/replace/<name>/`
as plain directories (hiddify keeps them as submodules of `github.com/hiddify/<name>`), so
a clean clone still builds without reaching anything but ordinary Go modules.
`core/thirdparty/` is gone; what it held is now either in `core/replace/` (wireguard-go,
tailscale, sing-vmess, sing-shadowtls) or an ordinary pinned module (connect-ip-go, dnscrypt,
vaydns, sing-snell, sing-anytls, GooseRelayVPN). First-party imports moved from
`github.com/spaiter/spaiter-vpn/core/…` to `github.com/sagernet/sing-box/…` (14 files).

### How the series was carried over

The historical record is `github.com/spaiter/hiddify-sing-box`, branch `extended`
(`95c4dcb7e`): 32 commits on hiddify/v5 `13267cb94`. They were rebased onto `e70a33ec6`
as branch `upgrade/v5-20261110` and this tree is `git archive` of its head plus the
contents of the `replace/` submodules. 27 commits survived; five were dropped, each
because upstream now does the same thing. A 28th commit carries what this directory had
acquired after the absorption and `extended` never saw (per-user MTProto secrets and
speed limits, per-inbound statistics, naive user reload, masque-wg and xhttp fixes with
their tests, the WARP registration `port` option, the shadowsocks 2022 dial); it is a
tree diff of the old `core/` against `extended`, rebased onto v5, and wherever v5
already had the same change the v5 text was kept:

| dropped | why |
|---|---|
| `integrate: XDP core … route hook onto v5` | patch contents already upstream (git found it empty) |
| `fix(submodule): pin tailscale to working 788aa623` | v5 is on tailscale 1.102.1; `with_tailscale` is not built anyway |
| `fix(gooserelay): vendor v1.7.1 shim in-repo` | v5 pins `hiddify/GooseRelayVPN`; GooseRelay was torn down 2026-08-15 |
| `fix(awg): bind a real listening UDP socket on listen_port` | v5 `transport/awg/h_listen.go` gives a server `conn.NewStdNetBind()`; our version replaced the client bind's `Open` with `net.ListenUDP`, which broke the detour path (three `TestH_*` in `transport/awg` fail with it, pass without) |
| `Restore the libbox bridge types` | `experimental/libbox/platform.go` upstream declares them |

What upstream absorbed meanwhile, so our commits shrank to the parts it does not have:
peer attribution (`hiddify/peeruser`, `AwgPeerOptions.Username` under json `name`) replaced
our `peerNameTable`; AWG 3.x options (`AwgRange`), the domain-peer deferral, MTU
discovery/fallback and the server listen bind are theirs. Kept as ours: the gVisor stack
tun that routes peers' flows through the router (`transport/awg/device_stack.go`, now on
sing-tun 0.9.7's `NewUDPForwarder(ctx, stack, handler, nil, UDPNatOptions{Timeout})`), the
per-user stats / `/manage` / `/stats` / `/panel` layer, XDP blocker with the tunnel-address
→ peer-endpoint mapping, the BitTorrent detector and pcap corpus, mtproto, masque-wg,
hot-reload of users/peers, snell users in `/manage`.

Adaptations made while rebasing (each visible as the resolution of the respective commit):

- Lifecycle: `Start(stage)` became `Start(stage, scope *adapter.Scope)`; components
  register their `Close` with `scope.Add` at `StartStateInitialize` (clash server, XDP
  service, mtproto and masque-wg inbounds).
- `header_protection_key` stays **base64** on the wire (the Amnezia `.conf` form the bot
  emits; `awg3-in` in production carries a 44-char key) and is hex-encoded for the UAPI;
  64 hex digits pass through for upstream-style configs. Upstream alone would reject the
  live config.
- `peerUsers` is an `atomic.Pointer` so `ReloadPeers` can swap it; `genIpcConfig` keeps
  upstream's `net.JoinHostPort` (IPv6 peers) and the peer block is `genIpcPeer`.
- shadowsocks reload uses upstream's `usersAccess`/`userName` instead of our atomic copy;
  anytls reload uses upstream `sing-anytls`'s `MultiService.UpdateUsers(names, passwords)`,
  which is now race-free, so that vendored copy is gone. `sing-shadowtls` still has no
  setter: `core/replace/sing-shadowtls` is the pinned `v0.2.2-0.20260928201441` plus
  `users atomic.TypedValue` + `UpdateUsers` (marked `//H`).
- The inbound/endpoint managers' `Remove` left the interfaces (hiddify's own box-level hot
  reload, `h_box_hotreload.go`, 2026-10-08, kept it on the implementations); `apply.go`
  reaches it through a type assertion. Whether our per-inbound apply should give way to
  that reload is an open question, not decided here.
- `UserStatsManager.Start/Close` tolerate a nil receiver (the typed-nil-in-closer-list
  case from the 2026-10-23 entry) — it is in the series now, not a local edit.

Carried from the 2026-11 entries above and checked against the new base: `godebug
multipathtcp=0` is in v5's `go.mod`; the Go 1.27 `force_close_go127.go` split and the
`badtls` anchor are upstream; the `bufio.CachedConn` mutex and the amneziawg
`netstack.Close` fix are in hiddify's `replace/sing` and `replace/amneziawg-go`; the gvisor
`handleConnecting` fix is in hiddify's `replace/gvisor` as well (their variant, marked `H:`). The three pinned
`github.com/spaiter/{gvisor,sing,amneziawg-go}` forks are therefore gone from the root
`go.mod`. `psiphon` is registered unconditionally by v5 (`include/registry.go`); it was
removed from the absorbed tree because `psiphon-tls` panicked in `init` on Go ≥ 1.26 — v5
builds on go 1.27 with `replace/psiphon-tls`, verified by running the binary (below).
The `with_dnstt` gate (license, THIRD-PARTY-NOTICES.md §6) now covers three outbounds,
not one: `dnstt`, `masterdns` and `soar` all consume `hiddify/hmrd_multi_resolver_dns`
through `common/dnspool`, so `include/dnstt.go` registers all of them and
`include/dnstt_stub.go` makes each report "not included in this build". `smart_dns_pool`
as a service no longer exists upstream. None of them is in a published build.

### Go 1.27's goroutineleak profile is not safe on this core

`/debug/pprof/goroutineleak` marks what it reports as leaked for good (`_Gleaked`). The gVisor
stack of the awg endpoint always looks leaked to it: sixteen `tcp.(*processor).start`
goroutines park in `sleep.(*Sleeper).Fetch`, whose waker the GC cannot see. They are not
leaked, but the next packet that wakes one is `fatal error: bad g->status in ready`. On
2026-11-10 this took the production core down within minutes of the first query (the
container restarted by itself). The constant 16 (before and after traffic) is that stack,
not growth. `debug_http.go` now answers 409 to the route unless `?force=1`, and
`test/acceptance/goroutineleak-probe.sh` forces it on its disposable VM and expects exactly
those sixteen stacks. Earlier cores showed 0 because their awg stack was not seen this way;
if the count ever differs from 16, or other stacks appear, that is a finding.
