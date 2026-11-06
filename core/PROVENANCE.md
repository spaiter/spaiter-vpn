# Provenance of `core/`

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
`replace` directive — the repository has **zero** of them. A `replace` exists
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

    CGO_ENABLED=0 GOTOOLCHAIN=go1.25.6 go build -trimpath \
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
