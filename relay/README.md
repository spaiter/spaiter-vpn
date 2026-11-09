# wdtt-relay

A server-side **WDTT (WireGuard-over-VK-TURN) relay shim**. It terminates the
WDTT obfuscation layer and hands plain WireGuard to a sing-box endpoint.

```
client (qWDTT, or the native wdtt outbound — not from this repository)
      │  WRAP / RTP / DTLS, carried over VK Calls TURN relays
      ▼
wdtt-relay  ──  strips obfuscation, pools connections
      │  plain WireGuard, UDP
      ▼
sing-box  wg-wdtt-in endpoint  ──  routing, sniffing, egress
```

Because obfuscation terminates here and WireGuard is handed on untouched, this
process needs **no TUN device and no `NET_ADMIN`** — it is a pure UDP relay.

## Where the client half lives, and why not here

Everything WDTT on the client side comes from the client tree
(`proxy-vpn-client-lab/sing-box`): the `wdtt` outbound, the VK-TURN bridge
behind it, and `cmd/wdtt-checkhash` / `cmd/wdtt-bridge-test`. `core/` in this
repository has none of it, and should not grow any:

- **There is no `wdtt` inbound anywhere** — not here, not in the client tree,
  which registers only an outbound. So sing-box cannot terminate WDTT at all;
  this relay is not a stopgap for a missing feature, it is the only
  implementation of that side.
- **A `wdtt` outbound would have nothing to dial.** Its whole purpose is to
  wrap WireGuard in a VK-TURN bridge and send it to a server; the live server
  config has exactly one outbound, `direct`. Compare `masque`, which *is* in
  `core/` and is used server-side, because the bot's `WARP_BIN` registers WARP
  accounts with it.

The one thing this costs is that `core/` cannot validate a `wdtt` config, so
`internal/bot/clientcfg/contract_test.go` checks the bundle's WG-over-VK node against the client
core instead — which is the right counterpart anyway, since that is what reads
it.

## What this is not

This is **not** qWDTT, and not an Android client. It is a fork of qWDTT's
`server.go`, stripped down to the relay role: the upstream userspace WireGuard
implementation, NAT layer, Telegram bot and web UI are all removed, and
`shim.go` replaces `main` with a GETCONF lookup plus a connection pool onto
sing-box.

The WDTT crypto and framing layer is reused **verbatim**, on purpose: stock
qWDTT clients stay wire-compatible with this relay. See [NOTICE.md](NOTICE.md)
for full provenance and licensing.

## Obfuscation profiles

Three profiles coexist and are auto-detected **per packet**, so clients of
different vintages can connect simultaneously and older ones degrade
gracefully:

| Profile | Shape |
|---|---|
| `v1` (legacy) | RTP header without extensions + ChaCha20-Poly1305 |
| `rtpopus2` | RTP + RFC 8285 one-byte extensions (audio-level, transport-cc) |
| `rtpopus3` | 3 extensions (+ abs-send-time), variable timestamp step, VAD/loss mimicry |

`rtpopus2`/`rtpopus3` are vendored from the FreeTurn project under MIT — see
[`rtpopus2/LICENSE`](rtpopus2/LICENSE) and [`rtpopus3/LICENSE`](rtpopus3/LICENSE).

## Usage

```
wdtt-relay \
  -listen      0.0.0.0:56000  \  # DTLS/WRAP listener (UDP)
  -wg-endpoint 127.0.0.1:10879 \  # sing-box wg-wdtt-in UDP endpoint
  -wg-pubkey   <base64>        \  # sing-box wg-wdtt-in public key
  -config-dir  /etc/wdtt       \  # holds passwords.json
  -dns         8.8.8.8            # DNS handed to clients in their WG config
```

`-password` sets an optional owner password.

**`SIGHUP` reloads `passwords.json`** without dropping live sessions — this is
how per-user provisioning takes effect.

### Gotcha: the config needs a seed entry

`passwords.json` must contain at least one entry (a placeholder such as
`__seed_*` is enough). With zero keys, `listenWrapped` fails at startup.

`passwords.json` holds per-user WRAP passwords and is in `.gitignore` — it is
runtime state, never commit it.

### Gotcha: the listen port must be synchronised in four places

When moving the WDTT port, update **all four** or inbound traffic is silently
dropped: the `-listen` flag, the provisioning bot's `WDTT_DTLS_PORT`, the
router's port forwarding entry, and the host firewall rule. A mismatch in the
firewall alone produces the exact symptom of "client connects to TURN fine,
server sees zero packets".

## License

**GPL-3.0-or-later** — see [LICENSE](LICENSE), inherited from qWDTT. Provenance
and third-party licensing: [NOTICE.md](NOTICE.md).

Note: the Go module is still named `wg-turn-client`, a leftover from the fork's
ancestry that does not match this repository's role.
