# Provenance and licensing of the packet captures in this directory

**The captures in this directory are third-party test data with their own
licenses.** This file travelled here with them.

This corpus was migrated on 2026-10-22 from the standalone
`spaiter/BitTorrentBlocker` project into this fork, because the sniffers in
`common/sniff/bittorrent.go` are what actually runs in production -- the
library was a separate NFQUEUE tool. Paths and framing in the notes below may
still refer to that project.

Licensing got simpler in the move rather than harder: this fork is GPL-3.0, and
every capture here is LGPL-3.0 (nDPI), GPL-3.0 (BittorrentReconstituter),
MPL-2.0 (USTC-TFC2016), BSD-3-Clause (Zeek), MIT (suricata-verify) or ours.
All of those are compatible with GPL-3.0, so the awkward part of the original
arrangement -- copyleft test data sitting inside an MIT repository -- no longer
applies.

| File set | Count | Origin | License |
|---|---:|---|---|
| `false-positive/` (all but `zattoo.pcap`) | 653 | `ntop/nDPI`, `tests/cfgs/default/pcap/`. 599 imported earlier; **54 added 2026-10-22 from nDPI commit `2b8c2989`** (dev HEAD, dated 2026-10-20). | **LGPL-3.0** |
| `false-positive/zattoo.pcap` | 1 | `ntop/nDPI`, same path — **deleted upstream** 2026-04-21 (commit "Recoded some legaci nDPI code", #3170). Byte-verified against nDPI commit `7714507f`. | **LGPL-3.0** |
| `true-positive/bittorrent.pcap`, `bittorrent_tcp_miss.pcapng`, `bittorrent_utp.pcap`, `bt-dns.pcap`, `bt-http.pcapng`, `bt_search.pcap`, `tls_torrent.pcapng` | 7 | `ntop/nDPI`, same path | **LGPL-3.0** |
| `true-positive/suricata-dht.pcap` | 1 | `OISF/suricata-verify`, `tests/bittorrent-dht/input.pcap` (renamed on import) | **MIT** |
| `true-positive/zeek_tracker.pcap` | 1 | `zeek/zeek`, `testing/btest/Traces/bittorrent/tracker.pcap` (renamed on import). Byte-verified, MD5 `6944d30816f6`. | **BSD-3-Clause** (Copyright © 1995-now The Regents of the University of California / LBNL / ICSI) |
| `true-positive/targusdataspeed_dht.pcap` | 1 | **Byte-identical to nDPI's `targusdataspeed_false_positives.pcap`** (MD5 `112a7f4c5ba8`), found when importing the 2026-10-22 batch. See "Upstream folder semantics" below — despite its upstream name the packets really are BitTorrent DHT. | **LGPL-3.0** |
| `true-positive/torrent-dht.pcap` | 1 | `camp0/incc`, `test/pcapfiles/torrent-dht.pcap`. Byte-verified, MD5 `10f2f8dfa269`. | **LGPL-2.0-or-later** (Copyright © 2013 Luis Campo Giralte) |
| `true-positive/mippo.pcap` | 1 | `tcoppi/BittorrentReconstituter`, `sample_pcaps/mippo.pcap`. Byte-verified, MD5 `3e96729587ff`. | **GPL-3.0** |
| `true-positive/ustc_bittorrent.pcap` | 1 | USTC-TFC2016 `Benign/BitTorrent.pcap`, via `davidyslu/USTC-TFC2016`, originating from `echowei/DeepTraffic` (Wei Wang, USTC). Byte-verified, MD5 `87601973859f`. | **MPL-2.0** |
| `true-positive/own_*.pcap` (10 files) | 10 | **Ours.** Generated 2026-10-22 by `test/tools/gen-own-captures.sh` (MSE) and `gen-protocol-captures.sh` (the rest) in an isolated lab; content is locally generated random bytes. One of the ten is synthetic rather than captured — see "Owned protocol fixtures" below. | **MIT**, same as the repository |

Verified 2026-10-22 by name-matching against the upstream `ntop/nDPI` `dev`
tree, the `zeek/zeek` `master` tree and the `OISF/suricata-verify` `master`
tree; by cross-hashing all local captures against each other; and by
byte-comparing against upstream where a candidate was found. Spot checks
`bittorrent.pcap`, `bittorrent_utp.pcap` and `443-chrome.pcap` are MD5-identical
to their nDPI originals.

## Licenses

- [`LICENSE.LGPL-3.0`](LICENSE.LGPL-3.0) — the nDPI-derived captures.
- [`LICENSE.GPL-3.0`](LICENSE.GPL-3.0) — LGPL-3.0 is a set of additional
  permissions layered on top of GPL-3.0, so the GPL-3.0 text is required to read
  the LGPL-3.0 grant. It does **not** mean anything here is GPL-3.0-only.
- `true-positive/suricata-dht.pcap` is MIT and `zeek_tracker.pcap` is
  BSD-3-Clause — both permissive.
- `true-positive/torrent-dht.pcap` is LGPL-2.0-or-later, `mippo.pcap` is
  GPL-3.0, and `ustc_bittorrent.pcap` is MPL-2.0. All three are genuine
  open-source grants that permit redistribution with notice, which is what this
  file provides. MPL-2.0 in particular is **not** the research-use-only
  restriction an academic dataset might have suggested — it was checked at the
  authoritative source (`echowei/DeepTraffic`) rather than assumed.

LGPL-3.0 is weak copyleft and these files are inert test data consumed only by
the test suite — they are not linked into, compiled with, or distributed as part
of `btblocker`. The MIT licensing of the detectors therefore stands. This notice
exists so that nobody has to reconstruct that reasoning later, and so the
upstream authors get the attribution their licenses require.

## Redundant duplicates — removed 2026-10-22

Cross-hashing the corpus found exactly two duplicate pairs, and both were wired
into `true_positive_test.go` as *separate* test cases over byte-identical input
with byte-identical assertions, so each pair asserted the same thing twice:

| Removed file | Removed test case | Kept instead |
|---|---|---|
| `bittorrent_knqyf263.pcap` | "Standard TCP Handshake (knqyf263)" (50.0% / 200 pkts) | `bittorrent.pcap`, "Existing: Standard TCP" (50.0% / 200 pkts) |
| `tracker.pcap` | "Tracker Communication" (40.0% / 100 pkts) | `zeek_tracker.pcap`, "Zeek Tracker" (40.0% / 100 pkts) |

The surviving names were chosen to carry provenance: `bittorrent.pcap` is
nDPI's own filename, and `zeek_tracker.pcap` records that the capture is Zeek's.
True-positive cases went from 15 to 13 with no loss of coverage; the full suite
still passes.

The corpus now contains no duplicate content.

## Upstream folder semantics do not match ours — do not bulk-import by name

`nDPI`'s `false_positives` naming refers to **its own classifier**, not to ours.
`targusdataspeed_false_positives.pcap` means "traffic nDPI wrongly labelled as
the TargusDataspeed protocol" — `targusdataspeed` is the IANA service name for
port 5200, which is where this flow happened to run. It does *not* mean "this is
not BitTorrent".

The packets in that file are plainly BitTorrent DHT: bencoded dicts with
`1:q9:find_node` queries and `5:nodes208:` compact node lists, i.e. textbook
BEP-5. When the 2026-10-22 batch was first imported wholesale into
`false-positive/`, this file was the only one of 55 that failed, and the
detector was right to flag all 4 of its packets — the imported expectation was
wrong, not the detector.

It was therefore dropped from `false-positive/`; the same bytes remain correctly
filed as `true-positive/targusdataspeed_dht.pcap`, whose provenance this
incident incidentally resolved. The lesson generalises: when importing an
upstream corpus, a directory name encodes *that project's* question, and the
expectation it implies has to be re-derived for ours.

That capture had been in the repository unused by any test. It is now wired in
as the true-positive case "DHT on a non-standard port", which measures 100%
detection (4 of 4 UDP packets) against a required 80%. It is the only case in
the suite that specifically pins down detection of DHT on a port no heuristic
would associate with BitTorrent — port 5200 — so it guards against any future
change that quietly reintroduces a port dependency.

## How the remaining provenance was established

The earlier version of this file said that "nothing in this repository records
where they came from". That was wrong, and the mistake is worth recording: the
sources had been written down in the **commit messages that added the files**
all along. `git log --diff-filter=A -- <path>` named them directly.

Before that was noticed, three were independently re-identified by hunting
upstream trees and byte-comparing, which then matched the commit messages
exactly — so both routes agree:

| Capture | Upstream file | Verified |
|---|---|---|
| `torrent-dht.pcap` | `camp0/incc` `test/pcapfiles/torrent-dht.pcap` | MD5 `10f2f8dfa269` |
| `mippo.pcap` | `tcoppi/BittorrentReconstituter` `sample_pcaps/mippo.pcap` | MD5 `3e96729587ff` |
| `ustc_bittorrent.pcap` | USTC-TFC2016 `Benign/BitTorrent.pcap` | MD5 `87601973859f` |
| `bt_6k.pcap` | 360BitScoping `pcaps/6.93k.pcap` | MD5 `a3f2ab2627ca` |
| `bt_middle.pcap` | 360BitScoping `pcaps/in_the_middle.pcap` | MD5 `399c6c18da6f` |
| `two_torrents.pcap` | 360BitScoping `pcaps/2_torrents-11.3k_each.pcap` | MD5 `1edb167e2732` |
| `small_torrent_mse.pcap` | 360BitScoping `pcaps/small_torrent.pcap` | MD5 `924d07dd487b` |

Note how all four 360BitScoping files were renamed on import, which is why
searching upstream by our filenames found nothing: `6.93k.pcap` became
`bt_6k.pcap`, `in_the_middle.pcap` became `bt_middle.pcap`, and so on. Searching
by **content hash** is the reliable method; searching by filename is not.

## Our own captures — `own_mse_handshake`, `own_mid_transfer`

Generated by [`test/tools/gen-own-captures.sh`](../../tools/gen-own-captures.sh)
on 2026-10-22, replacing the four unlicensed 360BitScoping fixtures described
below. These are MIT like the rest of the repository, and the generator is
committed so anyone can reproduce them.

The lab is two network namespaces joined by one veth pair. **Neither namespace
is given a default route**, so nothing can leave the pair — a stray tracker
announce or DHT bootstrap has nowhere to go. That is structural, not a config
flag, and the script refuses to run if it finds a default route or if an
off-link address turns out to be reachable. DHT, PEX, LSD, UPnP and NAT-PMP are
also disabled in both clients. Peer discovery uses `minitracker.py` inside the
seeder namespace.

Consequences that matter for a published corpus: no third party's traffic is
involved, so there is nothing to anonymise; the content is locally generated
random bytes, so no copyrighted material is involved either — not even an
Ubuntu ISO; and the whole thing is reproducible from the script.

Two deliberate fidelity choices:

- **Different implementations at each end** — Transmission seeds with
  `encryption = 2` (required), aria2 leeches with `--bt-require-crypto=true` —
  so the handshake is a real cross-client MSE negotiation rather than one
  implementation talking to itself. Verified: both captures contain **zero**
  plaintext `BitTorrent protocol` strings.
- **Segmentation offload disabled** on both veth ends. The first run recorded
  pre-segmentation superframes up to 64 KiB — sizes that never occur on a real
  NIC, and which flatter a per-packet detector because one superframe carries
  many BitTorrent messages. With offload off the captures are MTU-bounded
  (max 1514 B). `tc netem` adds 12 ms delay and 0.3% loss so the traffic is not
  a sterile loopback benchmark.

The honest limitation: this is still lab traffic. There are no NAT traversal
quirks and only two client implementations, so thresholds derived from it are
more optimistic than the open internet would be.

### What these fixtures immediately exposed

Both measure **0% detection**, and that is a real defect rather than a property
of the captures. `CheckMSEEncryption` requires Shannon entropy above 6.5 over a
96-byte window, which needs at least 92 of those 96 bytes to be distinct.
Sampling 96 bytes from 256 possible values yields about 80 distinct
(expected 80.2); across 20 000 random windows the best observed were 91
distinct and 6.481 entropy. The threshold is therefore **unreachable by
construction on cryptographically random data** — which is exactly what an MSE
Diffie-Hellman public key is.

This had been invisible because the only previous MSE fixture
(`small_torrent_mse.pcap`) also carried plaintext DHT and tracker traffic; its
apparent 60% detection rate came from other detectors matching those parts, not
from MSE detection working. A clean fixture was all it took to show the
difference.

The two cases are pinned at `minDetectionRate: 0.0` with that reasoning written
into the test, so the number documents a known gap instead of silently
legitimising it.

## ⚠️ No licence grant — `bt_6k`, `bt_middle`, `two_torrents`, `small_torrent_mse` (removed 2026-10-22)

These four come from [`goncalo-rodrigues/360BitScoping`](https://github.com/goncalo-rodrigues/360BitScoping),
a university coursework project (its own report is committed as
`g24-a-360bitscoping-report.pdf`, "g24" being the student group number). The
repository contains **no LICENSE, LICENSE.md, LICENSE.txt or COPYING file**, and
no licence statement anywhere in its sources.

No licence means all rights reserved: there is no grant to redistribute these
captures, and attribution does not create one. Unlike every other entry in this
file, this cannot be fixed by adding a notice — the files have to go.

A second, independent reason points the same way: they are the students' own
captures from a real home machine. Alongside the torrent flows they carry that
machine's unrelated Skype, Avast and Windows Update traffic and its residential
addresses (`192.168.0.102` and `194.210.230.86`, Portugal, Oct–Nov 2016, client
peer-ID `BT7990`). Republishing someone's personal traffic is not something a
licence would have fixed either.

They are also about 42 MB of this repository.

They were removed on 2026-10-22. Nothing in nDPI, suricata-verify or Zeek
replaces them — neither upstream has MSE or mid-transfer BitTorrent material —
so the MSE and mid-transfer coverage was regenerated in-house instead (see
above). These four cases went away with the files:

| Test case | Required rate | What is lost |
|---|---|---|
| "MSE Obfuscation" | 60.0% | the only Message Stream Encryption coverage |
| "BT Mid-Transfer" | 95.0% | the only sustained active-transfer coverage |
| "BT 6K Transfer (Encrypted)" | 0.5% | heavily encrypted stream |
| "Two Torrents (Encrypted)" | 0.5% | two concurrent encrypted torrents |

The MSE and mid-transfer cases were regenerated. The two 0.5%-threshold cases
were not: a threshold that low asserts almost nothing, and reproducing it would
add bulk without adding a check.

## Owned protocol fixtures — generated 2026-10-22

Before this batch, five of the thirteen detectors had no fixture of their own:
`CheckLSD` (BEP 14), `CheckUDPTrackerDeep` (BEP 15), `CheckExtendedMessage`
(BEP 10), `CheckFASTExtension` (BEP 6) and `CheckSOCKSConnection` /
`UnwrapSOCKS5`. Every DHT, uTP, signature and HTTP fixture was third-party.

These are ours, MIT like the repository, produced by
[`test/tools/gen-protocol-captures.sh`](../../tools/gen-protocol-captures.sh)
in the same isolated lab as the MSE fixtures: namespaces with no default
route, locally generated random content, nothing leaving the host.

| Fixture | Protocol | What the generator forced |
|---|---|---|
| `own_plaintext_bep6_bep10.pcap` | BEP 6 + BEP 10 | `encryption=0`, so the handshake and its reserved bytes stay readable |
| `own_lsd_bep14.pcap` | BEP 14 | trackerless torrent, so LSD multicast was the only way to find a peer |
| `own_udp_tracker_bep15.pcap` | BEP 15 | `udp://` announce URL against minitracker's BEP 15 implementation |
| `own_utp_bep29.pcap` | BEP 29 | TCP peer ports dropped by iptables inside the namespaces |
| `own_dht_bep5.pcap` | BEP 5 | two aria2 nodes bootstrapped at each other, a closed two-node DHT |
| `own_ipv6_peer.pcap` | — | both peers bound to IPv6 literals, announcing over IPv6 |
| `own_pex_bep11.pcap` | BEP 11 | three peers with `pex-enabled` |
| `own_socks5_wrapped_synthetic.pcap` | — | **synthetic, see below** |

### Fixtures assert their own protocol

Each of these is checked by `verify-fixtures.py`, run from Go as
`TestOwnedFixtureMarkers`. A generator can succeed, write a plausible capture,
and still have failed to exercise the protocol — a client falls back to TCP, an
option is rejected, a tracker is never reached — and the resulting fixture is
worse than none, because the detection-rate test it feeds passes while checking
nothing.

That is not hypothetical. Every one of the following was caught by these
assertions rather than by reading the captures:

- The first MSE run recorded 64 KiB segmentation-offload superframes instead of
  wire-sized packets. Per-packet rates measured against those would have been
  flattering and meaningless.
- An inverted pcap endianness check in the verifier made it decode zero
  packets. Negative assertions such as "no plaintext handshake" are trivially
  true of an empty list, so this read as a clean bill of health. The verifier
  now requires a fixture to decode at least 10 packets before any other
  assertion counts.
- The LSD fixture initially contained nothing but ICMPv6 router solicitations.

### The isolation broke LSD, and the fix had to preserve it

Transmission refused to start LPD with `Couldn't initialize LPD: No such
device (19)`. `IP_ADD_MEMBERSHIP` with an unspecified interface makes the
kernel consult the routing table for `239.192.152.143`; these namespaces have
no routes at all, by design, so the join failed. The fix is link-scoped
multicast routes (`224.0.0.0/4`, `ff00::/8`) on each veth: they select an
interface for multicast and provide no path off the segment, so the no-default-
route assertions still hold. Bridge `multicast_snooping` also had to be
disabled, since it is on by default and filters multicast with no IGMP querier
present.

### minitracker is dual-stack and BEP 7 aware

The tracker started as a single-threaded `HTTPServer` speaking HTTP/1.1. That
combination quietly broke every multi-peer scenario: the seeder held its
keep-alive connection open and blocked the only server thread, so the
leecher's announce went unanswered. The symptoms pointed nowhere near the
cause — a `BrokenPipeError` in the tracker log and a leecher sitting at
`Idle 0%`. It is now `ThreadingHTTPServer` with HTTP/1.0.

It also binds `::` with `IPV6_V6ONLY` off and returns IPv6 peers in a separate
`peers6` key per BEP 7. Putting them in `peers` would make clients read each
16-byte address as four malformed 6-byte IPv4 entries.

### `own_socks5_wrapped_synthetic.pcap` is not a capture

No BitTorrent client tunnels peer or DHT traffic through SOCKS5 — neither
Transmission nor aria2 offers it, their proxy settings cover tracker HTTP only.
There is no configuration of real software that would produce this traffic, so
it cannot be captured in the lab or anywhere else.

It is therefore built by transformation: `make-socks5-fixture.py` prefixes the
UDP payloads of the owned DHT capture with SOCKS5 UDP request headers (RFC 1928
§7), which is what a client behind a SOCKS5 UDP-associate proxy would emit.
UDP checksums are zeroed rather than recomputed — legal for IPv4 and honest,
since faking a checksum would imply a fidelity this file does not have.

The `_synthetic` suffix is deliberate: a detection rate read off this file is a
property of the transformation, not of real traffic.


### `own_mse_many_flows.pcap` — a sample big enough to settle the MSE question

The first MSE fixture yielded 2 flows, which is not a basis for tuning a
threshold. This one carries **151 flow-first payloads from 25 concurrent
torrents**: one TCP connection per (peer, torrent) pair, each with its own
handshake. 126 are genuine MSE; 25 are plaintext, because Transmission with
`encryption: 2` correctly answers a plaintext handshake with RST as the
*responder* but still *initiates* in the clear. That discovery is why the
scenario uses aria2 (`--bt-require-crypto=true`) as the initiator: a
Transmission-to-Transmission run produced 30 flows of plaintext-then-RST and
not one byte transferred.

With 126 MSE flows the answer is settled, and it is negative. Every gate that
detects all of them also flags 16-19 captures and ~190-200 flows in the
false-positive corpus -- consistently `ethereum`, `kerberos`, `zabbix` and
`telegram_videocall`. Tightening the entropy bound moves false positives only
from 19 captures to 16, because those protocols also open with cryptographic
random material. No threshold separates them, with or without flow context.

The detector measures **5.83%** on this fixture, which is exactly its 25
plaintext flows and none of the 126 encrypted ones.

**`BitTorrentMSE` was removed on 2026-10-22.** The deciding argument was not
that its thresholds were mis-tuned but that the function was self-contradictory:
phases 1 and 2 demanded near-random data (92 of 96 bytes distinct, entropy
above 6.5) while phase 3 then demanded a run of eight zero bytes in the
following ~530, which random data contains with probability about 2.9e-17. The
two halves could never hold at the same time, so no threshold existed that
would have made it work. `shannonEntropy` went with it, having had no other
caller.

Removing it changed no measurement: every fixture rate is byte-identical, and
`verify-fixtures.py` still asserts that no plaintext Verification Constant
appears anywhere in the fixture -- the premise the scan had depended on.
`TestMSETrafficRemainsUndetected` now records the gap instead, and will fail if
MSE detection is ever implemented, which is the moment to raise the thresholds
here.

## Rule for adding captures

Every new capture needs a row in a table above giving its origin and license in
the same commit that adds it. A capture with no recorded provenance is a
liability, not a test asset — if you generated it yourself, say so explicitly,
because "ours" is also provenance.
