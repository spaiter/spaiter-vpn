# Field notes — what Russian censorship is doing right now

Audience: an agent picking up protocol work with no prior context. These are
observations reported by users in the 4pda thread on whitelist ("БС") bypass,
<https://4pda.to/forum/index.php?showtopic=1110469>, not measurements of ours.
Forum reports are anecdotal and often contradict each other; each item below
says how many independent people reported it. Treat them as hypotheses to test
against our own deployment, not as facts.

Newest batch first. Each batch names the last forum post it covers, so the next
reader knows where to resume.

---

## 2026-11-01 … 2026-11-05 (posts up to #145855288, page `st=10500`)

### 1. Reality over a plain TCP stream degrades; XHTTP survives

**Reports:** at least four independent users, two of them on their own VPS.

Since the end of October, many VLESS Reality configs (all free subscriptions
in the thread header, plus self-hosted) show: handshake and ping succeed,
Telegram and Google search work, but nothing else loads, and the client cannot
display its exit IP. One user tested it on their own VPS:
`VLESS + RAW/TCP + REALITY + XTLS Vision` delivers a single request and its
response, then dies as soon as there is a sustained stream. The same config
works from a foreign VM, so the user blames ТСПУ. Switching that server to
`VLESS + XHTTP + REALITY` fixed it.

**What this means for us:**

- Our `vless-reality-in` is **not** raw TCP + Vision: it uses the
  `http` (h2) V2Ray transport with a path derived from the short_id
  (`internal/profile/generate.go`, `buildInbound`, `case VLESSReality`).
  Whether it hits the same pattern is **unknown — test it** from a Russian
  mobile network with a sustained download (≥ 50 MB), not just a page load.
- `vless-xhttp-in` already exists in tier B (`internal/profile/tierb.go`,
  port 10871, separate Reality keypair). Nothing to add there; the question is
  whether tier A deployments should get it too and whether clients prefer it.
- **The client urltest will be fooled by this failure mode.**
  `internal/client/singbox.go` builds a `urltest` group probing
  `https://www.gstatic.com/generate_204` every 3 minutes. A probe that small is
  exactly the "single request" that still passes, so urltest keeps choosing a
  transport whose bulk traffic is dead. Options, roughly in order of effort:
  1. Put XHTTP ahead of other Reality variants in the subscription/share-link
     order so manual-selection clients default to it.
  2. Probe with a request large enough to trip the stream cutoff (needs a
     size threshold measured first; there is no number in the reports).
  3. Accept the limitation and document "if pages stop loading but ping is
     fine, pick XHTTP manually".
  Measure before choosing; do not guess the cutoff size.

### 2. AmneziaWG 3.1 passes between cascade nodes

**Reports:** one user, corroborated by another saying AmneziaWG keeps working
where VLESS stopped.

`awg 3.1` works between the RU relay and the foreign exit in a cascade, while
VLESS between the same nodes is being degraded. The same user sees xray log
errors about certificate dates although all certificates are valid, and
suspects a new MITM/substitution technique on VLESS (unverified).

Relevant to us: `awg3-in` exists (`internal/profile/profile.go`, `AWG3`). This
is weak evidence that AWG 3.1 is a reasonable hop for a RU→abroad cascade if
we ever build one. No action needed unless a cascade is planned.

### 3. ТСПУ now sits above hosting providers too

**Reports:** two users.

From Russian VPSes, Hetzner stopped being reachable — "the same restrictions as
at home". A RU VPS "stops seeing a clean external IP within a day" after a
connection is set up (VLESS affected, AmneziaWG not). Implication: a RU relay
VPS is no longer a clean vantage point by default; any cascade design must not
assume the RU hop has unfiltered egress.

### 4. Beeline mobile: SNI/DPI shaping, WG-over-VK still passes

**Reports:** mixed. Several users say Beeline mobile got stricter (paid
subscriptions dropped, own VPSes dead on Beeline while fine on Tele2 and home
Wi-Fi — one user bought ~10 VPSes and changed IPs, nothing worked); others say
Beeline is fine. Explanation offered: Beeline shapes by SNI and DPI, so server
config matters more than IP.

"WDTT saves it" — WG-over-VK (our `wg-wdtt-in` + `relay/`) was reported working
on Beeline when other methods failed. This supports finishing the relay's
product integration (see `PLAN.md` §1, "WG-over-VK relay").

### 5. Operator- and region-specific behaviour (for test matrices)

| Date | Operator / region | Observation |
|---|---|---|
| 2026-11-03 | MTS, Nizhny Novgorod | Yandex CDN unreachable 30–40 min; requests never reached the CDN, operator-side block. Megafon fine meanwhile. Yota / T-Mobile also had intermittent Yandex CDN trouble. |
| 2026-11-02 → 05 | mobile, unspecified | VLESS+XHTTP fronted by Yandex Cloud: first ping passes, then unreachable; home network fine. |
| 2026-11-04 14:00–17:00 | Megafon, Moscow oblast | Everything unstable, including whitelisted services (VK, Rutube, MAX, Yandex speedtest). Naive and Hysteria2 flapped. Users attribute it to rumoured "AI" filtering; others say it is ordinary connection-dropping shaping. |
| ongoing | MTS, Perm | All non-whitelisted traffic shaped to ~100 kbit/s. "CIDR proxies" (endpoints inside whitelisted IP ranges) help. |
| ongoing | MTS, Krasnodar krai | Whitelist mode switched on less often, even during drone alerts. |
| ongoing | Tele2 | Own NL VPS unusable on mobile; cheap RU VPS bridges (~100 ₽) work a minute then drop; Yandex Cloud IPs not on the whitelist. CDN fronting solved it for that user. |

### 6. Tools worth looking at

- **qThrone** — fork of a sing-box/Xray client with qWDTT, CSQTT, olcRTC,
  OpenFlux, DNSTT, SlipStream, MasterDNS and "S3 Bypass" built in.
  Desktop: <https://github.com/ttrroyy/qThrone>,
  Android: <https://github.com/ttrroyy/qThroneMobile>.
  Closest public thing to our protocol mix; check how it packages WDTT/CSQTT
  and whether its subscription format could import our `/sub` bundle.
  Licence not checked yet — check before borrowing code (see `PLAN.md` §8).
- **WhiteDNS Clean IP Finder v1.4.8** —
  <https://github.com/WhiteDNS/WhiteDNS-cleanip-finder>. Scans CDN (Cloudflare
  and others) ranges per ASN for clean IPs, checks DoH/DoT resolvers for DNS
  tunnels with a uTLS handshake, SNI scanning, config generation. Useful for
  picking endpoints/SNIs; not something to embed.
- `sstp.wireconf.workers.dev` — Iranian OpenVPN/WireGuard config generator;
  noise, listed only so nobody re-researches it.

### 7. Context

- **Beget breach, night of 2026-11-01/02.** Attackers reached the provider's
  management plane and ran wipers; cloud data and VPS block-level copies were
  destroyed, only file-level backups survived. Second large RU hoster hit after
  VMmanager. Lesson for the installer: do not recommend a RU hoster as the only
  copy of anything, and keep the bootstrap's backup advice off-provider.
- The thread moderator again asked people not to post working methods
  publicly; several users argue that publicity is what gets methods blocked
  within weeks. Keep this repository's protocol choices out of public posts
  until the publication decision (`PLAN.md`) is made.
