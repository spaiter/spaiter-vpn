# spaiter-vpn — implementation plan and handover

Written 2026-10-23; updated 2026-11-03. Audience: an agent or developer picking
this up with no prior context. Everything below was measured on the live host,
not assumed; where a claim is inferred rather than verified it says so.

**Current product goal:** a self-hosted VPN that can be safely deployed on a
fresh supported server with a short guided bootstrap, then administered through
Telegram or another GUI. The server, installer, subscription service and
management control plane are in scope. The Android client remains a separate
project; this repository only has to generate and contract-test what it imports.

"One click" does not mean `curl … | bash`, hiding failed checks, or giving a
public bot the Docker socket. It means one verified artifact or provider image,
a reviewable plan, an idempotent apply, health/self-test and rollback.

---

## 1. What exists today

The repository now contains a working static Go binary, both deployment tiers,
preflight, generated Compose, a live self-test, client rendering, subscriptions
and the Go Telegram bot. The live home deployment still predates that installer:
its core, relay and surrounding infrastructure remain hand-assembled, while the
bot was migrated to `spaiter-vpn bot` on 2026-11-03.

| Component | Product state | Live state on this host |
|---|---|---|
| VPN core | generated Compose using immutable `spaiter-vpn-core` image | `spaiter-vpn-core:6070c61`, hand-managed stack |
| reload | generated unprivileged sidecar, SIGHUP after validation | legacy host units still exist for parts of the hand-built stack |
| Telegram bot | same static binary, `spaiter-vpn bot`; generated `bot.json` | Go bot live in `gcr.io/distroless/static` |
| subscriptions | served by the Go bot at `/sub/<token>` | live and rebuilding six subscriptions |
| WG-over-VK relay | source in nested `relay/` module | separate hand-managed stack; optional product integration still incomplete |
| cloudflare-ddns, cloudflared-tunnel, nginx-proxy-manager | outside core product | host infrastructure |

The generated fresh-host path is `preflight` → `init` → `up` → `selftest`.
It works as individual primitives, but it has not yet been turned into a single
idempotent bootstrap or proven as the only source of truth on a disposable clean
host. The live core deployment is therefore evidence for protocol behaviour,
not proof that the installer has completed its fresh-host product journey.

### Source repositories

| Tree | Source | State |
|---|---|---|
| `spaiter-vpn` | Forgejo `spaiter/spaiter-vpn`, private | product repository and source of truth |
| `core/` | absorbed from the sing-box/Hiddify fork and patched dependencies | one root module, zero `replace` directives; see `core/PROVENANCE.md` |
| `relay/` | absorbed from the former `wdtt-relay` repository | nested Go module to keep dependency graphs separate |
| client core | `~/src/proxy-vpn-client-lab/sing-box` on this host | separate product, used by the contract gate |
| `BitTorrentBlocker` | separate public Forgejo repository | **retired**; not the detector used here, see §7 |

---

## 2. The finding that shapes the whole design

Protocols split cleanly by what external input they need. This was derived by reading
the live config, not guessed.

### Tier A — needs nothing but an IP address

Generate keys and it works on a bare VPS:

| Inbound | Type | Port | Needs generated |
|---|---|---|---|
`vless-reality-in` | vless | 10861 | Reality keypair + UUID (Reality borrows a foreign SNI — **no own certificate**) |
`ss-stls-in` | shadowsocks | 10041 | password |
`shadowtls-in` | shadowtls | 10870 | users + an upstream handshake target |
`snell-in` | snell | 10875 | users + PSK |
`mieru-in` | mieru | 10878 | users |
`mtproto-in` | mtproto | 10868 | secret |
`vless-ws-cdn-in` | vless + ws | 10042 | users (TLS terminated upstream by a CDN/proxy) |
`awg-in` | awg | 10863 | WG keypair (AmneziaWG 2.0) |
`awg3-in` | awg | 10860 | WG keypair (AmneziaWG 3.1) |
`wg-masque-in` | awg | 10877 | WG keypair |
`wg-wdtt-in` | awg | 10879 | WG keypair (plain WG, fed by `wdtt-relay`) |

### Tier B — needs a domain and ACME

Five carry `tls` pointing at certificate files (today `/etc/certs/live/npm-2/{fullchain,privkey}.pem`,
bind-mounted from nginx-proxy-manager's Let's Encrypt directory):

`hysteria-in` (10862, also needs obfs), `tuic-in` (10869), `anytls-in` (10874),
`naive-in` (10872), `masque-wg-in` (10876).

`vless-xhttp-in` (10871) is grouped here but **does not belong**: re-reading the live
config, it runs Reality with a borrowed SNI and has no certificate of its own, exactly
like `vless-reality-in`. It needs no domain. Corrected in the implementation — see §9.

`masque-wg-in` is not merely an addition either: it is the public HTTP/3 front for the
Tier A endpoint `wg-masque-in`, which binds a wildcard but is not internet-facing. Tier A
on its own therefore generates a WireGuard endpoint no client can reach.

**Therefore: the honest "one click" is Tier A.** Seven protocols on a bare VPS with no
questions asked. Tier B is an opt-in flag when a domain is available.

---

## 3. Artifact: a single static Go binary

Not a shell installer. The reason is specific, not stylistic.

The generator should **reuse `option.Options` from the fork itself**. Then it cannot
emit a config that fails to parse, because there is one schema rather than a template
duplicating it. With 19 nested inbounds a jinja/jq template will drift from the fork at
the first upstream rebase onto `hiddify/v5`; a pinned Go module will not.

Go also supplies x25519 for WireGuard and Reality keys, UUIDs and password generation
from the standard library, so a fresh VPS needs neither Python nor `jq`.

    spaiter-vpn preflight    # kernel/BPF, free ports, docker, capabilities, disk
    spaiter-vpn init         # keys + config.json + .env; --profile a | ab; --domain
    spaiter-vpn up           # docker compose up
    spaiter-vpn selftest     # live BitTorrent-detection test, see §5

---

## 4. Original implementation phases (1–6)

These are retained as the history of how the working foundation was built.
All core phases are complete; the current roadmap starts at phase 7 below.

**Phase 1 — images to a registry.** Original state: the fork was built locally
(`docker build -t hiddify-sing-box:<tag> .` in the fork, ~7 s, Dockerfile pins
`golang:1.25-alpine` with `GOTOOLCHAIN=local`). Publishing to GHCR or Forgejo's registry
removes the Go toolchain from the install path. GPL-3 obliges offering source; the public
fork satisfies that, but the README must say so explicitly.

**Phase 2 — the generator.** The bulk of the work. Profiles as Go structs, not YAML.
Pin the fork's module version. `sing-box check` must be a mandatory post-generation step
(see the trap in §6 about checking exit codes properly).

**Phase 3 — preflight.** Check what actually breaks: a kernel without BPF (XDP will not
load on OpenVZ/LXC VPS), occupied ports, missing capabilities, disk. Refuse clearly up
front instead of failing halfway.

**Phase 4 — self-test as a product feature.** See §5. Neither Hiddify nor 3x-ui ships
anything equivalent.

**Phase 5 — remove the host systemd units.** `singbox-reload.path` and
`wdtt-reload.path` watch files and become a sidecar. `wdtt-port-sync.timer` is DS-Lite
specific and should be an optional module. `vc-holder.service` (headless VK Calls) stays
out of the product.

Status: `singbox-reload.path`/`.service` are **replaced** — generate with
`init -reload-marker <path>`. Still on the host, deliberately:

| Unit | Why it is still here |
|---|---|
| `wdtt-reload.path`/`.service` | Signals `wdtt-relay`, which this installer does not generate. The same mechanism applies — compose's `pid: "container:wdtt-relay"` reaches an externally managed container — but it belongs with a wdtt module rather than ahead of one. |
| `wdtt-port-sync.service`/`.timer` | DS-Lite specific, as the plan says: it exists because this host's external port rotates. An optional module, not core. |
| `vc-holder.service` | Out of the product by decision. |

⚠️ The live units on this host are untouched. Replacing them means pointing the
running deployment at a generated compose project, which is a migration rather
than a code change.

**Phase 6 — release.** A tarball with SHA256 and a signature. **Do not ship
`curl … | bash`** for a VPN server: teaching operators to pipe a remote script into root
is exactly how such projects become a supply-chain vector.

Status: **done** — `scripts/release.sh`. No remote shell installer exists. The
planned bootstrap is a subcommand of the verified binary, so this supply-chain
decision remains intact. Releases are internal artifacts: the GPL obligation to
ship corresponding source is unmet while this repository is private, so
`--source` produces that tarball and `RELEASE.md` states the constraint rather
than leaving it implied.

### Status, 2026-11-03

Phases 1–4 and 6 are complete. The core half of phase 5 is complete; optional
WG-over-VK/DS-Lite host integration remains outside the generated base stack.
Since the October status below, the provisioning bot has been ported from
Python into the same Go binary, its configuration moved to `bot.json`, the
subscription server and background loops were retained, and the Python runtime
was removed from production.

The next definition of done is deliberately user-visible:

> On a clean supported VPS, the owner starts one verified artifact, reviews a
> generated plan, supplies the minimum secrets through files or an interactive
> prompt, and receives a healthy VPN plus a securely claimed Telegram admin.
> Re-running the operation preserves keys and converges the deployment.

### Current roadmap — phases 7–10

**Phase 7 — fresh-host bootstrap.** Add a `bootstrap` workflow over the existing
primitives. Initially support one explicit platform matrix (recommended:
Ubuntu/Debian, amd64, root or passwordless sudo, Docker available or installed
through a pinned package repository). It must:

1. discover the host and show a plan before mutating it;
2. persist a versioned desired-state document without embedding secrets;
3. run preflight before key generation;
4. call the existing generator rather than implement another one;
5. install firewall additions and logrotate with backups and ownership checks;
6. start Compose, wait for health, run selftest and report external checks that
   cannot be proven locally;
7. be idempotent and preserve existing keys; and
8. roll back files and services when an apply fails.

The proposed command contract, state boundary, transaction model and delivery
slices are specified in [`BOOTSTRAP-DESIGN.md`](BOOTSTRAP-DESIGN.md). The key
constraint is that the core rewrites `config.json` as users are provisioned, so
a repeated bootstrap must preserve it as runtime state rather than calling
`init -force` and rotating credentials.

No remote shell installer is part of this phase. Distribution is a signed
release, a package, or a provider image whose provenance can be verified before
root executes it.

**Phase 8 — desired state and narrow control plane.** Separate the immutable
operator intent from generated files and runtime state. A privileged reconciler
owns only typed VPN operations over a local Unix socket: plan/apply, status,
preflight, selftest, protocol settings, update and rollback. It must reject
arbitrary command execution and arbitrary host paths. Every apply records a
redacted audit entry and keeps a recoverable previous generation.

The local apply engine now covers the first migration slice: `config.json` is
the authoritative server-side credential store, so ports, MTU, protocol-set and
handshake changes preserve bot-created users and apply through the live
management API with compensating rollback. Restart-based migrations are
implemented with a journalled Compose force-recreate and compensating
force-recreate of the previous generation. The first subnet-migration slice is
also implemented: an exact, persisted `from`/`to` policy with strategy
`preserve-host` moves both server and client credential snapshots in one
transaction, retaining every numeric host offset and every key. Bot peer files
now join that transaction as receipt-owned runtime state: the bot is stopped at
the write boundary and subscription caches are invalidated for rebuild. Explicit
`seedUsers` migrations (`migrationPolicy.seedUsers` with strategy
`preserve-existing`) are also implemented, preserving kept seed users and
bot-provisioned users while adding or retiring seed users across `config.json`
and `secrets.json` in one transaction. WG-over-VK relay state now joins an
authorized subnet transaction through the explicit
`bot.wdttConfigDirectory` host-path contract. Explicit per-user credential
rotation (`migrationPolicy.rotateCredentials`, `bootstrap rotate`) reissues a
user's credentials across every copy in one generation.

The Telegram bot and future GUI never receive `/var/run/docker.sock`, a general
root shell, registry credentials or ACME tokens. Compromise of an interface may
request an allowed VPN operation; it must not become arbitrary host root.

**Phase 9 — Telegram setup and administration.** Keep the current provisioning
features, then add an admin setup wizard backed by the phase-8 API. Initial
ownership uses a short-lived one-time claim code printed locally, not "the first
person who sends `/start` wins". The wizard covers status, preview/apply,
protocol/tier selection, domain/certificate prerequisites, health, selftest,
updates and rollback. Destructive changes require a preview and confirmation.

**Phase 10 — web GUI and provider one-click entry points.** Build a web UI as a
second client of the same control API, not a second implementation of deployment
logic. Only after the clean-host bootstrap is proven should provider-specific
cloud-init, VM image or marketplace buttons be added. Those entry points pin and
verify an artifact; they do not download an unpinned script into a root shell.

### Detailed status as of 2026-11-04 — done vs. remaining

#### Done (Phases 7 & 8 slices landed)

- **Strict desired-state schema, canonical form & diff (`internal/bootstrap/state`):**
  versioned `spaiter-vpn/v1alpha1` schema without embedded secrets, strict
  duplicate/unknown/missing-field rejection, canonical digesting, classification
  of reconcilable vs. migration changes, and retained `migrationPolicy` audit
  records that do not re-trigger on subsequent runs.
- **Read-only host discovery & deterministic planner (`internal/bootstrap/discover`, `internal/bootstrap/plan`):**
  platform/privilege/Docker/network/UFW/file/receipt discovery and deterministic
  plans (`fresh`, `reconcile`, `migrate`, `restart-migrate`, `subnet-migrate`,
  `restart-recover`, `migration-required`, `conflict`) with golden tests.
- **Crash-recoverable file transactions & ownership (`internal/bootstrap/transaction`):**
  `O_NOFOLLOW` root-scoped writes, Managed vs. RuntimeMutable ownership,
  foreign-file refusal, durable journal, pre-plan crash recovery, and firewall /
  container-recreate intent journalling.
- **First-install, convergence, health wait & live self-test (`internal/bootstrap/apply`, `internal/bootstrap/health`):**
  preflight before key generation, `sing-box check`, UFW rule opening and
  receipt-based retirement, logrotate validation/install, continuous health
  settle window with redacted logs, live BitTorrent self-test with automatic
  free-subnet selection, and full compensating rollback on failure.
- **Live & restart-based configuration migrations (`internal/bootstrap/apply`, `internal/profile`):**
  credential recovery from live `config.json` (preserving bot-provisioned
  users), live management-API apply for ports/MTU/protocols/handshakes, and
  journalled `compose recreate` + `restart-recover` for tier, domain,
  certificate-provider, XDP and log-level changes.
- **Authorized `preserve-host` subnet migration including bot state (`internal/bootstrap/apply/subnet.go`):**
  exact `migrationPolicy.subnets` (`strategy: "preserve-host"`) moving
  `config.json`, `secrets.json`, and `bot/awg/*.json` (bare IPv4 format matching
  `provision.NextIP`/`clientcfg.AWGNode`) in one transaction while stopping
  `vpn-bot` before reading peer state and invalidating `bot/wdtt/subs-cache/*.json`.
- **Authorized `preserve-existing` `seedUsers` migration (`internal/bootstrap/apply/users.go`):**
  exact `migrationPolicy.seedUsers` (`strategy: "preserve-existing"`) adding or
  retiring seed users across `config.json` and `secrets.json` in one
  transaction, preserving kept seed users and live bot-provisioned users, and
  invalidating subscription caches when seed users are retired.
- **WG-over-VK relay subnet migration (`internal/bootstrap/apply/subnet.go`):**
  `bot.wdttConfigDirectory` names the external relay's shared host directory;
  its `passwords.json`, matching bot peer files and `.reload-wdtt` marker join
  the `preserve-host` transaction while unknown relay fields are retained and
  concurrent pre-transaction writes fail closed.
- **Generation rollback and safe pruning (`internal/bootstrap/transaction`, `internal/cli`):**
  digest-verified historical desired-state reconstruction, explicit rollback as
  a new monotonic generation preserving live users and credentials, and
  `bootstrap prune -keep N` with preview, exclusive locking and a minimum of two
  retained committed generations so the previous rollback point remains usable.
- **Explicit per-user credential rotation (`internal/bootstrap/apply`, `internal/cli`):**
  `bootstrap rotate -users …` records a one-shot `migrationPolicy.rotateCredentials`
  (unique `id`, strategy `reissue`) and applies it as its own migration:
  proxy accounts and WireGuard keypairs (addresses kept) for seed and bot
  users, seed handover, bot peer files, WG-over-VK password plus relay entry
  and bound devices, and subscription tokens. A pre-write proof rejects any
  change to unselected users or deployment-wide keys; rollback carries the
  record verbatim and never resurrects retired credentials.
- **Bot users are never issued credentials by bootstrap (`internal/profile`, `internal/bootstrap/apply`):**
  `profile.Spec.Mint` restricts generation per user. Migrations re-render
  bot-provisioned users with exactly what they hold — a peer minted for them
  would carry a private key nobody stores — and a rotation reissues only the
  slots a user held. Found by the rotation acceptance case.
- **Optional pinned Docker installation (`internal/bootstrap/dockerinstall`):**
  `bootstrap.installDocker` installs Docker Engine and Compose from Docker's
  apt repository at versions pinned per release (Ubuntu 24.04, Debian 12/13),
  trusting an embedded repository key. Conflicting runtimes and foreign Docker
  repositories block the plan by name; installation precedes preflight, the
  host is re-observed and must differ only in Docker; packages are recorded in
  `platform.json`, never removed automatically.
- **Privileged local control daemon (`internal/control`, `spaiter-vpn control`):**
  root daemon on a Unix socket with `SO_PEERCRED` identity, observer/operator
  uid allow-lists in a root-owned file, a closed set of typed operations
  (status, generations, preflight, selftest, prepare/commit/cancel of settings,
  same-repository image, rotate and rollback changes), single-use uid-bound
  tickets with a TTL, and a redacted fsynced JSONL audit log.
- **Bot ownership by one-time claim code (`internal/bot`, `spaiter-vpn bot claim-code`):**
  the first caller no longer becomes admin. A locally issued 60-bit code,
  stored only as a hash, expiring in 15 minutes and destroyed after five wrong
  attempts or one success, is redeemed with `/claim`; bootstrap accepts an
  empty `bot.adminIds` and plans the claim as a manual step.
- **Telegram server administration (`internal/bot/ui`, `bootstrap.manageControl`):**
  bootstrap installs, proves, restarts and retires the control daemon as a
  managed systemd unit and mounts its socket into the bot; admins get a server
  menu and `/rotate`, `/port`, `/image` commands that show the daemon's plan and
  commit only the ticket an admin confirms.
- **Bot isolation (`bot.dedicatedUser`):** the bot runs as `spaiter-vpn-bot`
  with only a management-credentials file instead of the core's configuration;
  bot state, the relay directory and the daemon's allow-list follow that
  account, in both directions of the switch. `bot.telegramApiUrl` selects
  another Bot API server.
- **Per-user MTProto (`core/protocol/mtproto`, `internal/profile`, bot):**
  the inbound takes `users: [{name, secret}]`. A connection is matched to its
  user by the HMAC in its fake-TLS ClientHello (checked against mtg's own
  validation in a test), and Telegram DC connections are routed through the
  router as that user from the client's address, so statistics, limits, bans
  and rules apply. Strangers are domain-fronted as nobody. Each user has a
  credential slot (rotation and `Spec.Mint` cover it), their own `tg://proxy`
  link from `clients` and the bot, and the management API provisions MTProto
  users. A legacy shared secret is kept where it was handed out until
  `deployment.retireSharedMtproto`. Gated by `deployment.mtprotoPerUser`.
- **Web UI (`internal/web`, `spaiter-vpn web`):** the second client of the
  control socket. It is unprivileged, sits on loopback unless HTTPS is in
  front, and is reached by HMAC-signed single-use login links from the CLI or
  the bot's `/weblogin`. Sessions use `HttpOnly`/`SameSite=Strict` cookies,
  forms are CSRF-protected and origin-checked, and pages are script-free
  under a CSP. Every change goes plan → ticket → commit.
- **Bootstrap-managed web UI (`bootstrap.manageWeb`, `web.listen`, `web.publicUrl`):**
  runs as `spaiter-vpn-web` in the `spaiter-vpn` group, with a key created
  once and removed with the service. It reaches the daemon through
  `control.bootstrap.json`, a bootstrap-owned allow-list merged with the
  operator's. The bot is given the key, URL and group for `/weblogin`.
- **`guide/` retired (`internal/guide`, `internal/verify`):** `spaiter-vpn bot
  guide` writes a user's offline HTML guide through the bot's own service, and
  `spaiter-vpn verify` drives every node of their subscription bundle through a
  headless client core, replacing scripts that re-derived the bot's formats by
  hand. The bundle is written for the client fork, so AmneziaWG is reshaped
  into the core's endpoint form and mieru's port into port bindings; node
  types the core cannot run as a client (wdtt, chain, naive without cronet,
  or anything an older core refuses) are reported as skipped, not failed.
- **VPS one-click via cloud-init (`internal/cloudinit`, `bootstrap cloud-init`):**
  renders `#cloud-config` user-data whose first-boot script downloads a
  release, requires a valid signature over `SHA256SUMS` by a key pinned by
  fingerprint (the project's key is embedded), checks the tarball against it,
  installs the binary, stores the credentials and applies the document. Nothing
  unverified runs. Tests drive the real script against a genuine, a tampered
  and an impostor-signed release; acceptance installs a docker-less VM
  through real cloud-init.
- **Disposable-VM acceptance suite (`test/acceptance/`):**
  QEMU Ubuntu 24.04 runner and acceptance script covering fresh install,
  foreign-file refusal, unhealthy rollback, interrupted apply recovery,
  convergence, restart migration, interrupted restart recovery, failed
  convergence rollback, live port migration, refused unsafe migration,
  bot-backed `preserve-host` subnet migration including external WG-over-VK
  relay state, `preserve-existing` `seedUsers` migration, explicit generation
  rollback preserving live users and credentials, and safe pruning followed by
  rollback from the retained previous generation. The final suite completed
  successfully with 199/199 checks on 2026-11-05 (after the random ports and the public-address question), including credential rotation,
  the control daemon, the bot claim code, the managed web UI and real traffic
  through the VLESS Reality and AmneziaWG nodes of a user's bundle.

#### Not done yet (remaining work)

**Publication, decided 2026-11-05.** The project is published on GitHub as
the very last step, as a new repository with a fresh history: the private
history carries the original deployment's data and is never pushed. Core
images go to GHCR and releases to GitHub Releases, which is where cloud-init
fetches them; image labels and release notes then point at a public commit,
which is what the GPL source offer needs for the core image *and* for the
installer, which links 160 of the core's packages. Nothing of the original
deployment may be in it: no domain, address, name, Telegram ID, password,
key, short ID or token.

What makes that checkable rather than hoped for:

- `scripts/leakscan.sh` (and `scripts/check.sh leaks`) extracts what would be
  published, `git archive` of the index, and fails on any literal from a
  denylist. The denylist is built on the deployment's host by
  `ops/bin/leak-denylist.py` from the live core config and its backups, the
  bot's config and state, the relay's state and every `pass` entry, and is
  kept outside the repository (`~/.config/spaiter-vpn-leakscan/denylist`,
  0600). Neither the public script nor the repository knows any value.
- `ops/` is `export-ignore`: a snapshot of one host is never published.
- The bot's defaults carry no host (`Validate` asks for `public.host`); tests
  use `bot.ExampleConfig()` with example.com hosts, and fixtures taken from
  the live deployment have synthetic IDs, keys and RFC 5737 addresses.

- New installs do not listen on the original deployment's ports:
  `bootstrap state` and `init` draw random ones (`profile.RandomPorts`,
  10000–32767) and, at a terminal, offer them for review and editing; the
  fixed set survives only as `profile.DefaultPorts`, the reference the
  original deployment's documents and fixtures use. That deployment keeps
  its ports (decided 2026-11-05: it is not to be touched).

- A new install asks whether the server's public IP is static. Static: the
  address goes into client configs, a domain optional. Dynamic: a domain is
  required (`bot.dynamicIp`), and the built-in updater (`ddns`, Cloudflare,
  DuckDNS or dyndns2) can keep its record from the server itself.

The publication step itself, in order — status as of 2026-11-06:

1. ✅ Core image built from `Dockerfile.core` (now stamping OCI `source`,
   `revision` and `licenses` labels) and pushed as
   `ghcr.io/spaiter/spaiter-vpn-core:19419c49`; `singbox.DefaultImage` and
   `DefaultImageRegistry` point at it and the plan goldens are regenerated.
   ⏳ The GHCR package is still **private**: GitHub exposes no API to flip a
   container package's visibility, so the owner makes it public in the web UI
   (package → settings → change visibility). Until then an anonymous pull is
   401 and a fresh install cannot fetch the default image.
   ✅ `leaks` is in `check.sh all` (2026-11-06): it runs where the denylist
   is and skips with a visible notice elsewhere (no denylist, or no ripgrep) —
   a skip is not a pass, and `check: ok` on another machine does not vouch
   for publication.
2. ⏳ `deployment.mtprotoPerUser` is still off by default (item 1 below).
3. ✅ README describes the tree as a public reader sees it; `ops/` is named as
   the private mirror's export-ignored host snapshot.
4. ✅ `leakscan` clean (0 of 369 values); one commit from the exported tree,
   authored `6448350+spaiter@users.noreply.github.com`, pushed:
   <https://github.com/spaiter/spaiter-vpn>, commit `853c689` (snapshot of
   private `f1d545f`; 4218 files, no `ops/`, GitHub detects GPL-3.0).
   ⏳ No release yet: `scripts/release.sh vX.Y.Z --source` is the next step,
   and its notes now name the public corresponding source.
5. ⏳ Provider one-click waits on that release (item 3 below).

Also done on the way, 2026-11-06 — a licensing audit of every shipped binary
(`go list -deps` of the core with production tags, the installer and the
relay, each module's `LICENSE` read from the module cache): all compatible with
GPL-3.0 except `github.com/hiddify/hmrd_multi_resolver_dns`, which has **no
license at all** (pinned commit and upstream `HEAD`). Its two consumers,
`dnstt` and `smart_dns_pool`, are now behind `-tags with_dnstt`, which no
published build sets, so neither artifact links it. `THIRD-PARTY-NOTICES.md`
and `core/NOTICE.md` were rewritten to the real tree (psiphon gone, `replace/`
→ `core/thirdparty/` with the five unlisted modules, the sagernet GPL set, the
installer's true footprint, the pcap corpus's actual home and resolved status).

1. **Per-user MTProto in production:** the code is done (see above) and gated
   by `deployment.mtprotoPerUser`, because the default core image predates it.
   Remaining: decide how core images are published (the GPL source offer in
   their labels), bump `singbox.DefaultImage`, turn the flag on by default,
   move existing users off the shared secret and set `retireSharedMtproto`.
2. **Retire the shared naive account:** every code path already issues
   per-user naive and mieru accounts (generator, Go bot, guide), and mieru has
   no shared account (confirmed with the owner 2026-11-05). The one shared
   credential is the live `naive-in` legacy `seed` account, kept because a
   naive inbound cannot start with no users. Remaining: hand naive users
   per-user links, then drop `seed` once at least one per-user naive account
   exists. The core updates naive's users in place (`7001f6d`), so this costs
   no sessions. Naive cannot ship in the Android client (cronet does not
   link), so it stays link-only. This touches the live deployment, so it waits
   for the owner.
3. **Provider listings:** the cloud-init path exists (see above); what is
   left is publishing signed releases somewhere a fresh VPS can fetch them and
   wiring provider marketplace buttons to the rendered user-data. Both wait on
   the same publishing decision as item 1.
4. **Done 2026-11-05: MASQUE-WG no longer connects at start.** The outbound
   brings its WireGuard device up and dials CONNECT-UDP in a background loop
   (1 s doubling to 30 s), so one unreachable server no longer stops the whole
   core, and a flow that dies later is redialled instead of leaving the device
   deaf for good, which it used to. The bind now reads each flow through its
   own goroutine, because WireGuard's rebind waits for every receiver and a
   receiver blocked in masque-go's `ReadFrom` could not be woken (that
   library's read deadlines cannot be cleared once they fire). The inbound's
   `Close` also leaked its UDP socket, so a reloaded inbound could not listen
   again. `verify` keeps its workaround for images built before this.

5. **From the field notes of 2026-11-05 (`FIELD-NOTES.md`).** Reports say
   Reality over a plain TCP stream now passes a handshake and a small request
   but dies on a sustained stream, while XHTTP survives. Ours is Reality over
   h2, not raw TCP + Vision, so the report does not transfer directly. The
   live deployment, read on 2026-11-05 from its own logs and accounting: users
   on `vless-reality-in` alone still move 0.3–2.6 GB a day, so bulk traffic
   is not dead there; but they average 0.1–0.4 MB per connection against
   0.5–1.9 MB on `vless-xhttp-in`, and Reality's daily connections doubled in
   a week (3.7k → 7.7k) while XHTTP's halved. One or two users per inbound:
   consistent with streams being cut and reopened, not proof of it. Work it
   implies, in order:
   - **Done 2026-11-05: traffic per inbound.** The core writes
     `user_inbounds_daily` (user, date, inbound: bytes, connections, bulk
     connections of ≥ 1 MiB down, the largest single download), counted once
     per connection as it closes, so nothing is added per packet and a
     connection lands on the day it ends. Read it with `spaiter-vpn stats
     -inbounds`, `GET /stats/inbounds?days=N` on the clash API, or the
     `singbox_inbound_*` Prometheus families. A transport whose streams are cut
     after the first request shows many connections, few bulk ones and a small
     largest. Proved end to end on a built core: 5 MiB through one inbound and
     five small requests through another land as 1 bulk / 5.0 MiB and 0 bulk /
     2.2 KiB, summing to the user's total byte for byte. Needs the live core
     rebuilt from this tree to start counting.
   - **Done 2026-11-05: XHTTP in Tier A, first in every list.**
     `vless-xhttp-in` moved from Tier B to the head of Tier A, so a server
     without a domain gets it and its inbound comes first in the config, which
     orders `clients` output and the bot's `/sub` bundle the same way. Its
     secrets stay in `TierBSecrets`, where existing files hold them; recovery
     now reads Tier B from the domain alone, since an xhttp path no longer
     implies it (a test fails on the old rule). An existing Tier A install
     gains the inbound, on the port its desired state already assigns, at its
     next apply; behind NAT that port needs forwarding. urltest chooses by
     delay, so the order steers only clients that pick by hand. Prod's own
     order is its live config's and is untouched.
   - **The urltest probe cannot see this failure:** `generate_204` is the
     single small request that still passes. A larger probe needs the cutoff
     measured first (from a Russian mobile network, ≥ 50 MB through each
     transport); do not guess it.
     **Measured 2026-11-05 from a Moscow datacenter VPS (wired, not mobile):
     no cutoff.** 100 MB through every reachable transport (Reality h2,
     XHTTP, Hysteria2, TUIC, AnyTLS, MASQUE-WG, CDN WS) and 1 GB through
     Reality h2 and XHTTP (~4 MB/s, the home uplink) all completed. The
     filter reported in the field notes is on mobile networks, so this
     vantage cannot set the threshold; the measurement still needs a SIM.
     The same run found `vless-xhttp-obfs-in` (10865/tcp) unreachable from
     outside over IPv4 and IPv6: the router forwards 10865 only for UDP
     (WG-over-VK), so that subscription entry is dead for every user.
   - **WG-over-VK first-class:** reported to pass on Beeline mobile when
     everything else fails, which raises the priority of its product
     integration.
   - **Done 2026-11-05: backups off the provider.** `spaiter-vpn backup`
     (age-encrypted tar to stdout, manifest with a SHA-256 per file, a
     consistent `VACUUM INTO` copy of the accounting) and `spaiter-vpn
     restore` (a fresh install that renders the backup's credentials for the
     new host through the migration renderer instead of minting; refuses a
     deployed host; re-runnable). A new address is asked for, and the bot
     announces the moved subscription link to every subscriber once
     (`subscription-base.json` in its data). `bootstrap apply` reminds about
     an off-provider copy after every run. Found on the way and fixed: the
     bot's direct subscription link was empty on bootstrap installs (now
     `publicHost:subscriptionPort`), the subscription port was never opened
     in UFW, four of the bot's background messages had no default text,
     so they went out empty, and the core loaded its directory with `-C`,
     merging the bot's `bot.json` — it ran only because the bot is normally
     enabled after the core starts; on a bot-enabled host every SIGHUP reload
     was refused (kept the old config, logged "reload service") and any
     restart would not have come back. It now loads `-c config.json`.
   - **Checked 2026-11-05: qThrone** (github.com/ttrroyy/qThrone and
     qThroneMobile, both GPL-3.0, so code can be borrowed into this GPL tree
     with attribution). Read from source, not run: its subscription parser
     takes our `/sub` shape (`{"outbounds":[...]}`, sing-box types), skips
     selector/urltest, and maps vless, hysteria2, tuic, anytls, snell, mieru
     and shadowtls. It reports and drops `awg` (it wants `wireguard` with an
     `amnezia_wg` object), `masque-wg` and `chain` (our ShadowTLS and WARP
     nodes). `wdtt` maps to its qWDTT profile, but it reads `hashes`/`peer`/
     `wg_port` where we emit `vk_hashes`, so our WG-over-VK node imports
     incomplete. A qThrone-flavoured bundle (AWG as `wireguard`+`amnezia_wg`,
     WDTT in its field names or as a `qwdtt://config` link) would make it a
     full client for us; worth doing with WG-over-VK first-class. A RU→abroad cascade, if ever built, must not assume a Russian VPS
     has clean egress; AmneziaWG 3.1 is the hop reported to survive there.

### Status through 2026-10-23 (historical foundation)

**Phases 1, 2 (both tiers), 3, 4, the sing-box half of 5, and 6 are done.** What exists:

| Package | What it does |
|---|---|
| `internal/keys` | x25519 for WireGuard and Reality, UUIDv4, shadowsocks 2022 keys, the MTProto `ee` secret, AmneziaWG 2.0/3.1 obfuscation parameters. Standard library only. |
| `internal/profile` | `Spec` → `option.Options` for all twelve Tier A protocols, plus the `Secrets` bundle an operator hands to clients. Validates ports, subnets, capacity and the shadowtls→shadowsocks detour before generating. |
| `internal/config` | Context-aware marshalling (the fork's wrappers flatten through `MarshalJSONContext`; `encoding/json` alone emits only type and tag) and atomic 0600 writes. |
| `internal/singbox` | Runs `sing-box check`, local binary or image, distinguishing "config is bad" from "checker did not run". |
| `internal/manage` | Client for `/manage/{endpoints,apply}`. |
| `internal/selftest` | Phase 4, as specified in §5. |
| `internal/preflight` | Phase 3. Severity model with `-strict`; runs automatically from `init` before any key is minted. |
| `internal/hostinfo` | The host facts the checks need: bound ports, default route, virtualisation, kernel config, BTF, bpffs, sysctls, free space. |
| `internal/deploy` | compose/env rendering, plus the Phase 5 reload sidecar and its agent script. |
| `internal/cli` | the CLI. |
| `scripts/release.sh` | Phase 6: build, hash, sign, verify. |

Decisions taken while implementing, that the sections above did not anticipate:

- **Superseded 2026-10-23: the fork is no longer a submodule, it is `core/`.**
  Everything was absorbed into one module with **zero `replace` directives** —
  eleven module paths rewritten across ~2,500 files. The reasoning, the exact
  commit of every absorbed tree, and the cost (upstream rebasing is gone) are in
  `core/PROVENANCE.md`. What the original note said about Go's replace semantics
  is still why a submodule was needed before, and still why absorbing was the
  only way to reach zero.
- **Round-tripping a config back through `option.Options` is not possible here.**
  Unmarshalling needs an inbound/endpoint/service registry in the context, which
  lives in `include` and drags in every protocol and therefore every one of the
  fork's patched dependencies. Generation is one-way, and `sing-box check` is the
  validator. This is why the mandatory check is not optional cosmetics.
- **Tier B is implemented, and the certificate source is an explicit choice
  rather than a default.** `files` (somebody else renews), `acme-http` (the core
  renews, needs inbound :80) and `acme-dns` (the core renews, needs a zone API
  token). The decision is not a preference — it is a property of the host, and
  measurement settled it for this one: the deployment's own certbot config says
  `authenticator = dns-cloudflare`, `pref_challs = dns-01`, because a DS-Lite
  line has no inbound :80 at all. So `acme-dns` is the only mode that works
  here, and `acme-http` is for an ordinary VPS.

  The core turned out to be able to do ACME itself, which the plan assumed it
  could not: `certificate_providers` with `type: acme` is registered (behind the
  `with_acme` build tag, which this image has), supporting HTTP-01, TLS-ALPN-01
  and DNS-01 via Cloudflare/AliDNS/acme-dns. So certificates need not be an
  external concern after all, and `nginx-proxy-manager` is no longer a
  prerequisite for Tier B.

  One shared provider, referenced by tag from all five certificate-bearing
  inbounds. Five inline providers would be five ACME clients racing for one
  order against a per-domain rate limit.

- **The plan is wrong about `vless-xhttp-in` needing a domain.** The live config
  shows it running Reality with a borrowed SNI and no certificate at all, exactly
  like `vless-reality-in`. So the real line is `NeedsCertificate()`, which is one
  protocol narrower than the tier: an operator with only an IP can enable
  vless-xhttp, and `Validate` does not demand a domain for it. It gets its own
  Reality keypair rather than sharing the other inbound's — one leaked key
  should not deanonymise both.

- **Tier A alone generates a `wg-masque-in` endpoint nothing can reach.** Its
  public front is `masque-wg-in`, which is a *Tier B* inbound: it terminates
  HTTP/3 and forwards plain WireGuard to `127.0.0.1:<wg-masque port>`. The
  target is derived from the WGMasque port rather than configured separately,
  because if those two numbers disagree the MASQUE handshake still succeeds and
  the client reports a working tunnel that carries nothing.

- **`sing-box check` does not resolve a `certificate_provider` tag.** Measured:
  a config whose inbounds all point at a provider nobody declared passes with
  exit 0. The core resolves it in `Start()`, where a miss is a loud
  `certificate provider not found` — so a typo fails at startup rather than
  silently, but no amount of checking catches it first. The defence is
  structural: one `certProviderTag` constant produces both the declaration and
  every reference.

- **`check` *does* read the certificate file**, so a `files`-mode config cannot
  be validated before the certificate exists at the path the config names. That
  is depended on rather than worked around: it is what lets preflight tell an
  operator their bind mount is wrong before the service starts.

- **The Cloudflare token is never a flag.** `CLOUDFLARE_API_TOKEN` or
  `-cf-token-file`, because a token in argv is readable via `ps` by every user on
  the host and lands in the shell history — and unlike everything else in
  `config.json`, this credential is for an account rather than for this host.
  `preflight` does not require it at all: asking whether a host *could* run the
  deployment should not require producing a zone token first.

- **A preflight check that overstates its finding is one people learn to skip.**
  The key-permission check first claimed any local user could read a
  world-readable private key. Run against the live deployment it fired on a key
  that is mode 0654 with every directory beneath it world-traversable — and is
  still unreadable, because one ancestor (the operator's home directory) is 0750. It now names
  the directory doing the protecting and says the mode is a latent exposure
  rather than a current one.
- **Phase 3 found a failure mode the plan did not list, and it is the worst kind.**
  Every internet-facing inbound binds the IPv6 wildcard `::` and relies on
  dual-stack behaviour to serve IPv4 clients. With `net.ipv6.bindv6only=1` a `::`
  socket refuses mapped IPv4: the server starts, logs nothing unusual, and is
  unreachable for every IPv4 client. Nothing in the logs says why. Occupied ports
  and a BPF-less kernel are at least noisy; this one is silent, so preflight
  fails on it outright.
- **Phase 1 published the core as `spaiter-vpn-core`, and the rename is a licence
  requirement rather than tidiness.** sing-box's licence adds a clause beyond
  GPL-3.0 forbidding derivative works from using its name or implying
  association; pushing an image called `hiddify-sing-box` to a registry is
  distribution under exactly that name. The local build tag may keep its old
  name — it is not distribution — but the published one may not. Attribution
  moved to where the GPL wants it: `org.opencontainers.image.source` plus
  `.revision` on the image name the exact commit, which is a better offer of
  source than a README line.
- **The published image is anonymously pullable, which was not the intent.**
  Forgejo container packages belong to the *owner*, not to a repository, and do
  not inherit a linked repository's visibility — so the core image is public
  while `spaiter-vpn` itself is private. Measured with an empty docker config,
  not inferred. Convenient for a fresh VPS; still a decision to take rather
  than inherit.
- **Published tags are immutable; `DefaultImage` pins the fork commit.** A
  moving tag would let two installs a month apart validate against different
  binaries while reporting the same image. A `:extended` tag exists for humans
  but nothing in the installer points at it.
- A private registry introduced a new way for `docker run` to exit non-zero
  without reading the config at all. That had to be split out of
  `CheckError`, keyed on docker's own framing rather than on words like
  "connection refused" — which appear in genuine sing-box config errors too, so
  a looser classifier would hide a real rejection behind a registry excuse.
- **Phase 5: the reload unit became a sidecar that signals rather than restarts.**
  `singbox-reload.path` ran `docker restart sing-box`, which needs the Docker API
  — and a container with the Docker socket is root on the host, which is exactly
  what removing the socket from the bot was meant to avoid. Signalling needs only
  to share the PID namespace, which compose grants with `pid: service:sing-box`,
  so the sidecar runs with `cap_drop: ALL`, `network_mode: none`, `read_only` and
  two read-only mounts. Measured on an isolated stack: marker touched → SIGHUP →
  every inbound rebound, `RestartCount=0` and `StartedAt` unchanged, i.e. the
  config was re-read without the container being torn down.
- **SIGHUP is also the safer instrument, which was not obvious.** `cmd_run.go`
  handles it by re-running the config check FIRST and keeping the running
  instance if it fails. Proven: with a config sing-box refuses, SIGHUP left the
  service up and still accepting connections. `docker restart` on the same input
  takes the service down and leaves it down.
- ⚠️ **A failed reload reports on stderr, not in the log file.** `reload service:
  …` goes through the global logger before the configured output is in play, so
  it appears in `docker logs` — the one case where the usual rule ("the log file
  is the only source of truth") is inverted.
- ⚠️ **`-C <dir>` merges every top-level `*.json` in the directory as a config
  fragment.** The generator wrote `secrets.json` beside `config.json`, so the
  service died at every start with `unknown field "ClashAPISecret"` — while
  `sing-box check -c config.json` passed. Found by running it, not by reading it.
  Secrets now live in a subdirectory (the loader skips directories) and `init`
  re-validates with `-C` after writing, which is the only form of the question
  that predicts whether the service starts.
- **Phase 6: signed, reproducible, and no install script.** Two runs of the same
  commit produce a byte-identical tarball (`-trimpath`, `CGO_ENABLED=0`,
  `-buildid=`, fixed tar mtime and owner) — without that, a signature only
  proves someone signed *something*. The manifest is signed rather than each
  file, and verification checks the signature before the hashes: hashes beside
  a tarball are replaceable by whoever replaced the tarball.
- **A missing signature had to be made a failure.** The first version warned on
  stderr and exited 0, which means stripping the `.asc` — the cheapest attack
  available — got a green result. Measured, then fixed: all four tamper cases
  now exit 1, with `--allow-unsigned` as the explicit override.
- **The release key is deliberately not the password-store key.** The only GPG
  key on the host decrypts every secret and has no passphrase; signing releases
  with it would tie artifact publication to the whole secret store. A dedicated
  ed25519 key was created, its passphrase stored in `pass` **and round-tripped
  before the key existed**, so a key could not end up with a passphrase nobody
  recorded.
- **The monorepo move cost three bugs, all found by running rather than reading.**
  A textual path rewrite corrupted the serialised protobuf descriptors — the
  `go_package` string inside `rawDesc` is length-prefixed, so changing it without
  the prefix made every binary panic in `init`. `go mod tidy`, freed from the
  fork's pruned module graph, silently upgraded `protobuf`, `x/sys` and
  `raft-boltdb` to releases requiring Go 1.26; the whole 781-module build list
  the fork actually used is now pinned. And absorbing tailscale meant tidy had to
  resolve *every* package in it, including Taildrive, whose dependency only works
  through a replace — those packages are deleted, nothing reachable imported them.
- **One pre-existing fork bug was found and fixed because the code is now ours.**
  `UserStatsManager.Close` dereferenced a nil receiver, so a *successful*
  `sing-box check` still died on shutdown whenever `config_output_path` named an
  unwritable directory — the ordinary case for a local binary. Confirmed on the
  published image's own binary before changing anything, so it is a fix rather
  than an accommodation.
- Dropping psiphon **unblocked Go 1.26 for the core**: psiphon-tls hard-coded the
  layout of `crypto/tls.ConnectionState` through `unsafe` and panicked in `init`
  on 1.26. Verified by building and running on both 1.25.6 and 1.26.5. The
  Dockerfile still pins 1.25 until a 1.26 build has run in production.
- Preflight reports **four** severities, not three: `?` (cannot determine) is kept
  apart from `WARN` (imperfect but fine), because a check that could not read
  `/boot/config-*` is not the same claim as one that read it and found a gap.

---

## 5. The self-test (already designed and proven)

The full procedure, with every trap, is written up in **`the host's private operations notes`**,
section "Live end-to-end test of BitTorrent detection". It was executed successfully on
2026-10-22. Do not re-derive it; read that section. Summary of what the binary must do:

1. `POST /manage/endpoints` a throwaway `awg` endpoint on a free port with its own /24,
   then `POST /manage/apply`. A correct apply returns `added:[…]` with `recreated` and
   `reloaded` null — that is the proof live endpoints were untouched.
2. Bring up a plain WireGuard client (Go: `wgctrl` + netlink) with
   `endpoint 127.0.0.1:<port>`.
3. Send four UDP datagrams **to the endpoint's own tunnel address** — one benign control
   plus DHT (BEP 5), UDP-tracker connect (BEP 15) and LSD BT-SEARCH (BEP 14).
4. Read the result from the log file (§6) and assert: three detections with distinct
   `detector=` values, and **no** detection for the control.
5. Delete the endpoint, apply, delete the interface, verify `config.json` no longer
   mentions the test tag, shred the keys.

The control packet is the point: without it, "everything was rejected" could just mean
the destination was unreachable.

---

## 6. Traps that will cost you time if you do not read this

Each of these was hit on 2026-10-22.

**sing-box does not log to stdout.** `log.output` is `/etc/sing-box/sing-box.log` →
host `~/appdata/sing-box/config/sing-box.log` (~12 MB, level `debug`).
`docker logs sing-box` is **empty**; any conclusion drawn from it is worthless.
Also: `grep -c bittorrent` on that file returns tens of thousands of hits that are
**not** detections — `router: match[0] => sniff(bittorrent,100ms)` is the sniff rule
matching every connection. Real ones read `bittorrent sniff detection: … detector=`.

**Route rules cannot be hot-applied.** `applyConfig` in the clash API handles inbounds
and endpoints only; `route.rules` are ignored silently. Changing e.g. `ban_duration`
needs SIGHUP or a restart, and `cmd_run.go` handles SIGHUP by closing and recreating the
instance, so both drop sessions. Worse, sing-box rewrites `config.json` itself via
`config_output_path`, so an edit that is not applied gets clobbered from memory the next
time a peer changes. **Edit and apply in the same window.**

**The clash API secret must come from its own block.** The config contains several
`"secret"` fields (inbound passwords among them); a naive grep builds a multi-line header
and yields HTTP 400. There is no `python3` inside the container. Correct extraction is in
AGENTS.md. The value is 43 characters.

**`wg set` installs no routes** — only `wg-quick` does.

**Never route a routable prefix into the test tunnel.** sing-box forwards the packet out,
the host route sends it back in, and it loops. This produced 40 MB of traffic in under a
minute. Address the tunnel's own endpoint instead.

**Verify your verifier.** Four separate checks passed today while checking nothing: a pcap
parser with inverted endianness that decoded zero packets (negative assertions are
vacuously true of an empty list); a `t.Skipf` on one malformed file that cancelled a sweep
of 651 captures and still reported PASS; a `CHECK OK` printed by `&&` after `head` rather
than after the failing command; and `strings | grep -cx` returning zero for every detector
including live ones. Before trusting a green check, make it fail on purpose once.

---

## 7. BitTorrent blocking — context you need

The detector protecting this server is **`common/sniff/bittorrent.go` in the fork**,
expanded by `route/rule/rule_action.go` for sniffer name `bittorrent`. The standalone
`spaiter/BitTorrentBlocker` project is a **different**, NFQUEUE implementation that does
not run here; it was retired to Forgejo on 2026-10-22. A full day was lost to that
confusion — start in the fork.

Route rules in production:

    {"action":"sniff","sniffer":"bittorrent","timeout":"100ms"}
    {"protocol":"bittorrent","action":"reject","method":"drop",
     "xdp_block":true,"ban_duration":"10m0s"}

The ban targets the **offending VPN client**, not the torrent peer: `Router.xdpBlockTarget`
uses `metadata.Source` for proxy inbounds and `PeerEndpointResolver` for WireGuard-style
endpoints, then `BlockUserIPs` covers the user's other addresses to stop a dual-stack
bypass. Loopback is refused by `adapter.BlockablePeerEndpoint`, which is why a local
self-test logs `XDP: skipping local peer endpoint`.

Measured detection, 2026-10-22, image `v5-nomse`, against 663 captures in
`common/sniff/testdata/pcap`:

- 100%: LSD (BEP 14), DHT (BEP 5), PEX (BEP 11), uTP (BEP 29), plaintext handshake with
  FAST and the extension protocol, SOCKS5-wrapped.
- 90%: UDP tracker (BEP 15) — only the 16-byte connect **response** is missed, being too
  generic a shape to claim.
- 0% and correct: MSE, and TLS-wrapped BitTorrent.
- The 650-capture false-positive corpus yields **one** allow-listed hit
  (`lru_ipv6_caches.pcapng`, which genuinely carries DHT on port 6881).

**MSE is deliberately not detected.** `BitTorrentMSE` was removed because it was
self-contradictory, not mis-tuned: phases 1–2 demanded near-random data while phase 3
demanded eight consecutive zero bytes, which random data contains with probability
~2.9e-17. Loosening it was measured and rejected — every variant catching all 126 real MSE
flows also flagged 16–19 corpus captures, consistently `kerberos`, `ethereum`, `zabbix`
and `telegram_videocall`. **Do not "fix" this by lowering a threshold.** Rationale is in
the comment on `TestMSETrafficRemainsUndetected` and in `testdata/pcap/NOTICE.md`.

---

## 8. Licensing

`spaiter-vpn` is **GPL-3.0-or-later**, and that is inherited rather than chosen: the core
derives from sing-box via hiddify, `wdtt-relay` from qWDTT, and the dependency graph pulls
in psiphon-tunnel-core and mieru. AGPL-3.0 is not an alternative, because GPL-3.0 code
cannot be relicensed to it.

Linking the fork's `option` package into the installer makes the installer GPL-3.0 too —
which is already the case, so no conflict.

sing-box's licence carries an **extra clause** beyond GPL-3.0 forbidding derivative works
from using its name or implying association. That is why this project is named neutrally.

Every third-party component and its licence is recorded in
[`../THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md). Read it before adding a
dependency. Three upstreams are deliberately excluded and the file says why.

---

## 9. Open risks

- **The fresh-host path is not proven end to end.** The generator, Compose,
  preflight and self-test work independently, but production still runs a
  hand-built core stack. Phase 7 needs a disposable clean-host test matrix and
  must make that path repeatable before any provider button can honestly be
  called one-click.
- **There is no persistent desired-state model yet.** `init -force` is a
  generator overwrite, not reconciliation, and may replace credentials. A GUI
  must not call it as an update API. Phase 8 needs explicit generations,
  migrations, backups and rollback before host-level settings move into a bot.
- **A management UI expands the attack surface.** Telegram is internet-facing,
  while deployment operations need root. The current absence of Docker access
  is a property to preserve, not an inconvenience to work around. The control
  plane must expose typed local operations and keep secrets out of UI state and
  audit logs.
- **Bootstrap ownership is currently raceable when no admin ID is supplied.**
  The first `/start` claims the bot. That behaviour is convenient for a private
  hand-built deployment and unsafe as a public default; replace it with a
  short-lived local claim code before calling the setup flow complete.
- **The legacy `guide/` scripts duplicate client generation in Python.** The Go
  bot/clientcfg implementation is now authoritative. Keeping both as writable
  implementations invites the same schema drift the Go port was built to
  remove; either retire the scripts or turn them into consumers of Go-produced
  artifacts.
- **Schema drift** is the main source of breakage when the fork is rebased onto
  `hiddify/v5`. Mitigate with a pinned module version and a test asserting
  "generate → `sing-box check` passes".
- ~~**Tier B is not fully portable:** ACME over DNS-01 needs a provider API token.~~
  **Resolved by supporting all three sources rather than picking one.** The risk was
  real but the framing was wrong: there is no portable choice to make, because which
  source works is a property of the host. HTTP-01 is portable on a VPS and impossible
  behind CGNAT; DNS-01 works everywhere and needs a credential; external files need
  neither but go stale silently. So the source is a required explicit flag, `preflight`
  measures the prerequisite of whichever was chosen, and the one thing it refuses to do
  is report a green check for HTTP-01 reachability it cannot actually test.
- **XDP needs a kernel with BPF** and privileged capabilities; it will not work on
  OpenVZ/LXC VPS. Preflight must detect and say so rather than half-working.
- **uTP and the Bitfield fix have not been exercised by live traffic** — only against the
  capture corpus (uTP measures 100% there). The live test covered DHT, UDP tracker and LSD.

---

## 10. Pointers

- Host operations memory, including the self-test procedure: **`the host's private operations notes`**
- Licensing of every upstream: `../THIRD-PARTY-NOTICES.md`
- Field reports on current Russian blocking (4pda thread), with action items for
  our protocols and the last post read: `FIELD-NOTES.md`
- Capture corpus, provenance and generators: fork, `common/sniff/testdata/`
- Fixture generators: `common/sniff/testdata/tools/gen-protocol-captures.sh` and
  `gen-own-captures.sh` — isolated netns lab with no default route, so nothing can leave
  the host
- Current production core image (2026-11-03): `spaiter-vpn-core:6070c61`;
  compose backups sit beside `/opt/stacks/sing-box/docker-compose.yml`.
