# spaiter-vpn

Self-hosted VPN / censorship-circumvention stack: a sing-box-derived core with
WG-over-VK (TURN) and MASQUE+WireGuard transports, AmneziaWG, a Telegram
provisioning bot, and kernel-space BitTorrent blocking.

> **Status (2026-11-03):** both Tier A and Tier B, host preflight, deployment
> generation, the live self-test, client artifacts, subscriptions and the Go
> Telegram provisioning bot are implemented. The current gap is the product
> shell around them: a fresh host still needs Docker, several explicit setup
> steps, manual firewall/logrotate installation and a separately supplied bot
> token. The next milestone is a safe `bootstrap` workflow and a narrow control
> plane shared by Telegram and a future web GUI.
>
> **Start here: [`docs/PLAN.md`](docs/PLAN.md)** — scope, the Tier A/Tier B protocol
> split that shapes the installer, phase order, and the traps that will otherwise
> cost a day.

## The binary

    spaiter-vpn bootstrap -h              # a fresh server, start to finish
    spaiter-vpn preflight                 # check the host before changing anything
    spaiter-vpn init -users alice,bob     # keys + config.json + secrets.json + compose
    spaiter-vpn init -users alice -bot    # ... and the provisioning bot
    spaiter-vpn init -users alice -tier ab -domain vpn.example.com \
        -cert-source acme-dns -dns-provider cloudflare
    spaiter-vpn up                        # docker compose up -d
    spaiter-vpn clients -host <address>   # client configs, URLs, .conf files
    spaiter-vpn stats                     # per-user traffic
    spaiter-vpn stats -inbounds           # per transport: streams vs. requests
    spaiter-vpn metrics                   # serve /metrics for Prometheus
    spaiter-vpn logs -summary             # what the server has been blocking
    spaiter-vpn probe -host <address>     # from ANOTHER machine: reachable?
    spaiter-vpn selftest                  # prove BitTorrent detection works, live
    spaiter-vpn check                     # re-validate an existing config

`init` generates twelve protocols that need nothing but an IP address — vless
over Reality on XHTTP and on h2, shadowsocks behind shadowtls, snell, mieru, an
MTProto proxy, vless over websocket for a CDN, and four WireGuard-family
endpoints (AmneziaWG 2.0, AmneziaWG 3.1, and plain WireGuard backends for the
MASQUE and WG-over-VK fronts). Reality is in that list because it borrows a
foreign SNI and so needs no certificate of its own. XHTTP comes first, in the
config and so in every client list built from it: Russian mobile networks cut
a long stream over h2 after its first request, while XHTTP's short requests
pass.

Two things are worth knowing before running it:

- **The config is generated from the fork's own `option` structs**, not from a
  template. There is one schema rather than two, so a config that drifts from
  the core fails to compile instead of failing at startup. `init` then runs
  `sing-box check` against the real binary as a mandatory step, because the
  schema cannot tell whether a value it permits is one sing-box will start with.
- **`clients` is where a deployment becomes usable.** Up to that point the
  operator holds a list of UUIDs and passwords; `clients` renders a sing-box
  config, the share URLs for the protocols that have a standard form, WireGuard
  `.conf` files and a subscription file, per user — and validates each config
  with the real binary, the same way the server's is. What it cannot emit it
  says so and why: MTProto has no sing-box outbound, shadowtls-over-shadowsocks
  has no URL form, the websocket inbound needs the CDN hostname. `-host` is
  required because the server binds wildcards, so the address a client dials
  appears nowhere in its config.
- **`preflight` is about silent failures, not completeness.** It is a short list
  because every entry is something that breaks or something that breaks
  *quietly*. The one that justifies the package: with `net.ipv6.bindv6only=1` the
  inbounds bind `::`, the server starts, nothing unusual appears in the log, and
  every IPv4 client fails. `init` runs these checks before minting any keys.
- **The firewall gets rules, not surgery.** `init` writes a `firewall.sh` that
  only ever *adds* `allow` rules for this deployment's own ports — never a
  policy change, never a deletion, because a tool that adjusts policy on a host
  it does not understand eventually cuts someone's SSH. Read it, then run it.
  Four of the twelve ports are deliberately **not** opened: two bind loopback
  (one would expose shadowsocks to anyone, the other vless in clear text) and
  two take plain WireGuard from their own fronts on the same host. Verified
  against the hand-built deployment, whose `ufw` allowed exactly the seven the
  generator produced before XHTTP joined them as the eighth.
- **`metrics` is a port, not a new exporter, and that constrains it.** A Python
  exporter had been running beside Grafana for months, and the dashboards are
  built on its metric names — so a rename would not break loudly, it would
  empty a panel silently. Names, label keys, help text and output order are
  reproduced exactly; a test pins them as literals so that a rename cannot pass
  through. Verified by diffing live output against the original: 25,002 series
  on both sides, identical values, and the only 57 differences all accounted
  for by the one deliberate change below.
- ⚠️ **The ipinfo.io lookup is off by default, unlike the original.** The
  addresses it resolves are the destinations *your users* connected to, so the
  original was reporting where they went to a third party — the evidence being
  service labels like `1&1 Versatel GmbH`, an ASN org name that can only have
  come from there. With it off, an unresolved address appears as the label
  itself, which is already what the original did when a lookup failed, so no
  series changes shape. `-service-lookup-ipinfo` restores it.
- **`logs` reads the file, because `docker logs` is empty.** `log.output`
  points at a file, so anything concluded from the container's stdout about a
  running instance is worthless — the exception being a startup failure or a
  refused reload, which the core prints on stderr. `-detections` exists because
  grepping for "bittorrent" does not work: the sniff *rule* logs a line per
  connection, so on the live server 234,558 lines contain 8 detections.
  `-summary` aggregates by detector, inbound and source, and separates a
  dropped connection from a banned client — two outcomes that look alike in the
  log and are not.
- **The log is rotated by a generated config, not by the core.** `log.output`
  is append-only and the core has no rotation, so at debug level it grows until
  the disk is full, which takes the server down rather than merely losing logs.
  `init` writes a `logrotate.conf` and preflight fails if nothing covers the
  log at debug level. `copytruncate` is load-bearing: the core reopens its log
  only when it reloads its whole config, so a plain rename would leave it
  writing to the old inode, and the alternative — SIGHUP in postrotate — drops
  every live session.
- **`preflight` answers "will the host firewall block this", and says so.**
  Whether a port is reachable *from the internet* cannot be answered from
  inside the machine — a cloud firewall or a NAT is invisible from there. That
  is what `probe` is for, run from somewhere else. It is TCP-only on purpose:
  a dropped UDP datagram and an ignored one are indistinguishable, so for the
  WireGuard ports the only honest test is a client that completes a handshake.
- **The reload sidecar signals; it does not restart.** `init -reload-marker
  <path>` generates a sidecar that shares sing-box's PID namespace and sends
  SIGHUP when a provisioning bot touches the marker. It replaces a host systemd
  unit that ran `docker restart`, and it is better on both axes: it needs no
  Docker API (so no container here is root on the host), and SIGHUP re-checks
  the config before swapping, keeping the running instance alive if the new
  config is bad. `docker restart` would leave the service down.
- **`check` validates the directory, not just the file.** The service runs with
  `-C <dir>` and merges every top-level `*.json` as a config fragment, so an
  unrelated JSON file beside the config is configuration. `init` re-checks the
  written directory for exactly this reason.
- **`selftest` is a product feature, not a test suite.** It creates a throwaway
  WireGuard endpoint, sends one benign datagram and three BitTorrent ones to
  the endpoint's own tunnel address, reads the verdict out of the log file, then
  removes everything and verifies it is gone. Nothing leaves the host: no public
  swarm, no third party. The benign datagram is the point — without it, "every
  probe was rejected" is indistinguishable from "nothing arrived at all".

One `git clone` is the whole checkout: no submodules, and **zero `replace`
directives**. The VPN core and every dependency that used to be reached through
one live in `core/`, with eleven module paths rewritten under this module's
path. What that bought and what it cost — upstream rebasing is gone — is in
[`core/PROVENANCE.md`](core/PROVENANCE.md), which also records the exact commit
of every absorbed tree.

### A fresh server

`bootstrap` orchestrates the primitives above rather than duplicating them:

    spaiter-vpn bootstrap state -users alice,bob -o desired.json
    $EDITOR desired.json
    spaiter-vpn bootstrap plan -f desired.json
    sudo spaiter-vpn bootstrap apply -f desired.json
    spaiter-vpn bootstrap status

`state` writes a complete document with every default filled in — defaults are
applied when a document is created, never when one is read, so a stored intent
is reviewable and hashable and a future default change cannot alter an existing
server on its next apply. It holds no secret: a credential is referenced by
logical name and stored separately with `bootstrap credential <name>`, read from
stdin rather than argv, root-owned and 0600.

At a terminal it first asks how clients reach the server. A static public IP
can go into client configs as it is (offered, when the server sees it on an
interface), with a domain optional. A dynamic one needs a domain kept current
by dynamic DNS (ddclient, the DNS provider's client or the router's DynDNS),
because a config holding the address stops working when it changes; the
document records `bot.dynamicIp`, and validation then refuses an address
literal. Behind NAT the server cannot see its public address and assumes a
dynamic home line. Without a terminal: `-public-host HOST [-dynamic-ip]`.

For a dynamic address the server can keep the record itself: `state` offers
Cloudflare (an API token with Zone:DNS:Edit), DuckDNS or dyndns2 (No-IP, Dynu
and most registrars and routers), or `-ddns PROVIDER` without a terminal. The
token is stored with `sudo spaiter-vpn bootstrap credential ddns-token`, and
`apply` runs `spaiter-vpn ddns run` as its own unit, `spaiter-vpn-ddns`, with
no capabilities, a read-only filesystem and the deployment's directories
hidden; the token is the one secret systemd hands it. Every
5 minutes it asks three address services (two must agree) and changes the
record only when the address did; records it writes on Cloudflare are DNS-only.
`apply` waits for its first round and fails on a rejected token or an unknown
zone; a replaced token restarts it. Its last result is in
`/var/lib/spaiter-vpn-ddns/status.json`.

Its ports are drawn at random (10000–32767, below Linux's ephemeral range) for
every protocol and for the bot's subscription server, so installs do not share
a port set a scanner could look for. At a terminal `state` shows them and lets
you keep them or change any; without one (cloud-init, scripts) it only prints
them. `-ports vless-reality-in=443,subscription=8443` fixes chosen ones. `init`
does the same.

`plan` writes nothing, pulls no image and generates no credential, so it is safe
on a live server. Every action says whether it changes the host, why it exists,
what proves it worked and what undo is available.

`apply` recomputes that plan under an exclusive lock and refuses to act on
consent given for a host that has since changed. It runs the full preflight
**before** generating any key — minting a deployment's worth of credentials and
only then finding a port taken leaves you with keys to rotate for nothing — then
writes the managed files in a crash-recoverable transaction, opens the missing
firewall rules, starts Compose, waits for the core's management endpoint to
answer continuously through a settle window, and runs the live self-test. Only
then is the generation recorded. A failure undoes itself and leaves credentials,
the core's cache and the bot's data alone, so a retry rotates nobody's keys.

A subnet move needs an exact one-use authorization in the proposed state. For
example, moving AWG2 while retaining `.1`, `.2`, `.17`, and every other host
number uses:

```json
"migrationPolicy": {
  "subnets": {
    "awg-in": {
      "from": "10.10.0.0/24",
      "to": "10.99.0.0/24",
      "strategy": "preserve-host"
    }
  },
  "seedUsers": {
    "from": ["owner"],
    "to": ["owner", "partner"],
    "strategy": "preserve-existing"
  }
}
```

Each `to` value must also match `deployment.subnets` or `bootstrap.seedUsers`.
The plan refuses an inexact policy, an address that does not fit the new
prefix, or a `seedUsers.from` list that disagrees with `secrets.json`.
Applied policies may remain in `desired.json` as an audit record without
re-triggering on later runs. Bot-created peer files join the same transaction
and subscription caches are invalidated for rebuild when subnets move or seed
users are retired. For `wg-wdtt-in`, set `bot.wdttConfigDirectory` to the clean
absolute host directory that the external relay mounts as its config directory.
Its existing `passwords.json` then joins the same transaction: matching
`wg_ip` values move with the bot peers, relay-owned fields remain intact, and
`bot/.reload-wdtt` is touched so the host integration can send SIGHUP. A relay
write observed after bootstrap read the file aborts the migration instead of
being overwritten.

There is no remote shell installer and there will not be one: piping a
downloaded script into root is how a VPN project becomes a supply-chain vector.

This path is proven rather than asserted. `test/acceptance/` runs the whole
journey in a disposable VM — plan, foreign-file refusal, rollback of a
deployment that cannot become healthy, recovery from an apply killed with its
files already written, a clean install ending in the live BitTorrent self-test,
a second apply that converges and rotates no key, a failed convergence that puts
the previous deployment back, an unsafe migration refused with its field named,
an exact preserve-host subnet migration (including bot peer and external
WG-over-VK relay state), an exact preserve-existing seed-user migration
alongside retained subnet audit records, explicit generation rollback that
preserves live users and credentials, pruning followed by a successful
rollback from the retained previous generation, credential rotation, and the
control daemon's typed operations for authorised callers, the managed web UI and
real traffic through a user's subscription bundle. It passed 199 checks on Ubuntu 24.04,
and the first run of it found three defects
no unit test had caught, including one that made the default log level unable to
satisfy the product's own success gate.

Running it again **converges** rather than reinstalls. For ordinary image, bot,
logrotate and firewall changes, `config.json` and `secrets.json` remain outside
the transaction. For a supported migration, `config.json` itself is the single
server-side credential store: bootstrap reads every live user and key from it,
including users added by the bot, re-renders the new shape without reissuing
them, and applies the inbound/endpoint diff through the management API.
`secrets.json` remains the byte-identical initial client handover snapshot
unless an explicit `subnets` or `seedUsers` policy authorizes updating it in the
same transaction.

Ports, MTU, protocol-set and handshake changes are supported live migrations.
Tier, domain, certificate-provider, XDP and log-level changes use crash-safe
container recreation. A subnet can move under an exact `preserve-host` policy
with client copies in `secrets.json` or the bot peer store; the bot is stopped
before its peer files are read, they migrate transactionally and subscription
caches are rebuilt. WG-over-VK adds the external relay `passwords.json` and its
reload marker to that transaction when `bot.wdttConfigDirectory` names the
shared host directory. Seed users can be added or retired under an exact
`preserve-existing` policy while preserving kept seed users and bot-provisioned
users. A failed migration restores the old config and proves the previous
deployment healthy.

`bootstrap rollback` restores the previous committed generation by default, or
an explicitly selected older one with `-generation N`. It is itself a new
monotonic generation: committed history is never rewritten. The historical
deployment shape is restored through the normal planner/apply/health gates,
while current seed users, bot-provisioned users, credentials and runtime data
survive. Subnet rollback uses an automatically synthesized exact
`preserve-host` policy, including bot peers and WG-over-VK relay state. A
rollback that would re-enable a currently absent protocol is refused because
the live config no longer contains the server credential needed to do that
without silently minting a replacement.

`bootstrap prune -keep N` previews deletion of transaction history older than
the retained committed generations; `-yes` applies it. `N` includes the current
generation and must be at least two, preserving a usable previous rollback
point. Recovery runs first and pruning holds the same exclusive lock as apply
and rollback. Unknown transaction-directory entries are left alone.

`bootstrap rotate -users alice[,bob]` reissues every per-user credential of the
named users — seed or bot-provisioned — as a new generation: proxy accounts,
WireGuard peer keypairs at their existing addresses, the WG-over-VK relay
password (dropping devices bound with the old one) and the bot subscription
token. Seed users receive the new values in `secrets.json`; bot users fetch
them from the bot. Before writing, the apply proves that only the selected
users' slots changed and that no deployment-wide key moved. The request is
recorded as `migrationPolicy.rotateCredentials` with a unique `id`, so it is
reviewable afterwards and an unchanged record never rotates again; a later
rollback restores intent, never retired credentials.

`bootstrap.installDocker: true` lets a host without Docker get Docker Engine
and the Compose plugin from Docker's own apt repository, at exact versions
pinned in the binary (Ubuntu 24.04, Debian 12 and 13) and verified against a
repository key embedded in it rather than downloaded. The plan names every
package version; conflicting runtimes (`docker.io`, `containerd`, `runc`,
`podman-docker`, distribution Compose) and Docker repositories configured by
someone else block it by name. Installation runs before preflight, the host is
observed again, and the apply continues only if nothing but Docker changed.
Packages are not transactional, so a later failure does not uninstall them;
what was installed is recorded in `/var/lib/spaiter-vpn/bootstrap/platform.json`
and shown by `bootstrap status`, and removing it is the operator's decision.

New desired states run the bot as the unprivileged account `spaiter-vpn-bot`
(`bot.dedicatedUser`). The bot then sees only the management endpoint and
secret, never the core's configuration and keys.

`spaiter-vpn web serve` is a browser front end to the same daemon. It runs
unprivileged and is entered by one-time links from `spaiter-vpn web
login-link` or the bot's `/weblogin`. Every change shows its plan before it is
applied. `bootstrap.manageWeb: true` has bootstrap run it as its own account.

`spaiter-vpn bootstrap cloud-init -f desired.json -o user-data` renders
user-data for a fresh VPS. On first boot it verifies a signed release against
a pinned key, installs it and applies the document; nothing is piped into a
shell. A released binary installs its own release by default (`-release` and
`-version` override that; a `dev` build needs `-version`). See
[One click on a provider](#one-click-on-a-provider).

`spaiter-vpn bot guide -user NAME -o guide.html` (run where the bot runs)
provisions a user on every method the bot offers and writes one offline HTML
guide with links, files and QR codes. With `-bundle-out`, `spaiter-vpn verify
-bundle FILE` then sends a real request through every node of that user's
subscription, with the core running as a headless client. Nodes the core
cannot run as a client (WG-over-VK, chains, naive) are listed as `SKIP`.

A bot started without `bot.adminIds` has no admin until its owner claims it:
`spaiter-vpn bot claim-code` on the server prints a one-time code, and
`/claim <code>` to the bot grants the role. Messaging the bot first grants
nothing.

`spaiter-vpn control serve` runs the local control plane: a root daemon on
`/run/spaiter-vpn/control.sock` that lets unprivileged callers — the future
Telegram admin flow, a web UI, an operator's own account — perform typed
operations without the Docker socket or a root shell. Callers are identified by
the kernel (`SO_PEERCRED`) and authorised by uid in root-owned
`/etc/spaiter-vpn/control.json`; changes are prepared, reviewed and committed
by single-use ticket through the same engine as `bootstrap`, and every request
is audited. `spaiter-vpn control unit` prints its systemd unit, and
`bootstrap.manageControl: true` has bootstrap install, prove and manage it. With
the bot enabled, its admins then get a server menu and `/rotate`, `/port` and
`/image`, each showing the daemon's plan before anything is applied.

#### Backup and restore

`spaiter-vpn backup` writes one encrypted archive holding everything a new
server needs: the desired state, stored credentials, every key and every user
(including the ones the bot added, which live only in `config.json`), the
traffic accounting, the bot's state and the ACME account. Keep it away from the
provider the server runs at: its own snapshots go with the account, and a
Russian hoster's were wiped in a breach of its management plane. The archive
goes to stdout so no copy stays on the server:

    ssh root@server spaiter-vpn backup -recipient age1... > vpn-backup.age

It is [age](https://age-encryption.org)-encrypted, to a public key or to a
passphrase (asked when no `-recipient` is given), so `age -d` opens it even
without this binary. `bootstrap apply` reminds you after every apply, because a
backup goes stale with the first user the bot adds.

`spaiter-vpn restore -from vpn-backup.age` on a fresh server installs it the
way `bootstrap apply` installs, with this host's firewall rules, units and
receipt, but mints no key: every credential comes from the backup, so existing
clients keep working. What can change is the address they dial. Behind a
domain, point the record at the new server (the built-in dynamic DNS does it on
its own) and nobody notices. Behind a bare IP every client config and
subscription link holds the old address; restore asks for the new one
(`-public-host` without a terminal, `-keep-address` when the IP moved with the
server), and the bot, when it starts, sends every subscriber the new
subscription link, because a client polling the old one never learns of it.
Restore refuses a server that already has a deployment, and an interrupted one
can be run again with the same archive.

#### What is still missing

- Provider one-click listings, which point at the signed releases on GitHub
  (the first one, v0.1.0, is out; the core image is on GHCR and per-user
  MTProto is the default for new deployments). Roadmap in
  [`docs/PLAN.md`](docs/PLAN.md), design in
  [`docs/BOOTSTRAP-DESIGN.md`](docs/BOOTSTRAP-DESIGN.md).

## Layout

| Path | What |
|---|---|
| `cmd/`, `internal/`, `scripts/` | the installer — this is the Go module root |
| `core/` | the VPN core and every dependency that used to need a `replace` |
| `relay/` | the WG-over-VK shim — a **nested** Go module, built separately |

Everything needed to build the installer, the core image and the relay is in
this tree, and it has **zero `replace` directives**. The author keeps an
`ops/` directory beside it — a snapshot of one running host (compose projects,
systemd units, host-side tools) — as a separate private repository cloned into
the git-ignored `/ops/` path: it describes a specific deployment, not the
software, so it is not part of this repository. `bot/` was a similar snapshot
until 2026-11-03, when the Python bot it held was replaced by `internal/bot`
and removed — see `internal/bot/PROVENANCE.md`.

## Checks

    scripts/check.sh              all four gates, ~8s warm
    scripts/check.sh vet          one gate: fmt | deps | vet | test
    scripts/hooks/install.sh      run the gate on every commit

    scripts/check.sh contract     bot <-> core contract, not in `all`;
                                  builds both cores into .cache/ as needed

| Gate | Scope | Why scoped that way |
|---|---|---|
| `fmt` | `gofmt` on every tracked **and** new `.go` file, minus two excluded zones | New files are included deliberately — checking only tracked ones lets a file slip through on the commit that introduces it. Excluded: `core/thirdparty/` (vendored, kept close to upstream so changes can be ported by hand) and `relay/server.go` (the WDTT codec, verbatim from qWDTT so stock clients stay wire-compatible). Drift in those 41 files is reported, not failed |
| `vet` | first-party packages + the `relay/` module, against `scripts/vet-baseline.txt` | `thirdparty/` holds vendored upstream whose tests target other module paths and do not compile — and one vet failure aborts the whole run, hiding every finding after it. That is how the broken `tlsspoof` and `geosite` tests stayed invisible from the monorepo import until 2026-11-02 |
| `test` | same, minus `common/netns`, with `-checklinkname=0` | `experimental/libbox` reaches into `runtime/pprof` internals via `//go:linkname` and will not link without the flag; `netns` forks `/proc/self/exe` and needs privileges |

`contract` is separate because it needs **two** core
binaries. Two, because there are two cores with different option schemas: this
repository's, and the client tree `proxy-vpn-client-lab/sing-box` that is built
into the APK. Everything a user receives is checked against the client core —
validating it against the server core is how a broken subscription passed this
gate on 2026-11-02 while every shipped APK rejected it. The share URIs and the
AmneziaWG `.conf` files are covered too, since neither can be fed to
`sing-box check`: links are cross-checked against the bundle node for the same
inbound, `.conf` files against invariants. 35 checks.
`internal/bot/clientcfg/contract_test.go` documents what it does and does not
catch. It runs in-process; `CONTRACT_REQUIRED=1`, which the gate sets, turns its
skips into failures so a missing core cannot be reported as success.

It builds the two binaries into `.cache/` itself — 3.5s when they are current,
about two minutes from cold — so `SING_BOX_BIN` and `SING_BOX_CLIENT_BIN` are
only needed to point it elsewhere. The client core is outside this repository
and host-specific (`CLIENT_CORE_SRC`); if it is missing the gate skips, since
there is nothing to check client-facing output against.

The pre-commit hook runs the four cheap gates always, and this one only when
something that could break the boundary is staged — the generators, the option
structs they must match, the protocol registrations, or the gate itself.

The baseline holds eight accepted `possible misuse of unsafe.Pointer`
findings, all in upstream-derived code (`sing-vmess/vless/vision.go`,
`daemon/managed_service.go`, `libbox/debug.go`). The gate fails only on
findings that are **not** in it, so rewriting unsafe pointer arithmetic in the
VLESS fast path to satisfy a heuristic is not required — and should not be
attempted casually.

## The provisioning bot

`spaiter-vpn bot` is the Telegram front end, the subscription server and the
background loops; `init -bot` deploys it. It is this same binary with a
subcommand, and that is not packaging convenience: the generators that render
client configs and the core's option types are compiled together, so they
cannot disagree. They did disagree twice while the bot was a separate Python
program, and both times the symptom was a user whose configuration had quietly
stopped working.

Everything host-specific is in a generated `bot.json` — hosts, ports, tags,
intervals, and every string a user reads, so the deployment is re-brandable.
The Telegram token is not: secrets here live apart from configuration.

The bot is currently a **provisioning interface after the server exists**, not
the server's control plane. It can approve users, provision and revoke accounts
and peers, issue individual configs and auto-updating subscriptions, report
traffic, maintain the VK pool and rebuild subscriptions. It cannot yet select
the deployment tier, configure DNS/ACME or ports, apply firewall changes,
upgrade the stack, run preflight/selftest, or roll a failed deployment back.
Those host-level operations belong behind the narrow control plane planned
next, so Telegram and a future web UI use the same typed operations.

Three properties worth knowing, all tested:

- **A refresh never provisions.** Rendering a bundle takes a flag saying
  whether to create what is missing; the background loop is handed an
  interface that cannot pass it, so a timer cannot grow the configuration of
  someone who pressed nothing. A test asserts both modes produce identical
  bundles — otherwise a refresh could hand a subscriber something different
  from what the button did.

- **The reload marker is derived, not configured twice.** The bot asks for a
  config reload by touching a file; the sidecar watches one. Set independently
  they must *happen* to match, and a mismatch is invisible — provisioning looks
  like it worked, the marker lands where nobody watches, and new users never
  take effect. `init` derives both from the bot's data directory.
- **The bot gets no Docker access**, which is why the marker exists at all: a
  publicly reachable Telegram bot holding the Docker API is effectively root on
  the host.

Its token is referenced as `${TELEGRAM_TOKEN}` and never written into anything
generated, so `up` needs it in the environment.

### The Mini App

The same self-service is also a Telegram Mini App: a page under `/app/` on the
subscription port, served by the bot process itself, opened from the bot's
menu button or the «Приложение» button. It issues the same methods through the
same service, provisions the same subscription, shows the same traffic, and
gives an admin the user list and the access queue. Telegram signs what it hands
the page (the `initData` string); every request carries that string and the
server checks the signature against the bot token and its age, so there is no
login and no session to steal. Files reach the device through one-time,
five-minute download tickets, because Telegram fetches a download URL without
the page's headers.

It needs public HTTPS, which Telegram insists on. By default the app rides on
the Cloudflare-fronted subscription host (`subscription.host_cf`), which already
reaches this port; `web_app.url` points it elsewhere and `web_app.disabled`
hides it. Without a Telegram token the app is not mounted: there would be
nothing to authenticate against.

Not every Telegram client hosts Mini Apps — Telegram X has no WebView host, so
its menu button does nothing — and a desktop browser is sometimes handier. For
those, the «В браузере» button hands out a one-time login link: ten minutes,
single use, bound to the user, signed with a key derived from the bot token.
The same page, opened from it, trades the link for an HttpOnly cookie session
(twelve hours, held in memory) and uses the same API.

## The core image

The core runs from a prebuilt image, so installing needs no Go toolchain:

    # the installer pulls, with no credentials:
    #   ghcr.io/spaiter/spaiter-vpn-core:<commit>

The image is a GitHub Container Registry package whose visibility is set to
**public** by its owner, independently of any repository; an anonymous
`docker pull` is exactly what a fresh install does, so that setting is part of
the release, not an afterthought. The image carries
`org.opencontainers.image.source` and `.revision`, naming the public commit it
was built from — the GPL-3.0 corresponding source for what is inside it.

Should the package ever be private, an unauthenticated pull reports the
repository as *nonexistent* or *unauthorized* rather than naming the cause —
which is why the installer recognises docker's own framing and says "run
docker login against ghcr.io" instead of blaming the config it never read.

The tag is the commit the image was built from, and it is immutable. A
moving tag would let two installs a month apart validate against different
binaries while reporting the same image, and would leave a rollback with
nothing to roll back to. Bumping the core is a visible change to
`singbox.DefaultImage`.

**The image is named `spaiter-vpn-core`, not after the core it derives from,
and that is a licence requirement rather than a style choice.** sing-box's
licence adds a clause beyond GPL-3.0 forbidding derivative works from using its
name or implying association; publishing an image called `hiddify-sing-box`
would be distribution under exactly that name. Attribution instead lives where
the GPL wants it — in the image's own OCI labels:

    org.opencontainers.image.source    https://github.com/spaiter/hiddify-sing-box
    org.opencontainers.image.revision  <the exact commit built>
    org.opencontainers.image.licenses  GPL-3.0-or-later

That pair of labels is the GPL offer of source: anyone holding the image can
find the precise sources it was built from. `docker inspect` shows them.

## Releases

    scripts/release.sh v0.1.0 --source     # build, hash, sign
    scripts/release.sh --verify dist/v0.1.0

One static amd64 binary, packed with the licence and the notices; every
artifact hashed into a single `SHA256SUMS`, and that manifest signed rather
than each file. Builds are byte-reproducible: two runs of the same commit
produce an identical tarball, which is what makes a signature worth checking.

Verification order matters and the script enforces it: **signature first, then
hashes**. Hashes sitting beside a tarball are replaceable by anyone who can
replace the tarball. A missing signature is a failure, not a warning —
stripping the `.asc` is the cheapest attack there is, and a verifier that
answers "ok" to it has given the attacker what they wanted. `--allow-unsigned`
exists for deliberately unsigned local builds.

Signing key `6D4841065CBDB46F500A4367C0718B337F6155B7` is dedicated to
releases, deliberately **not** the key the password store is encrypted to: that
one has no passphrase and decrypts every secret on the host.

**There will be no `curl … | bash` installer.** A one-line remote shell script
for a VPN server teaches operators to pipe unaudited network input into root —
exactly how a project like this becomes the supply-chain vector it exists to
avoid. "One click" here means a verified release running the built-in,
reviewable `bootstrap` command — never bypassing signature verification. By
hand that is: download, verify, unpack, run. Without a hand it is the
cloud-init path below, which performs the same verification before the binary
is allowed to exist on the host.

Releases are published at
<https://github.com/spaiter/spaiter-vpn/releases>: the first is **v0.1.0**.
Each carries the binary tarball, `spaiter-vpn-<tag>-source.tar.gz` — the
corresponding source GPL-3.0 §6 asks for, since the binary contains the GPL
core — `SHA256SUMS` and `SHA256SUMS.asc`. The core image is
`ghcr.io/spaiter/spaiter-vpn-core`, labelled with the commit it was built from.

### One click on a provider

Every major VPS provider accepts cloud-init user-data at creation time. That
is the one-click entry point here, and it works the same everywhere; nothing
provider-specific is installed and no vendor marketplace is involved.

1. Write the document and review it — ports are drawn at random, set the
   host clients will dial, and a fresh VPS needs Docker installed:

       spaiter-vpn bootstrap state -users alice,bob -public-host vpn.example.com -o desired.json
       # set "installDocker": true under "bootstrap"; edit anything else you like
       spaiter-vpn bootstrap plan -f desired.json

2. Render the user-data. A released binary points at its own release; a
   `dev` build needs `-version v0.1.0`:

       spaiter-vpn bootstrap cloud-init -f desired.json -o user-data

   The file holds the document and every credential it names (mode 0600).
   **The provider can read user-data**; prefer a bot that claims its admin
   after boot (no token travels), and rotate anything that had to.

3. Paste `user-data` where the provider takes cloud-init, on an **Ubuntu
   24.04** or **Debian 12/13** amd64 image:

   | Provider | Console | CLI |
   |---|---|---|
   | Hetzner Cloud | Create server → *Cloud config* | `hcloud server create --image ubuntu-24.04 --type cx22 --name vpn --user-data-from-file user-data` |
   | DigitalOcean | Advanced options → *Add initialization scripts (free)* | `doctl compute droplet create vpn --image ubuntu-24-04-x64 --size s-1vcpu-1gb --region fra1 --user-data-file user-data` |
   | Vultr | Deploy → *Cloud-Init User-Data* | `vultr-cli instance create --region fra --plan vc2-1c-1gb --os 2284 --userdata "$(cat user-data)"` |
   | Linode / Akamai | Create Linode → *Add User Data* | `linode-cli linodes create --type g6-nanode-1 --region eu-central --image linode/ubuntu24.04 --metadata.user_data "$(base64 -w0 user-data)"` |
   | Oracle Cloud | Advanced options → *Cloud-init script* | `oci compute instance launch … --user-data-file user-data` |

4. First boot does the rest and logs to `/var/log/spaiter-vpn-firstboot.log`:
   download the release, require a valid signature over `SHA256SUMS` made by
   the pinned key `6D4841065CBDB46F500A4367C0718B337F6155B7`, check the tarball
   against it, install, store the credentials, apply the document. A bot with
   no admin prints a one-time `/claim` code to the serial console.

Marketplace listings (DigitalOcean Marketplace, Hetzner Apps, Vultr
Marketplace) ship a vendor-built image through a vendor review process; they
are a distribution channel, not a different install path, and this repository
does not depend on them. The user-data above is what such an image would run.

## License

**GPL-3.0-or-later** — see [LICENSE](LICENSE).

This is inherited, not chosen: `core/` derives from sing-box (GPL-3.0) via
hiddify, the WG-over-VK relay derives from qWDTT (GPL-3.0), and mieru is
GPL-3.0. No weaker license is available for the combined work, and AGPL-3.0 is
not an option either, because GPL-3.0 code cannot be relicensed to AGPL-3.0.

Since the core was absorbed, the GPL boundary is no longer visible as a
repository boundary — it is a directory boundary. Each absorbed tree keeps its
own licence file next to its code (`core/LICENSE`, `core/thirdparty/*/LICENSE`),
and those are the governing terms for those directories.

Every third-party component, its license, and how it is used are recorded in
**[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)**. Read it before adding a
dependency or copying code from anywhere — it also records three things that
are deliberately *not* used and why.

## Naming

sing-box's license carries an additional clause forbidding derivative works
from using its name or implying association with it. This project is therefore
named neutrally and makes no claim of endorsement by or association with
sing-box or Hiddify. Attribution to them is in the notices file, where the GPL
requires it.

## Where licenses live

Licensing is recorded per directory, next to the code it governs, rather than
only in one root file:

| Path | License | Why it differs |
|---|---|---|
| this repository | GPL-3.0-or-later | the combined work |
| `core/` | GPL-3.0 **+ naming clause** | sing-box via hiddify, absorbed 2026-10-23; see `core/LICENSE`, `core/NOTICE.md` and `core/PROVENANCE.md` |
| `core/thirdparty/tailscale/` | **BSD-3-Clause** | see its `LICENSE` and `licenses/` |
| `core/thirdparty/{wireguard-go,gooserelay,sing-anytls,sing-shadowtls,sing-vmess,sing-snell,connect-ip-go,dnscrypt/v2}/` | **MIT** / permissive | each keeps its own `LICENSE` beside its code |
| `core/thirdparty/vaydns/` | see its `COPYING` | |
| `core/common/ja3/` | see its `LICENSE` | |
| `core/common/sniff/testdata/pcap/` | **LGPL-3.0** + BSD-3 + MIT | nDPI corpus, two zeek captures, one suricata-verify capture — see §5 |
| `wdtt-relay/` (separate repo) | GPL-3.0-or-later | fork of qWDTT's `server.go`; see its `NOTICE.md` |
| `wdtt-relay/rtpopus2/`, `rtpopus3/` | **MIT** | vendored FreeTurn codecs, per-file SPDX grant |
| `core/transport/wdtt/rtpopus2/`, `rtpopus3/` | **MIT** | same codecs, client-side copy |
| `BitTorrentBlocker` (separate repo, retired) | **MIT** | independent NFQUEUE implementation, not used here |

⚠️ **The GPL boundary used to be a repository boundary and is now a directory
boundary.** Absorbing the core removed the structural reminder that `core/` is
someone else's GPL-3.0 work carrying an extra naming clause. Nothing about the
obligations changed; only their visibility did. Every absorbed tree keeps its
licence file next to its code, and those files — not this one — are the
governing terms for those directories.

`BitTorrentBlocker` stayed a separate MIT repository rather than being merged
in, and that reasoning still holds for anything MIT worth reusing elsewhere:
merging collapses its licensing into GPL-3.0 and destroys the ability of
unrelated projects to use it.

## Repository topology

The earlier plan kept the core and relay in separate repositories. That was
superseded on 2026-10-23: the core and its patched dependencies now live under
`core/`, and the WG-over-VK relay under `relay/`. The root module deliberately
has zero `replace` directives; `relay/` remains a nested module because merging
its dependency graph would move the core's carefully pinned versions.

The licence boundary is therefore a directory boundary rather than a repository
boundary. `BitTorrentBlocker` remains a separate, retired MIT project and is not
the detector used by this VPN.
