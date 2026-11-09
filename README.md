# spaiter-vpn

Self-hosted VPN / censorship-circumvention stack: a sing-box-derived core with
WG-over-VK (TURN) and MASQUE+WireGuard transports, AmneziaWG, a Telegram
provisioning bot, and kernel-space BitTorrent blocking. One static Go binary
installs it, operates it, backs it up and runs the bot.

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
    spaiter-vpn backup -recipient age1... # encrypted archive of the deployment
    spaiter-vpn restore -from FILE        # bring it up on a new server
    spaiter-vpn control serve             # local control plane (root daemon)
    spaiter-vpn web serve                 # browser front end of the control plane
    spaiter-vpn bot                       # Telegram bot, /sub server, background loops
    spaiter-vpn verify -bundle FILE       # real request through every node of a subscription

`spaiter-vpn <command> -h` lists the flags of a command.

### Protocols

Tier A needs nothing but an IP address. `init` generates twelve inbounds:
vless over Reality on XHTTP and on h2, shadowsocks behind shadowtls, snell,
mieru, an MTProto proxy (per-user by default), vless over websocket for a CDN,
and four WireGuard-family endpoints: AmneziaWG 2.0, AmneziaWG 3.1, and plain
WireGuard backends for the MASQUE and WG-over-VK fronts. XHTTP is first in the
config and so in every client list: mobile networks that cut a long h2 stream
after its first request pass XHTTP's short requests.

Tier B (`-tier ab`) adds hysteria, tuic, anytls, naive and masque-wg. It needs
`-domain` and a certificate source: `acme-dns` (the core renews; needs a zone
API token; the only option behind carrier-grade NAT or DS-Lite), `acme-http`
(the core renews; needs inbound port 80) or `files` (someone else renews).

### How the pieces behave

- **The config is generated from the core's own `option` structs**, not from a
  template, so a config that drifts from the core fails to compile. `init`
  then runs `sing-box check` against the real binary before writing.
- **`clients` is where a deployment becomes usable.** Per user it renders a
  sing-box config, share URLs for the protocols that have a standard form,
  WireGuard `.conf` files and a subscription file, each validated with the
  real binary. What it cannot emit it names and explains: MTProto has no
  sing-box outbound, shadowtls-over-shadowsocks has no URL form, the websocket
  inbound needs the CDN hostname. `-host` is required because the server binds
  wildcards, so the address a client dials appears nowhere in its config.
- **`preflight` catches silent failures**, such as `net.ipv6.bindv6only=1`,
  with which the server starts cleanly and every IPv4 client fails. `init`
  runs these checks before minting any key.
- **The firewall gets rules, not surgery.** `init` writes a `firewall.sh` that
  only adds `allow` rules for this deployment's ports; it never changes policy
  or deletes anything. Read it, then run it. Loopback-bound inbounds and the
  plain WireGuard backends behind their own fronts are not opened.
- **`metrics`** serves the traffic accounting in Prometheus format. The ipinfo.io
  lookup of destination addresses is off by default, because those are the
  places your users went; `-service-lookup-ipinfo` turns it on.
- **`logs` reads the log file**, because `log.output` points at a file and
  `docker logs` holds only startup errors. `-detections` filters real
  detections out of the per-connection sniff lines; `-summary` aggregates by
  detector, inbound and source, and separates a dropped connection from a
  banned client.
- **Log rotation is generated.** `init` writes a `logrotate.conf` with
  `copytruncate`, since the core reopens its log only on a full reload, and
  preflight fails if nothing covers the log at debug level.
- **`probe`**, run from another machine, answers whether the ports are reachable
  from the internet, which no check from inside the host can. It is TCP-only:
  a dropped UDP datagram and an ignored one are indistinguishable, so for the
  WireGuard ports the honest test is a client completing a handshake.
- **The reload sidecar signals.** `init -reload-marker <path>` adds a sidecar
  that shares sing-box's PID namespace and sends SIGHUP when the bot touches
  the marker. SIGHUP re-checks the config before swapping, so a bad config
  leaves the running instance alive, and no container holds the Docker API.
- **`check` validates the directory**, since the service merges every
  top-level `*.json` beside the config as a fragment.
- **`selftest`** creates a throwaway WireGuard endpoint, sends one benign and
  three BitTorrent datagrams to its own tunnel address, reads the verdict from
  the log and removes everything. Nothing leaves the host. The benign datagram
  distinguishes "every probe was rejected" from "nothing arrived".

One `git clone` is the whole checkout: no submodules, and the only `replace`
directives point at public, commit-pinned forks (`sagernet/gvisor`,
`sagernet/sing`, `amnezia-vpn/amneziawg-go` under `github.com/spaiter/`, one
bug-fix commit each). [`core/PROVENANCE.md`](core/PROVENANCE.md) records the
exact commit of every absorbed tree and fork.

## A fresh server

Supported hosts: Ubuntu 24.04 or Debian 12/13 on amd64 with systemd.

    spaiter-vpn bootstrap state -users alice,bob -o desired.json
    $EDITOR desired.json
    spaiter-vpn bootstrap plan -f desired.json
    sudo spaiter-vpn bootstrap apply -f desired.json
    spaiter-vpn bootstrap status

**`state`** writes a complete desired-state document with every default filled
in. Defaults are applied when a document is created, never when one is read,
so a stored intent is reviewable and a future default change cannot alter an
existing server. It holds no secret: a credential is referenced by logical name
and stored with `sudo spaiter-vpn bootstrap credential <name>` (read from stdin,
root-owned, 0600).

At a terminal `state` asks how clients reach the server. A static public IP
goes into client configs as it is, a domain optional. A dynamic address needs a
domain (`bot.dynamicIp`); the server can keep its record itself with the
built-in dynamic DNS: Cloudflare (API token with Zone:DNS:Edit), DuckDNS or
dyndns2 (No-IP, Dynu, most registrars and routers). Store the token as
`ddns-token`; `apply` runs `spaiter-vpn ddns run` as the hardened unit
`spaiter-vpn-ddns`, which checks three address services every 5 minutes (two
must agree) and writes only when the address changed. Its last result is in
`/var/lib/spaiter-vpn-ddns/status.json`. Without a terminal:
`-public-host HOST [-dynamic-ip] [-ddns PROVIDER]`.

Ports are drawn at random (10000–32767) for every protocol and for the bot's
subscription server, so installs do not share a port set a scanner could look
for. At a terminal `state` lets you keep or change them;
`-ports vless-reality-in=443,subscription=8443` fixes chosen ones. `init` does
the same.

**`plan`** writes nothing, pulls no image and generates no credential, so it is
safe on a live server. Every action says whether it changes the host, why, what
proves it worked and what undo exists.

**`apply`** recomputes the plan under an exclusive lock and refuses to act on
consent given for a host that has since changed. It runs preflight before
generating any key, writes the managed files in a crash-recoverable
transaction, opens the missing firewall rules, starts Compose, waits for the
core's management endpoint to answer through a settle window and runs the live
self-test. Only then is the generation recorded. A failure undoes itself and
leaves credentials, the core's cache and the bot's data alone, so a retry
rotates nobody's keys. After every apply it reminds you to take a backup.

Running `apply` again **converges**. Ports, MTU, protocol set and handshake
changes are live migrations through the management API; tier, domain,
certificate source, XDP and log level use crash-safe container recreation.
`config.json` is the single server-side credential store: every live user and
key, including the ones the bot added, is re-rendered without being reissued.
A failed migration restores the old config and proves the previous deployment
healthy.

A subnet move or a seed-user change needs an exact one-use authorization in
`migrationPolicy`:

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

Each `to` must match `deployment.subnets` or `bootstrap.seedUsers`; an inexact
policy or an address that does not fit the new prefix is refused. Bot-created
peers migrate in the same transaction and subscription caches are rebuilt. For
`wg-wdtt-in`, `bot.wdttConfigDirectory` names the host directory the external
relay mounts; its `passwords.json` then moves with the peers and the relay is
told to reload. Applied policies may stay in `desired.json` as an audit record.

**`bootstrap rollback [-generation N]`** restores a committed generation as a
new one; history is never rewritten. Current users, credentials and runtime
data survive. A rollback that would re-enable an absent protocol is refused,
because the live config no longer holds that server credential.

**`bootstrap prune -keep N`** previews deletion of transaction history older
than the retained generations; `-yes` applies it. `N` must be at least two.

**`bootstrap rotate -users alice[,bob]`** reissues every per-user credential of
the named users (proxy accounts, WireGuard peer keys at their existing
addresses, the WG-over-VK relay password, the subscription token) as a new
generation. Seed users get the new values in `secrets.json`; bot users fetch
them from the bot. The request is recorded as
`migrationPolicy.rotateCredentials` with a unique `id` and never rotates again.

**`bootstrap.installDocker: true`** installs Docker Engine and the Compose
plugin from Docker's apt repository at versions pinned in the binary, verified
against an embedded repository key. Conflicting runtimes and foreign Docker
repositories block it by name. Packages are not transactional; what was
installed is recorded in `/var/lib/spaiter-vpn/bootstrap/platform.json`.

**`bot.dedicatedUser`** runs the bot as the unprivileged account
`spaiter-vpn-bot`, which sees only the management endpoint and secret.

There is no remote shell installer: piping a downloaded script into root is
how a VPN project becomes a supply-chain vector. `test/acceptance/` runs the
whole journey in a disposable VM.

### Control plane and web UI

`spaiter-vpn control serve` is a root daemon on
`/run/spaiter-vpn/control.sock` that performs typed operations for
unprivileged callers: the bot, the web UI, an operator's own account. Callers
are identified by the kernel (`SO_PEERCRED`) and authorised by uid in
`/etc/spaiter-vpn/control.json`. A change is prepared (the plan and a ticket
are shown), then committed by that single-use ticket through the same engine
as `bootstrap`; every request is audited.

    spaiter-vpn control prepare -port vless-reality-in=443
    spaiter-vpn control commit <ticket>
    spaiter-vpn control status | generations | preflight | selftest

`spaiter-vpn control unit` prints its systemd unit; `bootstrap.manageControl:
true` has bootstrap install and manage it. Bot admins then get a server menu
and `/rotate`, `/port`, `/image`, each showing the plan before it is applied.

`spaiter-vpn web serve` is the browser front end of the same daemon. It holds
no privilege and is entered by one-time links from `spaiter-vpn web login-link`
or the bot's `/weblogin`; `spaiter-vpn web key` creates the signing key.
`bootstrap.manageWeb: true` runs it as its own account.

### Backup and restore

`spaiter-vpn backup` writes one encrypted archive: the desired state, stored
credentials, every key and user (including the bot's), the traffic accounting,
the bot's state and the ACME account. It goes to stdout so no copy stays on the
server, and it should not stay with the provider either:

    ssh root@server spaiter-vpn backup -recipient age1... > vpn-backup.age

The archive is [age](https://age-encryption.org)-encrypted, to a public key or
to a passphrase, so `age -d` opens it without this binary.

`spaiter-vpn restore -from vpn-backup.age` installs on a fresh server the way
`bootstrap apply` does, with this host's firewall rules and units, but mints no
key: existing clients keep working. Behind a domain, point the record at the
new server (the built-in dynamic DNS does it alone). Behind a bare IP, restore
asks for the new address (`-public-host`, or `-keep-address` when the IP moved
with the server) and the bot sends every subscriber the new subscription link
when it starts. Restore refuses a server that already has a deployment; an
interrupted one can be rerun with the same archive.

### Cloud-init: one click on a provider

Every major VPS provider accepts cloud-init user-data at creation time.
Nothing provider-specific is installed and no marketplace is involved.

1. Write and review the document. A fresh VPS needs Docker installed:

       spaiter-vpn bootstrap state -users alice,bob -public-host vpn.example.com -o desired.json
       # set "installDocker": true under "bootstrap"
       spaiter-vpn bootstrap plan -f desired.json

2. Render the user-data. A released binary installs its own release; a `dev`
   build needs `-version vX.Y.Z`:

       spaiter-vpn bootstrap cloud-init -f desired.json -o user-data

   The file holds the document and every credential it names (mode 0600).
   **The provider can read user-data**: prefer a bot that claims its admin
   after boot, and rotate anything that had to travel this way.

3. Paste `user-data` where the provider takes cloud-init, on an Ubuntu 24.04
   or Debian 12/13 amd64 image:

   | Provider | Console | CLI |
   |---|---|---|
   | Hetzner Cloud | Create server → *Cloud config* | `hcloud server create --image ubuntu-24.04 --type cx22 --name vpn --user-data-from-file user-data` |
   | DigitalOcean | Advanced options → *Add initialization scripts (free)* | `doctl compute droplet create vpn --image ubuntu-24-04-x64 --size s-1vcpu-1gb --region fra1 --user-data-file user-data` |
   | Vultr | Deploy → *Cloud-Init User-Data* | `vultr-cli instance create --region fra --plan vc2-1c-1gb --os 2284 --userdata "$(cat user-data)"` |
   | Linode / Akamai | Create Linode → *Add User Data* | `linode-cli linodes create --type g6-nanode-1 --region eu-central --image linode/ubuntu24.04 --metadata.user_data "$(base64 -w0 user-data)"` |
   | Oracle Cloud | Advanced options → *Cloud-init script* | `oci compute instance launch … --user-data-file user-data` |

4. First boot downloads the release, requires a valid signature over
   `SHA256SUMS` by the pinned key `6D4841065CBDB46F500A4367C0718B337F6155B7`,
   checks the tarball against it, installs, stores the credentials and applies
   the document. It logs to `/var/log/spaiter-vpn-firstboot.log`; a bot with
   no admin prints a one-time `/claim` code to the serial console.

## The provisioning bot

`spaiter-vpn bot` is the Telegram front end, the subscription server and the
background loops; `init -bot` or `bot.enabled` deploys it. It is the same
binary as the installer, so the generators that render client configs and the
core's option types cannot disagree.

Everything host-specific is in a generated `bot.json`: hosts, ports, tags,
intervals, and every string a user reads, so the deployment is re-brandable.
The token is referenced as `${TELEGRAM_TOKEN}` and never written into anything
generated; `up` needs it in the environment.

The bot approves users, provisions and revokes accounts and peers, issues
individual configs and auto-updating subscriptions (`/sub/<token>`), reports
traffic, maintains the VK pool for WG-over-VK and rebuilds subscriptions. With
the control daemon, admins also rotate credentials, move ports and change the
core image from Telegram. Tier, domain, certificates and firewall remain
`bootstrap` operations.

- **A refresh never provisions.** The background loop cannot create what is
  missing, so a timer cannot grow the configuration of someone who pressed
  nothing.
- **The reload marker is derived**, by both the bot and the sidecar, from the
  bot's data directory, so they cannot disagree.
- **The bot has no Docker access.** A publicly reachable bot holding the
  Docker API would be root on the host.

A bot started without `bot.adminIds` has no admin until its owner claims it:
`spaiter-vpn bot claim-code` on the server prints a one-time code, and
`/claim <code>` to the bot grants the role.

`/notify <text>` from an admin sends one message to every approved user with
the APK button under it; `spaiter-vpn bot notify -text "<text>"` does the same
from the server (run where the bot runs, with its `TELEGRAM_TOKEN`).

`spaiter-vpn bot guide -user NAME -o guide.html` provisions a user on every
method and writes one offline HTML guide with links, files and QR codes. With
`-bundle-out`, `spaiter-vpn verify -bundle FILE` then fetches a URL through
every node of that subscription with the core as a headless client; nodes the
core cannot run as a client (WG-over-VK, chains, naive) are listed as `SKIP`.

`spaiter-vpn vk login` signs in to the VK account whose calls carry the
WG-over-VK pool (login, password and code at the terminal) and writes the
access token; `-mint` also proves the call-token path works headless.

### Health monitor

The bot watches the server and tells the admins when something breaks
(`bot.json` → `monitor`; `"disabled": true` turns it off). Every 30 s it checks
that the core's API answers, that every inbound's port is bound (from
`/proc/net`, so UDP counts and `/port` changes are followed), and memory, the
data disk and conntrack against `mem_pct`/`disk_pct`/`conntrack_pct`. Two
probes are off until given a target: `world` asks check-host.net to connect to
a public `host:port` from several countries (the only check that sees a block
on the way in), and `egress` fetches `https://api.ipify.org` through a local
SOCKS5 inbound and compares it with `expect_ip`.

A check is down after `fail_threshold` failures in a row and up on the first
success. The first alert after a calm period goes out at once; what follows is
collected into one message per `digest_every`, and nothing is sent during the
quiet hours (`quiet_from`–`quiet_to`, in `timezone`). A daily summary of the
last day is off by default; `"daily_report": true` sends one at each of
`report_times` (10:00 and 22:00 unless changed). `/health` shows the current
state; counters live in `monitor.json` in the data dir and survive a restart.

### The Mini App

The same self-service is a Telegram Mini App under `/app/` on the subscription
port, served by the bot process and opened from the bot's menu button. It
issues the same methods, shows the same traffic, and gives an admin the user
list and the access queue. Every request carries Telegram's signed `initData`,
checked against the bot token and its age, so there is no login and no
session to steal. Files reach the device through one-time, five-minute
download tickets.

It needs public HTTPS. By default it rides on the Cloudflare-fronted
subscription host (`subscription.host_cf`); `web_app.url` points it elsewhere
and `web_app.disabled` hides it. Clients without a WebView host (Telegram X)
and desktop browsers use the «В браузере» button: a one-time login link (ten
minutes, single use, bound to the user) that trades for a twelve-hour
HttpOnly cookie session.

## The core image

The core runs from a prebuilt public image, so installing needs no Go
toolchain:

    ghcr.io/spaiter/spaiter-vpn-core:<commit>

The tag is the commit the image was built from and is immutable, so two
installs validate against the same binary and a rollback has something to roll
back to. Bumping the core is a visible change to `singbox.DefaultImage`.
If an anonymous pull fails, the installer says "run docker login against
ghcr.io" rather than blaming the config.

The image is named `spaiter-vpn-core`, not after the core it derives from,
because sing-box's licence forbids derivative works from using its name.
Attribution lives in the image's OCI labels, which are also the GPL offer of
source:

    org.opencontainers.image.source    https://github.com/spaiter/hiddify-sing-box
    org.opencontainers.image.revision  <the exact commit built>
    org.opencontainers.image.licenses  GPL-3.0-or-later

## Releases

Releases are at <https://github.com/spaiter/spaiter-vpn/releases>. Each
carries one static amd64 binary tarball, `spaiter-vpn-<tag>-source.tar.gz`
(the corresponding source GPL-3.0 §6 asks for), `SHA256SUMS` and
`SHA256SUMS.asc`. Builds are byte-reproducible.

    scripts/release.sh v0.1.0 --source     # build, hash, sign
    scripts/release.sh --verify dist/v0.1.0

Verification is **signature first, then hashes**, and a missing signature is a
failure (`--allow-unsigned` is for deliberately unsigned local builds). The
signing key is `6D4841065CBDB46F500A4367C0718B337F6155B7`, dedicated to
releases.

There is no `curl … | bash` installer. "One click" means a verified release
running the reviewable `bootstrap` command: by hand, download, verify, unpack,
run; without a hand, the cloud-init path above.

## Layout

| Path | What |
|---|---|
| `cmd/`, `internal/`, `scripts/` | the installer and bot; this is the Go module root |
| `core/` | the VPN core and its patched dependencies (`core/thirdparty/`) |
| `relay/` | the WG-over-VK relay shim; a nested Go module, built separately |
| `test/acceptance/` | the end-to-end journey in a disposable VM |

## Checks

    scripts/check.sh              all gates: fmt | deps | vet | test | leaks
    scripts/check.sh vet          one gate
    scripts/hooks/install.sh      run the gates on every commit
    scripts/check.sh contract     bot <-> core contract; builds both cores into .cache/

`fmt` runs `gofmt` on every tracked and new `.go` file except `core/thirdparty/`
and `relay/server.go`, which are kept close to upstream (drift there is
reported, not failed). `vet` and `test` cover the first-party packages and the
`relay/` module against `scripts/vet-baseline.txt`; `thirdparty/` is excluded
because its upstream tests target other module paths. `test` passes
`-checklinkname=0` for `experimental/libbox` and skips `common/netns`, which
needs privileges. `leaks` runs where a denylist of deployment values exists and
skips visibly elsewhere.

`contract` needs two core binaries: this repository's and the client core
built into the Android app (`CLIENT_CORE_SRC`, host-specific). Everything a
user receives is validated against the client core, since that is what reads
it; share URIs and AmneziaWG `.conf` files are cross-checked against the bundle
node for the same inbound. Without the client core the gate skips;
`CONTRACT_REQUIRED=1` turns skips into failures. The pre-commit hook runs it
only when generators, option structs or protocol registrations are staged.

## License

**GPL-3.0-or-later**, see [LICENSE](LICENSE). This is inherited: `core/`
derives from sing-box (GPL-3.0) via hiddify, the WG-over-VK relay derives from
qWDTT (GPL-3.0), and mieru is GPL-3.0. No weaker licence is available for the
combined work, and GPL-3.0 code cannot be relicensed to AGPL-3.0.

sing-box's licence also forbids derivative works from using its name or
implying association. This project is named neutrally and makes no claim of
endorsement by or association with sing-box or Hiddify.

Every third-party component, its licence and how it is used are recorded in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). Read it before adding a
dependency or copying code.

Licensing is recorded per directory, next to the code it governs; those files,
not this one, are the governing terms for their directories:

| Path | License |
|---|---|
| this repository | GPL-3.0-or-later |
| `core/` | GPL-3.0 + naming clause; see `core/LICENSE`, `core/NOTICE.md`, `core/PROVENANCE.md` |
| `core/thirdparty/tailscale/` | BSD-3-Clause |
| `core/thirdparty/{wireguard-go,gooserelay,sing-anytls,sing-shadowtls,sing-vmess,sing-snell,connect-ip-go,dnscrypt/v2}/` | MIT / permissive, each with its own `LICENSE` |
| `core/thirdparty/vaydns/` | see its `COPYING` |
| `core/common/ja3/` | see its `LICENSE` |
| `core/common/sniff/testdata/pcap/` | LGPL-3.0 + BSD-3 + MIT (nDPI, zeek and suricata-verify captures) |
| `relay/` | GPL-3.0-or-later; fork of qWDTT's `server.go`, see `relay/NOTICE.md` |
| `relay/rtpopus2/`, `relay/rtpopus3/` | MIT, vendored FreeTurn codecs |
