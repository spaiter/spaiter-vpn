# Bootstrap design

Status: design approved; all nine implementation slices are complete. The
strict desired-state schema lives in `internal/bootstrap/state`, read-only host
discovery in `internal/bootstrap/discover`, and the deterministic typed planner
in `internal/bootstrap/plan`. The allowlisted file transaction, ownership
checks, durable journal, crash recovery and rollback live in
`internal/bootstrap/transaction`. Pure profile/deployment rendering and typed
Compose lifecycle execution are reusable through `internal/profile`,
`internal/deploy` and `internal/compose`. The first-install apply engine lives
in `internal/bootstrap/apply`, with credentials read through
`internal/bootstrap/secret`, readiness proved by `internal/bootstrap/health`,
rotation validated by `internal/bootstrap/logrotate` and firewall rules opened
through the typed `firewall.Applier`.

The `bootstrap` command exists: `state`, `credential`, `plan`, `apply`, `status`
and `rollback`, with bare `bootstrap` as the guided wrapper over the same
planner and the same apply engine. Rollback reconstructs an earlier committed
desired state from digest-verified transaction backups, synthesizes the exact
runtime-preservation policy, and applies it as a new generation. Apply installs
and converges. A first install — re-plan under the lock, preflight, generate, write the managed files
in a transaction, open the missing firewall rules, `compose pull` and `up`, then
wait for readiness and run the self-test before recording a receipt. A
convergence does the same without the generator: it validates the live config
against the requested image, leaves `config.json` and `secrets.json` out of the
transaction entirely, and on failure restores the previous files and starts the
previous generation again rather than stopping it. The one thing it cannot do it
refuses **by name**: Docker installation. An apply
that silently omits a step the operator just approved is worse than one that
stops, so the engine keeps an allowlist of implemented action IDs rather than a
list of exclusions; a future planner action is refused until someone implements
it.

**Proven on a clean host, 2026-11-04:** the acceptance suite in
`test/acceptance/` passed 113 checks in a disposable Ubuntu 24.04 QEMU guest —
plan, foreign-file refusal, rollback of a deployment that cannot become healthy,
recovery from an apply killed after both its files and UFW rule were written,
ownership adoption of that rule, a clean install ending in the live BitTorrent
self-test passing with `reject actions: drop,xdp-block`, a second apply that
rotated no key, restart migration and interrupted-restart recovery, rollback of
a failed convergence, a live port migration that closed the retired UFW rule,
exact subnet and seed-user migrations that retained credentials, and explicit
generation rollback that restored historical subnets while preserving live
users, bot peers and external WG-over-VK relay state. XDP attaches in the guest,
so the proof covers the blocker rather than skipping it.

Running it found six defects that every unit test had missed. Five were in the
product and are fixed below; the sixth was in the suite itself (a background
apply started through a shell function, so the kill hit the wrapper while the
real apply kept the lock — which read exactly like a product that cannot
recover).

## 1. Outcome and non-goals

The first supported journey is:

1. the operator obtains and verifies one release artifact;
2. `spaiter-vpn bootstrap` discovers the host and asks only for facts that
   cannot be discovered;
3. it prints every intended host change before applying one;
4. after explicit confirmation it installs the deployment, waits for it to be
   usable and runs the existing live self-test; and
5. running the same command again preserves credentials and converges files,
   firewall rules, log rotation and Compose services.

The initial platform matrix is deliberately narrow: Ubuntu 24.04 or Debian
12/13 on amd64, systemd, root for apply, and Docker Engine with the Compose
plugin.
Planning is read-only and may run unprivileged when all existing state is
readable. Apply does not silently elevate itself; it prints the exact `sudo`
command when root is required.

Phase 7 does not provide the phase-8 daemon or Unix-socket API, provider
images, cloud-init, a web GUI, or arbitrary reconfiguration of a live server.
In particular, it does not turn `init -force` into an update mechanism.

## 2. The state boundary

There are three different kinds of state. Treating them as one is the shortest
path to rotating every user's keys during an innocent re-run.

| Kind | Owner | Examples | Bootstrap rule |
|---|---|---|---|
| desired state | operator | tier, protocols, ports, domain, image, bot enabled | versioned, reviewable, no secret values |
| credentials | bootstrap/core | private keys, passwords, API tokens | root-only; preserve unless an explicit rotation operation exists |
| runtime state | core/bot | provisioned users, peers, counters, bot database, ACME state | mutable; recover server credentials from the live config, never from seed intent |

The core writes live provisioning changes back to `config.json` through
`config_output_path`. That makes the file runtime state, not an immutable build
artifact. The generated `secrets.json` describes the initial handover but is
not authoritative after the bot has provisioned more users. Consequently a
repeat bootstrap treats that live config as the single server-side credential
store. Convergence preserves it; a supported migration recovers its users and
keys and re-renders around them. It never regenerates from the original user
list. Client-only private peer keys remain in the bot/client store, as intended.

Changing protocol shape after the first successful apply is a **migration**, not
convergence. Ports, MTU, protocol membership and handshake targets are applied
through the management API with credentials preserved. Tier,
domain/certificate provider, XDP and log-level changes preserve the same live
credentials but force-recreate the Compose project because the management API
cannot reload their top-level state. A subnet moves only under an exact
`preserve-host` policy, which rewrites the live config, the handover snapshot
and the bot's peer files in one transaction. The bot is stopped before its peer
files are read, not merely before they are written, so a peer it provisions at
the last moment is either migrated or refuses the move — never left behind on
the old subnet. WG-over-VK additionally migrates matching `wg_ip` copies in the
explicitly located external relay `passwords.json`, and seed-user changes use
their own exact `preserve-existing` policy. Image, bot settings, log rotation
and firewall rules are ordinary reconciliation.

Three consequences of that boundary turned out to be load-bearing, and all
three were found by running it rather than by reasoning about it:

- **The runtime files are absent from a convergence's transaction**, not written
  with equal content. There is no equal content to write — the generator would
  produce different keys, and the core has already rewritten the config since —
  so preservation is structural rather than a comparison somebody has to get
  right.
- **`secrets.json` is held to byte equality; `config.json` is not.** Nothing in
  a running deployment writes the credentials, so any change there is the
  apply's fault. The core owns the config and rewrites it through
  `config_output_path` whenever a user or peer is provisioned — and the
  self-test an apply has just run adds a throwaway endpoint and removes it
  again, so a digest comparison across an apply would fail on a deployment that
  is behaving correctly.
- **Compensation differs by mode.** A failed install ends with nothing running;
  a failed convergence must end with the previous deployment running again. So
  convergence restores the files *first* (which puts back the previous compose
  project and image), then starts the project from them and waits for it to
  answer; it never runs `compose down`, which would take a working server
  offline because an update to it failed. The expected service list for that
  wait comes from the restored project, not from desired state, because a
  convergence that was enabling or disabling the bot changes which services
  exist.

Still deferred to the remaining phase-8 work: address/user-policy migration
outside the management API's inbound/endpoint boundary.

This is narrower than pretending all fields are mutable, but it fulfils the
fresh-host goal without creating an update path that silently destroys access.

## 3. On-disk layout

The default root is fixed rather than accepted from a remote caller. Local CLI
flags may override it for development and tests; the future control API will
not accept arbitrary host paths.

```text
/etc/spaiter-vpn/
  desired.json                 # 0644, root:root, no secret values
  credentials/                 # 0700, root:root
    telegram-token             # 0600, optional
    cloudflare-token           # 0600, optional
  deployment/                  # 0700, root:root
    config.json                # mutable core state, 0600
    secrets/secrets.json       # initial client credentials, 0600
    docker-compose.yml
    .env                       # remains non-secret
    bot.json
    reload-agent.sh
    firewall.sh                # preview/debug artifact, not the apply engine
    logrotate.conf
/var/lib/spaiter-vpn/
  cache/                       # core cache and ACME state as configured
  bot/                         # bot database/subscriptions/runtime files
  bootstrap/
    lock
    current.json               # last successful apply receipt
    transactions/<id>/         # journal, backups and redacted result
```

The desired document stores secret references by fixed logical name, never a
token and never an arbitrary path. Interactive input is written directly to a
root-only credential file and is not echoed, included in the plan, passed in
argv or written to the audit journal. Existing `CLOUDFLARE_API_TOKEN` and token
file inputs remain usable for an import, but the persisted reference becomes
`cloudflare-token`.

Certificate files are an explicit exception because `cert-source=files` points
at externally renewed material. The bootstrap accepts them only as root-owned
regular files beneath an allowlisted certificate root, rejects symlinks and
checks ownership and mode before every apply. A later local control API exposes
the logical certificate source, not a free-form filesystem path.

## 4. Desired-state schema

Use JSON and strict decoding: unknown fields are errors. The document has an
API version from the first release so migrations do not become guesswork.

```json
{
  "apiVersion": "spaiter-vpn/v1alpha1",
  "deployment": {
    "image": "registry.example.com/spaiter/spaiter-vpn-core:95c4dcb7",
    "tier": "a",
    "protocols": { "disabled": [] },
    "ports": {},
    "xdpInterfaces": ["auto"],
    "logLevel": "debug"
  },
  "bootstrap": {
    "seedUsers": ["owner"],
    "installDocker": false,
    "manageFirewall": true,
    "manageLogrotate": true
  },
  "bot": {
    "enabled": true,
    "adminIds": [123456789],
    "publicHost": "198.51.100.10",
    "subscriptionHost": "sub.example.com",
    "wdttConfigDirectory": "/srv/spaiter-vpn/wdtt-relay"
  }
}
```

Tier-B certificate fields form a tagged union matching `profile.TLSCerts`:
`files`, `acme-http` or `acme-dns`. Only the selected branch may be present.
The Cloudflare token is represented as `"credential": "cloudflare-token"`.

Defaults are applied while creating the document, not while reading it. A
stored desired state is therefore complete enough to review and hash, and a
future default change cannot alter an existing server on the next apply.

`seedUsers` is immutable after the first apply unless an explicit
`migrationPolicy.seedUsers` entry (`strategy: "preserve-existing"`) names the
exact `from` and `to` seed-user lists. When authorized, kept seed users and
live bot-provisioned users retain their existing credentials and WireGuard peer
addresses, newly added seed users receive fresh credentials and free peer
addresses in both `config.json` and `secrets.json`, and retired seed users are
removed from both stores (with bot subscription caches invalidated). Telegram
admin IDs may be supplied, or left empty and ownership claimed with a local
one-time code: `spaiter-vpn bot claim-code` stores a hash of a 60-bit code in
the bot's data directory (`0600`), valid for 15 minutes and destroyed after five
wrong attempts or one success, and the owner sends `/claim <code>` to the bot.
The bot no longer makes the first caller its admin; the plan names the claim
as a manual step when `adminIds` is empty.

Credential rotation is an event, not an end state, so it is the one policy
entry with an identity: `migrationPolicy.rotateCredentials` carries an `id`, a
sorted `users` list and `strategy: "reissue"`. An entry identical to the
previous generation's is a retained audit record; a new `id` requests a new
rotation, and reusing an `id` for different users is refused. A rotation must be
the only migration in its generation, so a failure is never ambiguous about
what to retry and a rollback never undoes two things at once. `bootstrap rotate`
synthesizes the entry with a timestamped random `id` from the stored desired
state, the same way `rollback` synthesizes its document.

Rotation clears the selected users' per-user slots before regeneration and
keeps each WireGuard peer's address, so the generator mints new values in the
same places. It refuses before writing when a rotated peer's private half has
no copy bootstrap can update (the live config only holds public keys), and it
proves on the rendered bundle that rotated users hold a different value in
exactly the slots they had, everyone else is identical and no deployment-wide
key changed. The same transaction then rewrites the seed handover, the bot's
peer files, the user's WG-over-VK password and the relay's `passwords.json`
(removing the old entry and the devices bound to it, as the relay's own delete
does, and keeping operator policy and counters), replaces the user's
subscription token and invalidates subscription caches. A leaked subscription
link would otherwise serve the new credentials on its next poll.

`bot.wdttConfigDirectory`, when non-empty, is a clean absolute host directory
shared with the externally managed WG-over-VK relay. Bootstrap requires an
existing regular `passwords.json`, mounts the directory into `vpn-bot` at
`/wdtt-cfg`, and uses the exact host path for authorized `wg-wdtt-in` subnet
migrations. Relay entries are correlated with the bot's peer and password
copies before `wg_ip` changes; unknown top-level and per-entry fields survive,
the reload marker joins the transaction, and a concurrent file change fails
closed rather than losing an update.

## 5. CLI contract

```text
spaiter-vpn bootstrap                 # guided plan, confirm, apply
spaiter-vpn bootstrap plan  -f FILE  # read-only, machine-readable with --json
spaiter-vpn bootstrap apply -f FILE  # recompute plan under lock, then apply
spaiter-vpn bootstrap status         # desired/current generation and health
spaiter-vpn bootstrap rollback       # restore the previous successful receipt
spaiter-vpn bootstrap rollback -generation N # select an older committed generation
spaiter-vpn bootstrap prune -keep N  # preview old transaction deletion
spaiter-vpn bootstrap prune -keep N -yes # apply explicit retention
spaiter-vpn bootstrap rotate -users alice,bob # reissue named users' credentials
```

`bootstrap` without a subcommand is the guided wrapper, not a second
implementation. It creates or loads desired state, calls the same planner,
prints the plan, asks for confirmation and calls the same apply engine.
Non-interactive apply requires `--yes`; stdin not being a terminal never
implies consent.

Rollback has the same consent, root, preflight, validation, transaction,
firewall, health and self-test gates as apply. It never moves the receipt
pointer backwards: restoring generation N commits a newer generation. Current
seed users are retained, so users introduced after N are not retired; all users
recovered from live `config.json`, including bot-created users, keep their
credentials. Current runtime storage paths are retained and subnet reversals
receive exact `preserve-host` policies, so bot peers and external WG-over-VK
relay entries move atomically. A target that enables a protocol missing from
the current live shape is rejected rather than minting a replacement server
credential.

Pruning requires an explicit `-keep N` retention rule, with N at least two and
including the current generation. Without `-yes` it only previews the selected
transactions. Both preview and deletion recover any interrupted transaction and
hold the exclusive lock. The cutoff is the earliest retained committed
generation: every older committed or rolled-back transaction can be removed,
while unknown directory entries are left untouched. The first later committed
change to a managed file remains in the retained history, so its backup still
reconstructs the oldest retained generation.

Plan output is ordered and typed. Every action says why it exists, whether it
mutates the host, which check proves success and what rollback is available.
Secret values are represented only as `present`, `missing` or `invalid`.

The planner returns a digest over canonical desired state and the relevant
observations. Apply takes the exclusive lock, discovers the host again and
recomputes the plan. If the digest changed, it prints the new diff and refuses
to apply stale consent. The guided command avoids this plan/apply gap by doing
both in one locked process.

## 6. Internal packages

The bootstrap is an orchestrator over existing packages, not a CLI calling its
own CLI commands.

```text
internal/bootstrap/state       strict schema, defaults, validation, migrations
internal/bootstrap/discover    OS, privileges, Docker, files, firewall, services
internal/bootstrap/plan        pure desired + observed -> ordered typed actions
internal/bootstrap/transaction allowlisted files, journal, recovery, rollback
internal/bootstrap/apply       action execution and compensation
internal/bootstrap/platform    Ubuntu/Debian package and Docker repository adapter
internal/bootstrap/health      Compose readiness and local control endpoint polling
internal/bootstrap/secret      fixed-name credential store and redaction
```

Existing CLI logic needs thin reusable APIs:

- `internal/preflight` is already callable and remains the source of host
  checks;
- `internal/profile.Render` is the single generation and JSON rendering entry
  point used by `init` and reserved for bootstrap;
- `internal/deploy.Render` returns the complete deterministic Compose, bot,
  reload and logrotate artifact set without writing it;
- `internal/firewall` remains the rule calculator, while apply receives a
  typed backend adapter instead of executing the emitted shell script;
- Compose execution lives behind the typed `internal/compose.Runner` interface
  (`pull`, `up`, `down`), used by `up` and ready for bootstrap; and
- the self-test is already callable through `internal/selftest`.

No action accepts a shell string. Commands are executable plus argument slices,
and every filesystem action receives a validated path from the layout object.
This makes the same action vocabulary suitable for the phase-8 privileged
reconciler without accidentally growing an arbitrary root-command endpoint.

## 7. Plan and apply order

Planning performs no writes, package refresh, image pull or key generation.
It may query package metadata only when Docker installation was explicitly
requested.

Apply order:

1. acquire the exclusive lock and reject an incomplete transaction that has
   not been inspected. The lock is held by a `transaction.Guard` across
   discovery, generation and container start, not merely across the writes, and
   a transaction opened inside it does not release it on commit;
2. validate platform, root ownership, credential references and desired state;
3. optionally install the pinned Docker repository and exact package versions;
4. run the full existing preflight **before generating any credentials**;
5. create a private staging directory on the target filesystem;
6. for a first install, generate once through `profile.Generate`, render all
   deployment files and validate the staged config with `sing-box check`;
7. for convergence, leave runtime files outside the transaction; for a
   supported migration, recover credentials from live `config.json`, re-render
   it, validate it and journal its replacement while leaving `secrets.json`
   byte-identical;
8. stage and validate the logrotate file;
9. add only missing, supported firewall allow rules;
10. atomically replace managed files, journalling each one. The receipt is
    written only after the services are proven, so a failure during start can
    still be compensated. A committed transaction is never automatically
    compensated; explicit rollback restores its desired state as a new
    generation;
11. pull the immutable image and run Compose from the managed project;
12. on every existing deployment, synchronise live inbounds/endpoints with
    `config.json` through the management API (this also heals a crash between a
    previous live apply and its transaction commit);
13. wait for the container and the localhost management endpoint, with a
    deadline and recent redacted logs on failure;
14. run the existing self-test;
15. mark the transaction successful and atomically update `current.json`; and
16. report checks that cannot be proved locally: provider firewall/NAT,
    external reachability and client import.

Docker installation is a platform prerequisite transaction. If bootstrap
added its repository or packages and later fails, the journal records them but
does not automatically remove Docker: package removal can destroy unrelated
containers created concurrently. The failure report offers an explicit cleanup
command only when discovery proves Docker was absent, no foreign containers or
images appeared, and the operator requests cleanup.

## 8. File safety and ownership

Every managed target is opened relative to a pre-opened root directory with
no-follow semantics. Before replacement, bootstrap rejects symlinks, non-regular
files, unexpected owners and a path that escapes the managed root. It never
blindly overwrites a foreign file.

Each managed file contains or accompanies a marker with its schema version and
content digest. The three cases are:

- absent: create it;
- owned by bootstrap: update after backing it up;
- present but foreign: report a conflict and require an explicit import step.

Writes use a same-directory temporary file, `fsync`, rename and directory
`fsync`. The transaction journal is flushed before the corresponding mutation
so a power loss leaves enough information to recover. Backups retain mode,
owner and group and are stored under the root-only transaction directory.

Only one bootstrap/apply/rollback/rotate/prune may run at a time. Apply holds the lock
from discovery through the final receipt; pruning holds it through deletion.

Restart migrations journal their recreate intent before Compose is touched. If
the process dies after the container was replaced but before commit, file
recovery restores the previous generation and marks `recreatePending` in the
receipt. The next plan uses `restart-recover`, force-recreates from those
restored files, proves health/selftest and only then clears the marker. Normal
compensation records the marker resolved after it successfully recreates the
previous generation, so an old rolled-back journal cannot cause endless
restarts.

Two things deliberately sit outside the transaction. The core's cache directory
and the bot's data directory are created before it and are never removed by a
rollback: they hold ACME state and the users the bot has provisioned, which is
exactly the state a rollback exists to protect. The reload marker is created as
a regular file for the same reason it is derived rather than configured twice —
Docker creates a *directory* at a missing bind source, after which the bot's
write fails and reloads stop working with no visible error.

The bot's Telegram token reaches Compose through the Docker CLI's process
environment. Not argv, which any local user can read from `/proc`; not the
generated `.env`, which is mode 0644 and deliberately secret-free; not a shell
string, which the typed `compose.Runner` exists to prevent.

## 9. Firewall and logrotate boundary

Bootstrap never enables a firewall, changes a default policy, removes an
unrelated rule or assumes a cloud firewall is visible locally.

The first writable backend is active UFW because it can be discovered and
reconciled reliably on the initial Ubuntu/Debian matrix. Bootstrap records each
exact rule it added and rollback removes only those additions. An inactive or
absent host firewall needs no local rule mutation. firewalld, raw nftables and
iptables remain plan-only until each has a tested typed adapter; an unknown
ruleset is not permission to run the current generated shell script.

`/etc/logrotate.d/spaiter-vpn` is installed only when absent or already marked
as bootstrap-owned. `logrotate --debug` validates the staged file before
commit. A foreign file is a conflict, not an overwrite.

**A killed apply does not disown rules it opened.** The transaction journal
records the exact additions before UFW is touched. Recovery rolls the managed
files back, then folds those additions into the durable ownership receipt. On a
killed first installation that receipt intentionally owns firewall rules but no
files; discovery does not mistake it for a deployment, so the retry plans a
fresh install and its committed receipt absorbs the ownership. The journal is
marked adopted only after the receipt is durable, making a second crash at that
boundary safe to replay. Independent acceptance cases still reset UFW because
they model independent clean hosts, not successive generations of one host.

**A migrated port closes the door it stopped using.** The receipt records the
rules this deployment opened and has not retired, as `port/protocol`, and a rule
is closed only when it is in that list and no longer wanted. That ownership
record is the whole mechanism: the alternative — diffing the live rule set
against what the deployment wants — would delete whatever the operator opened
for their own reasons, which on a remote host means cutting their SSH.

Three details are load-bearing:

- **Open before close.** A port that is both wanted and owned is never briefly
  shut, and a migration that moves a listener opens the new door before closing
  the old one.
- **The undo is symmetric.** A failed apply closes what it opened *and re-opens
  what it retired*. Without the second half, a failed port migration would
  restore the previous deployment unreachable on the only port its clients know
  — worse than the failure that triggered the rollback.
- **An entry that cannot be parsed is kept, not acted on.** We cannot close what
  we cannot name, and dropping it from the record would disown a rule that is
  still open. Likewise, turning firewall management off carries the list
  forward rather than disowning everything, which would strand those rules
  permanently.

The implemented adapters follow that boundary exactly. `firewall.Applier` is
typed per rule — `Add`, `Remove`, `Name` — so a privileged caller behind it
cannot express "change the default policy" or "flush the ruleset" at all, and
the rules to add come from the observation the approved plan was built on rather
than from a second probe, so what is opened cannot differ from what was
reviewed. The add/retire intent is journalled before mutation; normal rollback
removes only additions made by that apply, while crash recovery conservatively
adopts additions instead of deleting firewall state without a live process to
prove what happened.

Validating logrotate turned out to need care. `logrotate --debug` exits non-zero
and prints `error:` lines for reasons unrelated to the configuration: the core's
log file does not exist yet at install time, and `/var/lib/logrotate/status` is
unreadable without root. Trusting the exit status, or grepping for `error:`,
refuses every valid configuration — that was the first implementation and it was
wrong. A parse error is distinguishable because logrotate prefixes it with the
config path and a line number, and that is the only signal read.

## 10. Rollback semantics

Rollback means restoring the last known working product generation, not trying
to return the entire operating system to an earlier moment.

On an apply failure, compensation runs in reverse order:

1. restore previously managed files from the journal;
2. remove only firewall rules added by this transaction;
3. restore the previous Compose project and image reference;
4. run Compose again, re-apply the restored config through the management API
   and wait for the previous local health check; and
5. retain the failed transaction and redacted diagnostics for inspection.

For a failed first install, Compose services created by the transaction are
brought down, but credentials and the transaction backup are retained. The
operator can retry without rotating keys. Volumes, bot data, ACME state and
mutable config are never deleted automatically.

Rollback itself is journalled and may fail. Such a failure is reported as
`apply failed; rollback incomplete`, naming the exact remaining actions. It is
never collapsed into the original error.

## 11. Health and proof

`container is running` is necessary but insufficient. Success requires:

- Compose reports every expected service running;
- the core's localhost management endpoint answers with the expected secret;
- no expected service has entered a restart loop during the settle window;
- the live BitTorrent self-test passes and cleans up its temporary endpoint;
  and
- the installed logrotate configuration validates.

The implemented wait samples Compose service state and the management endpoint
on an interval and requires both to hold continuously for a settle window. The
window is the whole point: a crash-looping container reports `running` for part
of every cycle, so a single sample is worthless, and a service that flaps must
not inherit the time it was healthy. A failure report names what was wrong and
carries recent output per service, scrubbed of known credential values, with an
empty log reported as "the process never started" — that is a diagnosis in
itself, since it places the fault at the container level rather than in the
application.

Health and the self-test run **before** the receipt is written. The receipt
names the generation a later rollback restores, so recording one for a
deployment that never answered would make the broken state the thing we roll
back to.

External reachability cannot be proved from the server itself. The result ends
with a generated `spaiter-vpn probe` command to run from another network and a
machine-readable list of ports for a provider firewall. Tier B additionally
reports DNS resolution and certificate issuance state separately; local DNS
resolution is not claimed as proof that ACME or the public path works.

## 12. Test and delivery slices

Implementation should land in reviewable slices:

1. **complete:** strict desired-state schema, canonical form and immutable-field
   diff;
2. **complete:** discovery plus a deterministic read-only planner with golden
   plan tests;
3. **complete:** file transaction, ownership checks, crash-recovery journal and
   rollback;
4. **complete:** extraction of reusable generator/Compose APIs with no
   behaviour change to `init` and `up`;
5. **complete:** first-install apply without Docker installation, firewall
   mutation or logrotate installation;
6. **complete:** health wait and self-test;
7. **complete:** UFW and logrotate adapters;
8. **complete, and passing:** optional pinned Docker installation for the
   supported distributions, proved by `docker-install-acceptance.sh` (18 checks
   on a Docker-less Ubuntu 24.04 guest, 2026-11-05); and
9. **complete, and passing:** disposable-VM acceptance tests — clean install,
   identical second apply, interrupted apply, failed health rollback,
   foreign-file refusal and key preservation. The suite lives in
   `test/acceptance/`; see its README for which gates it asserts today and which
   have to be rewritten rather than deleted when the reconcile slice lands.

### What acceptance found

Each of these was invisible to the unit tests, and each would have met an
operator on their first real install.

1. **An interrupted apply could not heal.** The CLI built the plan before taking
   the lock, so the transaction manager's automatic rollback never ran. The
   planner saw the half-written files as a deployment it must not adopt, returned
   a blocked plan, and apply never started — so the lock was never taken and the
   rollback stayed unreachable. The host needed `rm -rf` to become installable
   again. Apply now recovers before planning.
2. **The default log level made the product's own gate unreachable.** The fork
   logs a BitTorrent detection at info, but the reject that follows it is logged
   by the router at debug. At info the traffic is still dropped and there is no
   record of the drop — so the self-test reported "identified and then allowed
   through", which was both frightening and false, and apply refused to record a
   deployment it could not verify. The generated default is now `debug`, and the
   self-test now distinguishes "not enforced" from "not observable at this
   level".
3. **Preflight blocked the apply that fixes what preflight complained about.**
   At debug level an unrotated log is a failure, and preflight runs before any
   host file is written — including the logrotate file installed three steps
   later. `preflight.Options` now carries `LogrotateWillBeInstalled`, because the
   check's question is whether the log will be reclaimed, not whether the file is
   already there.
4. **A killed first installation produced a receipt that looked like a foreign
   deployment.** Recovery correctly needed a durable place to claim the UFW
   additions made before the crash, but discovery treated that firewall-only
   receipt as runtime state. The retry was therefore blocked as an untracked
   deployment. Discovery now distinguishes an ownership-only receipt from a
   committed deployment, recovery preserves it across repeated runs, and the
   journal is marked adopted only after the receipt is durable. The QEMU suite
   kills the real apply only after both a managed file and its UFW rule exist,
   then proves that retry completes and keeps ownership of the rule.
5. **The self-test's fixed subnet could make a valid migration fail its proof.**
   Moving a production endpoint to `10.99.0.0/24` succeeded, but the self-test
   then refused to use its own identical default subnet and apply rolled the
   otherwise healthy migration back. The default is now a preference: self-test
   deterministically selects a free private /24 when it overlaps live state,
   while an explicitly supplied `-subnet` still fails closed on collision.
6. **Every migration minted peers for bot users that nobody could use.** The
   first credential rotation in a VM refused, correctly, because bot user
   `4242` had an `awg3-in` peer with no private-key copy anywhere. An earlier
   seedUsers migration had re-rendered every live user onto every endpoint, so
   the generator issued that bot user peers (and proxy accounts) it never
   asked for. The bot keeps the private halves of its users' peers and would
   later have added a second peer of the same name beside each orphan. Unit
   fixtures had always given bot users a full set, so nothing else noticed.
   `profile.Spec.Mint` now restricts generation per user: migrations issue
   bot-provisioned users nothing new, and a rotation reissues exactly the slots
   a user held.
7. **A successful rotation locked the deployment against every later
   operation.** Its receipt owned `bot/wdtt/subs.json` and each rotated user's
   `bot/wdtt/<uid>.json`, but the allowlist a later process rebuilds from the
   layout did not name them, so recovery refused the receipt and apply,
   rollback and the control daemon's status all failed. Unit tests reused the
   harness's manager, whose allowlist the rotation had just extended. Those
   paths are now part of `BotTransactionTargets`, and the test rebuilds a
   manager from the layout alone after rotating.
8. **A bootstrap-deployed bot had never been able to start.** Its Compose
   service ran `command: ["bot", …]` on a bare `distroless/static` image
   with no entrypoint, so the container looked for a program called `bot`.
   Every earlier case faked the bot's state instead of running it; the first
   case that started a real bot, against a stand-in Bot API, failed on it. The
   service now names the mounted binary as its entrypoint.
9. **Handing the bot its directories locked bootstrap out of them.** File
   transactions require a target's parent to be owned by the manager, which
   is correct by default: root writing by path into a directory an
   unprivileged account controls is the classic symlink-swap attack. With the
   bot's data directory owned by the bot, both the apply and its rollback were
   refused. `transaction.Manager.Delegated` now names the bot's data directory
   (its uid) and the relay directory (root with its group) as the only trees
   whose directories may have that owner. They still must not be group- or
   other-writable, and writes stay exclusive no-follow temporary files renamed
   into place. Every process that opens a manager derives the delegation from
   the account's existence, so a switch back to root can still move the files.
10. **No supported migration had ever changed the image successfully.**
    The first one that did, enabling per-user MTProto on a newer core,
    recreated the container and immediately asked its management API to
    apply. The API was not listening yet, so the apply and its rollback both
    failed with a refused connection. A plain image convergence had the same
    race. The runtime sync now retries a refused connection for up to a
    minute; any answer from the API, including a rejection, is final.
11. **Credentials a migration minted for seed users never reached them.**
    `secrets.json` was held byte-identical through every migration other
    than the subnet, seedUsers and rotation ones. A migration that issued a
    seed user something new, such as a per-user MTProto secret or a newly
    enabled protocol, put it in `config.json` alone, where no client could be
    given it. The deployment facts there also kept a moved port's old number,
    so `clients` rendered links to it. Migrations now refresh the handover:
    facts follow the rendered bundle, slots and peers a migration minted are
    added, and existing credentials are kept, or refused if they disagree
    with the live configuration.
12. **The managed web UI could not read its own key.** The service ran as
    `spaiter-vpn-web`, and the key sat in `/etc/spaiter-vpn`, which is root-only
    `0700`, so the service started and never listened. Opening the
    configuration directory to it would have been the wrong fix. The unit now
    uses `LoadCredential=`: systemd, as root, reads the key and gives this
    service alone a private copy. The bot still gets it through a bind mount
    readable by its group.
13. **A failed first isolation of the bot could not be rolled back.** The
    directories an apply may find owned by the bot's account were worked out
    when the apply started, and the first isolation creates that account
    part-way through. Once its directories had been handed over, the rollback
    refused to write into them ("owned by 993:984, want 0:0") and left the host
    with neither deployment running. They are now recomputed as soon as the
    account exists. What made the apply fail was a dynamically linked binary,
    which the bot's container, with no C library, reports as "no such file or
    directory" forever; such a binary is now refused before anything changes.
14. **`verify` could be stopped by a single node.** A MASQUE-WG node that
    could not connect stopped the whole client core as it started, and the
    image's core then panicked while shutting down, before printing why. The
    report said only that the core exited. Now a node the core names as
    failing at start is reported failed and left out of a restart, and a core
    that stops without naming one has its nodes tried one at a time. The core
    log in the report keeps its start as well as its end.

The release gate for phase 7 is not unit coverage alone. A clean supported VM
must reach a passing self-test, a second apply must produce no credential or
runtime-config diff, and an injected post-start failure must restore the prior
healthy deployment.

## 13. The control plane

`spaiter-vpn control serve` is the phase-8 service: a root daemon on
`/run/spaiter-vpn/control.sock` that wraps this engine rather than replacing
it. `spaiter-vpn control unit` prints its systemd unit.

- **Identity comes from the kernel.** The daemon reads the caller's uid with
  `SO_PEERCRED`; nothing the caller sends can claim an identity. Root-owned,
  root-writable `/etc/spaiter-vpn/control.json` lists `observers` (status,
  generations) and `operators` (everything else) by uid. Root is always an
  operator. `socketGroup` makes the socket `0660` for that group as a second
  fence, but group membership alone grants nothing.
- **Operations are typed and closed.** One endpoint, one strict request shape
  with unknown fields refused, and a fixed list: `status`, `generations`,
  `preflight`, `selftest`, `prepare`, `commit`, `cancel`. A change is one of
  `settings` (ports, MTU, enabling or disabling protocols), `image` (a new tag
  or digest of the repository already deployed — another registry is refused),
  `rotate` (named users) or `rollback` (a generation). No request can name a
  host path, a certificate file, a credential reference, the relay directory
  or a command, and Docker installation stays a local `bootstrap apply`.
- **Consent has two steps.** `prepare` synthesizes the desired state with the
  same functions the CLI uses, plans it and returns the plan with a random,
  single-use ticket bound to the caller's uid and valid for ten minutes.
  `commit` runs it through `apply.Run`, which recomputes the plan under the
  engine lock and refuses stale consent exactly as for the CLI. A ticket is
  consumed before it runs, so a failed commit is prepared and reviewed again
  rather than retried blind. One mutation runs at a time; a second caller is
  told the daemon is busy.
- **Every request is audited.** Granted, denied and malformed requests append a
  JSON line to `<data-root>/control/audit.log` (`0600`, fsynced per entry):
  time, kernel-reported uid/gid/pid, operation, a typed change summary, ticket
  and transaction, and a redacted error. Plans, outputs and credentials are not
  logged; responses are scrubbed of stored credentials and the management
  secret.

`bootstrap.manageControl: true` makes bootstrap install the daemon as
`/etc/systemd/system/spaiter-vpn-control.service`, a managed file whose
`ExecStart` is the same binary the bot mounts, create
`/etc/spaiter-vpn/control.json` once with nobody but root allowed (the operator
owns it afterwards; later applies never replace it), enable and start the unit,
and prove it by a status request on the socket before recording the generation.
A changed unit is restarted; turning the option off stops the daemon while its
unit file still exists and then removes the file. Each step is reversed by the
compensation when the apply fails. With the bot enabled, the bot mounts
`/run/spaiter-vpn` and gets `control_socket` in `bot.json`.

The bot is the first client. Its admins get a "🛠 Сервер" menu (status,
generations, rollback) and `/rotate`, `/port` and `/image` commands. Each one
prepares a change and shows the plan — mode, desired-state changes and every
host-mutating action — with "apply" and "cancel" buttons carrying the ticket.
Nothing changes until an admin presses "apply". A compromised bot can request
typed VPN operations and nothing more.

`bot.dedicatedUser` (set in new documents, omitted when false so older ones
keep their digest) runs the bot as the system account `spaiter-vpn-bot`, which
bootstrap creates once and records in `platform.json`. The bot then no longer
mounts the core's configuration directory, which holds every private key:
`deployment/bot-management.json` (`0640`, the bot's group) gives it only the
management endpoint and secret. Every bot-state file a transaction writes is
owned by that account. Switching an existing bot moves the receipt-owned files
through the transaction, so the receipt agrees with the disk, and hands the
rest of the data directory over with `chown`. The relay directory becomes
`0750` with the bot's group: enterable, but not writable by anyone but root,
because bootstrap's own transactions refuse a group-writable directory. The bot
therefore rewrites `passwords.json`, which it owns, in place instead of by
rename. A daemon allow-list created alongside names the bot's uid as its
operator and its group as the socket's. Switching back to root reverses each
step. `bot.telegramApiUrl` points the bot at another Bot API server, such as a
self-hosted one.

Every host the bot hands out comes from the document. `bot.publicIpv4Host`
is an A-only name for the UDP methods, for a `publicHost` that also has an
AAAA record (VK's TURN has no IPv6); `bot.cdnHost` is the CDN edge in front of
the CDN-fronted VLESS inbound. Both are optional. The bot's own built-in
defaults name the original deployment's hosts, so a rendered configuration
replaces them with these values or with nothing, and never inherits them.

The web UI (`spaiter-vpn web serve`) is the second client. It runs as an
unprivileged account in the daemon's allow-list, refuses to start as root,
listens on loopback unless it sits behind HTTPS (`-secure-cookie`), and holds
no deployment logic. Access is by one-time login links signed with HMAC by
`/etc/spaiter-vpn/web.key` (`spaiter-vpn web key`): a link names its expiry,
which is at most a day, and a nonce that works once. `spaiter-vpn web
login-link` prints one on the server, and the bot's `/weblogin` sends one to a
Telegram admin when `web.url` and `web.key_path` are configured. A session is an
in-memory id behind an `HttpOnly`, `SameSite=Strict` cookie that lasts eight
hours. Every form carries the session's CSRF token, and a cross-origin
`Origin` is refused. Pages are `html/template` with a CSP that forbids scripts.
They show status and generations, and offer port, protocol, image, rotation
and rollback changes. Each change shows the daemon's plan and is committed
only by its ticket.

`bootstrap.manageWeb` (it needs `manageControl`) has bootstrap run the web UI
as the system account `spaiter-vpn-web`, in the group `spaiter-vpn`, which it
creates once and records in `platform.json`. The unit is managed like the
daemon's and is proved by an anonymous request answered with 401. `web.listen`
defaults to loopback; any other address needs `web.publicUrl` on https,
which also marks the session cookie Secure. The key `web.key` is created once
(`0640`, group `spaiter-vpn`), kept across applies so sessions survive, and
removed with the service, which signs every link and session out. The bot is
given the key and the URL, plus the group through `group_add`, so `/weblogin`
works for a bot running as its own account.

Service accounts reach the daemon through a second allow-list,
`control.bootstrap.json`, which bootstrap manages and the daemon merges with
the operator's `control.json`. Each file keeps one owner: the operator's edits
are never rewritten, and bootstrap adds or removes the bot and web accounts
itself, restarting the daemon when its list changes. The socket's group is
`spaiter-vpn` unless the operator set another.

### Dynamic DNS

A server whose public address changes is reached by a name, and the name has
to follow the address. `ddns` in the desired state has bootstrap run
`spaiter-vpn ddns run` as `spaiter-vpn-ddns.service`, beside the control
daemon's unit:

```json
"ddns": { "provider": "cloudflare", "token": "ddns-token", "ipv6": true }
```

It keeps `bot.publicHost` (A, and AAAA with `ipv6`) and `bot.publicIpv4Host`
(A only). Providers: `cloudflare`, `duckdns` (only `*.duckdns.org`), and
`dyndns2` with `username` and an https `server`, IPv4 only. Validation wants a
name in `bot.publicHost`, not an address, and `bot.dynamicIp` records that the
address changes, which on its own already refuses an address literal there.

The unit runs the binary bootstrap was run from, in place, as root with every
capability dropped: the filesystem is read-only but its `StateDirectory`, and
the configuration and data roots do not exist for it (`InaccessiblePaths=`).
The token comes through `LoadCredential=`. Not a `DynamicUser`: that forces a
private `/tmp` and an account that cannot traverse a 0750 home, so a binary
in either place is not found (203/EXEC, which acceptance hit). The token's file
revision (inode and mtime, not its content) is written into the unit, so
`bootstrap credential` with a new token makes the next apply restart it.

The address is found the way the internet sees it, from three echo services
over the wanted family, two of which must agree (one answer is taken when only
one answers); a server behind NAT cannot see it any other way. The provider is
called only when the address changed, or after its refresh period (an hour on
Cloudflare, a day for the protocols that treat repeated no-change updates as
abuse). Each round's result goes to `/var/lib/spaiter-vpn-ddns/status.json`.
The apply's proof is the first round after a start or restart: a rejected token,
an unknown zone or host fails the apply and rolls it back; a network problem is
reported and left to the updater's next round.

## 14. Remaining decisions

- image update policy beyond an explicitly selected immutable reference.

Credential rotation (`bootstrap rotate`) and retention of transaction history
(`bootstrap prune`) were decided and implemented; see sections 4, 5 and 8.

Phase 7 nevertheless uses the same typed desired state, plans, actions and
receipts that the phase-8 service will expose. The daemon should wrap this
engine, not replace it.
