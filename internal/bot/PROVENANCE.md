# `internal/bot` — the Telegram provisioning bot

Imported into this repository on **2026-10-23**. Until then it had no version
control of any kind.

## What it is

`@SpaiterProxyBot`. It is the only thing that provisions users: it talks to the
core's clash `/manage` + `/stats` API to add and remove users and WireGuard
peers, issues the `/sub/<token>` subscription bundle, registers per-user WARP
accounts, and maintains the WG-over-VK hash pool. Lose it and there is no way
to onboard anyone.

## Where it came from, and why that mattered

| | |
|---|---|
| Source | `~/appdata/vpn-bot/bot.py`, a single file |
| Tracked by | nothing — no repository, no remote |
| In the image? | **no**; the Dockerfile has no `COPY`, the file is bind-mounted `ro` |
| History | one backup, `bot.py.bak-20260724-android-apk-button` |

The first commit in this directory is that July backup, so the second produces
a readable diff rather than a 114 KB blob appearing from nowhere. The diff
between them is **+1459 / −119 lines**: three months of edits made in place,
with everything between the two points overwritten and unrecoverable.

`system-backup.sh` does archive `~/appdata`, so the file was never one `rm`
away from oblivion — but a backup is not version control. It cannot say what
changed between July and October, and it cannot undo one edit.

## ⚠️ The live deployment still runs the file outside this repository

`/opt/stacks/vpn-bot/docker-compose.yml` mounts
`~/appdata/vpn-bot/bot.py:/app/bot.py:ro`. Importing the source did
not change that, so right now there are two copies and they will diverge the
moment anyone edits the live one.

Pointing the deployment here is a one-line change to that mount:

    - ~/src/spaiter-vpn/bot/bot.py:/app/bot.py:ro

followed by `stack-up vpn-bot up -d`. It is left undone deliberately: it
restarts the bot that is currently serving users, which is a production change
rather than a code change.

Until it is done, treat `appdata` as authoritative and re-import after edits.
After it is done, this directory is authoritative and `appdata` should keep only
`data/` and `apk/`.

## Configuration

Everything comes from the environment — 24 variables, all in
`docker-compose.yml`, which is imported here with its comments intact because
several of them record hard-won facts (why `WDTT_SUB_HOST_DIRECT` must carry
port 10866 on DS-Lite; why `BUNDLE_ENABLE_AWG3` cannot be turned on before
every client has a core that understands the AWG 3.x schema).

The only secret is `TELEGRAM_TOKEN`, passed as `${TELEGRAM_TOKEN}` and injected
by `stack-up` from `pass stacks/music-tgbot/…`-style entries — see the host's
`AGENTS.md`. **Nothing secret is committed here**, which was verified before
the import rather than after: `bot.py` reads every credential through
`os.environ`, and the compose file contains no literal.

## Deliberately not imported

| | Why |
|---|---|
| `singbox-fork` (57 MB) | a build of `core/`, used for per-user WARP registration. Rebuildable from this repository. |
| `wdtt-checkhash` (11.8 MB) | comes from the `wdtt-relay` repository. |
| `data/`, `apk/` | runtime state and a distributed APK, not source. |

Both binaries are in `.gitignore`. Keeping them as files beside the source was
only costing backup space.

## No Docker socket, and keep it that way

The bot had `/var/run/docker.sock` removed in the 2026-08-11 security audit: a
publicly reachable Telegram bot with the Docker API is effectively root on the
host. It now writes marker files in its data directory and something
privileged reacts to them. For sing-box that something is no longer a host
systemd unit but the reload sidecar this repository generates, which signals
the process over a shared PID namespace and needs no Docker access at all —
see `internal/deploy/reload.go`.

## The Python is gone (2026-11-03)

This package is the port: the same provisioning model, the same on-disk
formats, the same clash API, run as `spaiter-vpn bot`. Cut over on 2026-11-03
and confirmed on live traffic, after which `bot.py`, `bot/contract_test.py`,
`bot/Dockerfile`, `bot/docker-compose.yml` and the `bot` gate were deleted. This
file moved here because it is the provenance of what the code replaced, and a
directory holding only its own history is worse than the history living beside
the thing that supplanted it.

`embed.go` went with them, along with the reason it existed. It let the
installer deploy `bot.py` without a checkout, which solved something real: the
live bot ran from an untracked file under `~/appdata` and the copy in git
drifted from the copy executing. Nothing is left to drift — the provisioning
code and the core's option types are compiled together, which is also the fix
for the two outages that motivated the port.

Both contract implementations ran side by side through the port, which was the
only arrangement that could catch one of the generators drifting while the other
was being written. With one implementation left there is nothing to compare, so
the Python half of that gate went too.

### Rollback, after the deletion

Still available and worth knowing where. The host keeps
`~/appdata/vpn-bot/bot.py`, the image `vpn-bot:local`, and the Python compose
file as `/opt/stacks/vpn-bot/docker-compose.yml.bak-20261103-112545-python`;
restoring that file and running `stack-up vpn-bot up -d --force-recreate` brings
the old bot back. The formats under `data/` did not change, so it reads
everything the Go bot wrote — including `last_hash`, which it simply overwrites
with its own on the first refresh. Git history holds the source either way.

### What the cutover found, which the tests could not

Four values where the defaults disagreed with the bot that was actually running,
surfaced only by rebuilding all six live subscriptions and diffing them
(`spaiter-vpn bot -compare`, which reads and writes nothing):

| value | was | is |
|---|---|---|
| MASQUE port | 443, guessed | 10876, a source constant |
| WireGuard and VK host | the proxy hostname | the A-only name — a dual-stack name resolves to AAAA first and both are IPv4-only |
| VK port and obfs | the compose defaults | the container's environment, which overrides them |
| chain and endpoint node tags | the interface captions | their own config section |

The last one is the subtlest: a client keys its saved selection by node tag, so
renaming ShadowTLS to "ShadowTLS + SS2022" is a new node appearing and the old
one vanishing, taking the user's choice with it.

Hence the rule now written into the defaults test: **"matches the Python bot"
means the one that is running, not the source file.** bot.py read thirty
environment variables, its compose file supplied some, and the container's
environment overrode those again. The authority for anything configurable is
`docker exec vpn-bot env`; for anything hard-coded it was bot.py.
