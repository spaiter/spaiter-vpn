# Bootstrap acceptance suite

Slice 9 of [`../../docs/BOOTSTRAP-DESIGN.md`](../../docs/BOOTSTRAP-DESIGN.md).
Unit tests prove the engine behaves against an injected host. This proves it
behaves against a real one: a real `/etc`, a real firewall, a real Docker
daemon, a real kernel to attach XDP to, and a real WireGuard interface for the
self-test to send through.

Both halves matter. The unit tests can be made to pass by an engine that is
internally consistent and wrong about the machine; this suite can only be made
to pass by one that works.

**Status: passing.** 192 checks on Ubuntu 24.04 in QEMU, 2026-11-05,
including successful and interrupted restart migrations, exact preserve-host
subnet and preserve-existing `seedUsers` migrations, explicit generation
rollback preserving live users and credentials, pruning followed by a
successful rollback from the retained previous generation, credential rotation
of seed and bot users across every copy, the control daemon serving
kernel-identified observers and operators, and the bot claim code.
See "What acceptance found" in the design doc for defects that unit coverage
alone missed.

## Running it

```sh
nix shell nixpkgs#qemu nixpkgs#cloud-utils --command \
  test/acceptance/run-on-qemu-vm.sh --binary ./spaiter-vpn   # NixOS, nothing installed
test/acceptance/run-on-qemu-vm.sh --binary ./spaiter-vpn      # anywhere with qemu + cloud-utils
test/acceptance/run-on-lxd-vm.sh                              # if you already run LXD
```

The QEMU runner is the one that has actually been used. It installs nothing,
creates no host interface and adds no bridge: networking is QEMU's user-mode
stack with ssh forwarded on loopback, the Ubuntu cloud image is cached, and the
per-run disk is a throwaway overlay. Takes about four minutes once the image is
cached; a failing run keeps the guest and copies the evidence out.

A **virtual machine**, not a container, and that is a safety requirement rather
than a preference: the suite's self-test creates a WireGuard interface and the
core attaches an XDP program to a NIC. A container shares the host kernel, so a
bad run could replace the XDP program of a deployment running on the host
itself.

The runner does not initialise LXD. Doing so adds a bridge and a storage pool
to the machine you are sitting on, which is an operator's decision; run
`sudo lxd init` yourself first.

When the image's registry is not reachable from the guest at all — closed to
the internet, or behind credentials the guest does not have — serve the image
from this host's Docker instead:

```sh
test/acceptance/run-on-qemu-vm.sh --binary ./spaiter-vpn \
  --local-image git.example.com:10866/spaiter/spaiter-vpn-core:95c4dcb7
```

A throwaway TLS registry on the guest's loopback answers for that registry
name, so every `compose pull` the suite triggers still talks to a real registry
and the unpullable-image case still fails for the reason it claims. The
registry is the CNCF `distribution` binary pinned by version and release
digest, filled by `push-oci.py` from a `docker save` tarball, so it needs no
Docker in the guest.

### Docker installation

`docker-install-acceptance.sh` proves `bootstrap.installDocker` on a guest that
has no Docker at all:

```sh
test/acceptance/run-on-qemu-vm.sh --no-docker --binary ./spaiter-vpn \
  --suite test/acceptance/docker-install-acceptance.sh \
  --local-image git.example.com:10866/spaiter/spaiter-vpn-core:95c4dcb7
```

It checks that a conflicting runtime (`runc`) and an operator's own Docker
repository each block the plan by name, that one apply then installs exactly
the pinned packages from Docker's repository, records them and brings up a
deployment that passes its self-test, and that a second apply installs nothing.

On a LAN behind a DS-Lite line there is no hairpin NAT, so a guest cannot reach
this site's registry by its public name. Point the name at the reverse proxy's
LAN address instead, which keeps the TLS name intact:

```sh
REGISTRY_HOST=git.example.com REGISTRY_LAN_ADDRESS=192.168.0.2 \
  test/acceptance/run-on-lxd-vm.sh
```

### On some other disposable host

`bootstrap-acceptance.sh` has no LXD in it. Copy it and a static binary to any
throwaway Ubuntu 24.04 or Debian 12/13 machine with Docker Engine, the Compose
plugin and the `wireguard` module, and run it as root:

```sh
SPAITER_VPN_ACCEPTANCE=i-understand-this-host-is-disposable \
  ./bootstrap-acceptance.sh /usr/local/bin/spaiter-vpn
```

**It destroys any deployment on the host it runs on.** It deletes
`/etc/spaiter-vpn` and `/var/lib/spaiter-vpn` between cases, which holds every
private key and every user the bot has provisioned — things a real rollback
must never touch. Hence the environment variable, and hence the two extra
refusals: an existing `config.json` or a running `sing-box` container aborts the
run regardless of what the variable claims.

## What each case proves

| Case | The failure it exists to catch |
|---|---|
| document and plan | A plan that writes something. Planning must not even create the roots it describes, or "read-only" is a claim rather than a property. |
| foreign file refused | Taking ownership of a file somebody else installed. The suite plants a foreign `/etc/logrotate.d/spaiter-vpn` and requires it to come out byte-identical. |
| unhealthy rollback | Recording a generation for a deployment that never answered — which would make the broken state the thing a later rollback restores. Also that the rollback itself finishes, and that the failed transaction's journal is kept. |
| interrupted apply | Resuming from half a deployment. The apply is killed at the dangerous moment — managed files on disk, no receipt naming them — and the next apply must roll that back before installing. |
| clean install | The whole point: `apply` on a bare machine ends with the live BitTorrent self-test passing, all three detectors firing, the control datagram *not* flagged, `reject actions: drop,xdp-block` recorded, and `status` reporting the management endpoint answering. Also the file modes, and that the secrets bundle is not in the directory the core parses as configuration. |
| convergence | Rotating a live deployment's keys. A second apply must succeed, `secrets.json` must be byte-identical, a new generation must be recorded, and the core must still be running. `config.json` is deliberately not held to byte equality — the core owns it and the self-test just added and removed an endpoint through it. |
| restart migration | Treating a bind-mounted config rewrite as if `compose up` reloads it. A log-level migration must plan `restart-migrate`, replace the core container, preserve `secrets.json`, load the new value and avoid the live management apply. |
| interrupted restart recovery | Rolling files back while leaving a replacement container with the new top-level config in memory. The suite kills apply after the container ID changes but before commit; retry must plan `restart-recover`, replace that container again from the restored generation, clear `recreatePending` and preserve credentials. |
| failed convergence | A failed update taking a working server offline. The image is pointed at a reference that cannot be pulled; the previous compose project must come back, the core must be running again, and the credentials untouched. |
| supported migration | Losing credentials while changing a live listener. An AWG port change must apply through the management API, keep `secrets.json` byte-identical, update the live config and leave the core running. |
| unsafe migration refused | Silently reassigning every peer address. An AWG subnet move must be refused with `deployment/subnets/awg-in` named, and neither config nor Compose may change. |
| preserve-host subnet migration | Reissuing keys or compacting addresses during an authorized move. An exact policy must retain every numeric host offset in config, handover, injected bot peers and the external WG-over-VK relay's `passwords.json`; preserve keys and relay-owned fields; touch its reload marker; invalidate subscription cache; adopt runtime state in the receipt; replace the container; and leave the deployment healthy. |
| preserve-existing seedUsers migration | Refusing an unauthorised `seedUsers` edit, then applying an exact `preserve-existing` policy while retaining the earlier subnet policy as an audit record. Existing seed and bot users must keep their keys and addresses while the new seed user receives the next free address in both `config.json` and `secrets.json`. |
| explicit generation rollback | Restoring an older committed intent as a new monotonic generation without rotating or retiring users added since. Both subnet prefixes, bot peer addresses and external WG-over-VK relay addresses must return to their historical values while credentials and relay-owned runtime counters survive. |
| generation pruning | Deleting history without destroying rollback. Preview must delete nothing; `-keep 2 -yes` must leave exactly current and previous, keep the receipt sequence unchanged, and still allow a successful default rollback to the previous generation. |
| credential rotation | Reissuing exactly the selected users. Refusals without a terminal or for an unknown user change nothing; a rotation of a seed and a bot user changes their accounts and peer keys at the same addresses, the seed handover, the bot's peer files, the relay password (dropping the device bound to the old one) and their subscription tokens, and leaves everyone else alone. The live core must serve the new credentials, re-applying the record must rotate nothing, and rolling back past it must not restore retired credentials. |
| control daemon | Typed operations for kernel-identified callers. The socket is group-owned `0660`; an observer reads status but cannot prepare; a uid in the socket group but not in `control.json` is denied; another registry's image is refused; an operator's port change is prepared, committed once, opened in UFW and audited with its transaction. |
| managed control daemon | `manageControl` installs, enables and proves the unit; the allow-list is created root-only and an operator's later edit survives the next apply; turning it off stops the daemon and removes its unit. |
| isolated bot | A real bot against a stand-in Bot API, run as `spaiter-vpn-bot`: its process has that uid and stays up, the core's configuration is not mounted, the management file is `0640` for its group, everything in its data directory and the receipt belongs to it, the relay directory is enterable but not writable by it, it reaches the control daemon as an operator, and switching back to root reverses all of it. |
| per-user MTProto | On a second served core image with MTProto users: every seed user gets their own fake-TLS secret in `config.json` and `secrets.json` while the handed-out shared one survives; a live fake-TLS handshake is recognised as its user and a stranger's as nobody; a user provisioned through the management API is recognised live; retiring the shared secret keeps every user's own. Needs a second `--local-image`. |
| web UI | Run unprivileged as an operator account: no session gets 401, a login link works once, a form without its CSRF token is refused, and a port change is planned and committed through the browser flow, recorded in the audit log under that account. |
| bot claim code | Issued locally and stored only as a hash in a `0600` file. |

UFW is **active** in the guest, brought up by the runner's cloud-init, so the
firewall path runs against a real rule set rather than returning early. Two
things make that safe and meaningful. Port 22 is opened *before* the policy comes
up, because the default deny on incoming would otherwise drop the ssh session
the runner drives the guest through — and that same rule doubles as the one the
suite checks is never touched, since the operator owns it and the deployment
never wants it. `reset_host` resets the firewall between independent cases so
each models a clean host. Within the interrupted-apply case, recovery adopts the
rule whose add-intent was journalled before the killed process opened it.

The fault lever for the unhealthy case is `-health-deadline 2s`, a real
operational flag, rather than a sabotaged config or a test-only hook in the
engine. A deployment that cannot answer within the deadline is exactly the
condition the wait exists to detect.

### Reading a failure

A failing check copies what it needs into `/var/tmp/acceptance-evidence/<case>/`
in the guest — the apply output, the core's own log and a file tree — and the
QEMU runner pulls that out and keeps the guest. The core's log matters
especially: sing-box writes to `log.output`, so `docker logs sing-box` is empty
and any conclusion drawn from the container's stdout is worthless.

Two traps this suite itself fell into, both worth not repeating. Do not start
the apply through a shell helper function when you intend to kill it: `$!` is
then the subshell, so the kill takes out the wrapper while the real apply keeps
running and keeps the lock — which reads exactly like a product that cannot
recover. And do not check Docker in the guest without `sudo`; the unprivileged
user is deliberately not in the `docker` group, so a daemon that is running
perfectly reports as missing.

## Deliberately not covered yet

- **Docker installation**, which `apply` refuses by name; the runner installs
  Docker itself.
- **External reachability.** Nothing inside the machine can prove a port is
  reachable from the internet, and a suite that claimed otherwise would be
  asserting something it cannot see. `spaiter-vpn probe` from another network is
  the check, and it is a manual one.
- **Tier B.** Certificate issuance needs a domain and a DNS credential, so it
  cannot run in a disposable VM without wiring real DNS to a throwaway name.
