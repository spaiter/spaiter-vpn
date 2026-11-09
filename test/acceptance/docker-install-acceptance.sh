#!/usr/bin/env bash
# Acceptance suite for bootstrap.installDocker: a host with no Docker at all
# gets Docker's own packages at the pinned versions and then a working
# deployment, in one apply.
#
# Runs ON a disposable Ubuntu 24.04 or Debian 12/13 host without Docker, as
# root. run-on-qemu-vm.sh provides one:
#
#   test/acceptance/run-on-qemu-vm.sh --no-docker --binary ./spaiter-vpn \
#     --suite test/acceptance/docker-install-acceptance.sh [--local-image REF]
#
# It installs packages on the host and does not remove them: a disposable host
# is the only kind this may run on.

set -u -o pipefail

BINARY=${1:-}
CONFIG_ROOT=/etc/spaiter-vpn
DATA_ROOT=/var/lib/spaiter-vpn
WORK=$(mktemp -d /tmp/docker-install-acceptance.XXXXXX)
PASSED=0
FAILED=0
CURRENT=""

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
die() { red "FATAL: $*"; exit 2; }
case_begin() { CURRENT=$1; printf '\n=== %s\n' "$CURRENT"; }
ok() { PASSED=$((PASSED + 1)); green "  ok: $*"; }
bad() {
	FAILED=$((FAILED + 1))
	red "  FAIL [$CURRENT]: $*"
	mkdir -p /var/tmp/acceptance-evidence
	cp -a "$WORK"/*.log /var/tmp/acceptance-evidence/ 2>/dev/null
	true
}
assert() { local what=$1; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }
bootstrap() { "$BINARY" bootstrap "$@"; }

[ -x "$BINARY" ] || die "give the path to the spaiter-vpn binary"
[ "$(id -u)" = 0 ] || die "run as root"
[ "${SPAITER_VPN_ACCEPTANCE:-}" = "i-understand-this-host-is-disposable" ] ||
	die "refusing to run without SPAITER_VPN_ACCEPTANCE=i-understand-this-host-is-disposable: this suite installs packages"
command -v docker >/dev/null && die "Docker is already installed; this suite needs a host without it"
trap 'rm -rf "$WORK"' EXIT

. /etc/os-release
case "$ID $VERSION_ID" in
"ubuntu 24.04") WANT_ENGINE="5:29.9.3-1~ubuntu.24.04~noble" ;;
"debian 12") WANT_ENGINE="5:29.9.3-1~debian.12~bookworm" ;;
"debian 13") WANT_ENGINE="5:29.9.3-1~debian.13~trixie" ;;
*) die "unsupported host $ID $VERSION_ID" ;;
esac

DESIRED=$WORK/desired.json
bootstrap state -users owner -o "$DESIRED" >"$WORK/state.log" 2>&1 || die "state failed: $(cat "$WORK/state.log")"
python3 - "$DESIRED" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
doc["bootstrap"]["installDocker"] = True
json.dump(doc, open(sys.argv[1], "w"), indent=2)
PY

# ---------------------------------------------------------------------------

case_begin "a conflicting container runtime blocks the plan by name"
DEBIAN_FRONTEND=noninteractive apt-get install -y runc >"$WORK/runc.log" 2>&1 || die "could not install the conflicting fixture: $(tail -5 "$WORK/runc.log")"
bootstrap plan -f "$DESIRED" >"$WORK/conflict-plan.log" 2>&1
assert "the plan is blocked" grep -qi 'blocked' "$WORK/conflict-plan.log"
assert "the blocker names runc" grep -q 'runc' "$WORK/conflict-plan.log"
if bootstrap apply -yes -f "$DESIRED" >"$WORK/conflict-apply.log" 2>&1; then
	bad "apply ran despite a conflicting runtime"
else
	ok "apply refused the conflicting runtime"
fi
assert "nothing was installed" test ! -e /etc/apt/sources.list.d/spaiter-vpn-docker.sources
DEBIAN_FRONTEND=noninteractive apt-get purge -y runc >"$WORK/runc-purge.log" 2>&1 || die "could not remove runc"

case_begin "a Docker repository configured by someone else blocks the plan by name"
echo "deb https://download.docker.com/linux/$ID $VERSION_CODENAME stable" >/etc/apt/sources.list.d/operator-docker.list
bootstrap plan -f "$DESIRED" >"$WORK/foreign-plan.log" 2>&1
assert "the blocker names the operator's source" grep -q 'operator-docker.list' "$WORK/foreign-plan.log"
rm -f /etc/apt/sources.list.d/operator-docker.list

# ---------------------------------------------------------------------------

case_begin "cloud-init installs a verified release, the pinned Docker and the deployment"
if bootstrap plan -f "$DESIRED" >"$WORK/plan.log" 2>&1; then
	ok "the plan succeeded"
else
	bad "the plan failed: $(tail -12 "$WORK/plan.log")"
fi
assert "the plan names the exact engine package" grep -qF "docker-ce=$WANT_ENGINE" "$WORK/plan.log"
# The provider path: a signed release served over HTTP, user-data rendered by
# the binary under test, real cloud-init laying out the files, and the
# first-boot script verifying, installing and applying.
export GNUPGHOME="$WORK/gnupg"
mkdir -m 0700 "$GNUPGHOME"
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-gen-key acceptance-release ed25519 sign 1d
RELEASE_FPR=$(gpg --batch --list-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')
REL_NAME=spaiter-vpn-v0.0.0-acceptance-linux-amd64
mkdir -p "$WORK/release/$REL_NAME"
cp "$BINARY" "$WORK/release/$REL_NAME/spaiter-vpn"
tar -C "$WORK/release" -czf "$WORK/release/$REL_NAME.tar.gz" "$REL_NAME"
rm -rf "$WORK/release/$REL_NAME"
(cd "$WORK/release" && sha256sum -- *.tar.gz >SHA256SUMS)
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --armor --detach-sign -o "$WORK/release/SHA256SUMS.asc" "$WORK/release/SHA256SUMS"
gpg --batch --armor --export "$RELEASE_FPR" >"$WORK/release-key.asc"
unset GNUPGHOME
systemd-run --unit acceptance-release python3 -m http.server --bind 127.0.0.1 18090 --directory "$WORK/release" >/dev/null
for _ in $(seq 1 20); do curl -fsS -o /dev/null http://127.0.0.1:18090/SHA256SUMS && break; sleep 1; done
if bootstrap cloud-init -f "$DESIRED" -release http://127.0.0.1:18090 -version v0.0.0-acceptance \
	-signing-key "$WORK/release-key.asc" -fingerprint "$RELEASE_FPR" -o "$WORK/user-data" >"$WORK/cloud-init-render.log" 2>&1; then
	ok "user-data rendered"
else
	bad "cloud-init rendering failed: $(cat "$WORK/cloud-init-render.log")"
fi
assert "real cloud-init accepts the user-data's schema" cloud-init schema --config-file "$WORK/user-data"
cloud-init single --name write_files --frequency always --file "$WORK/user-data" >"$WORK/cloud-init-files.log" 2>&1
assert "cloud-init laid out the first-boot files root-only" test "$(stat -c %a /run/spaiter-vpn-firstboot/firstboot.sh)" = 700
rm -f /usr/local/bin/spaiter-vpn
if sh /run/spaiter-vpn-firstboot/firstboot.sh; then
	ok "first boot verified the release and applied the deployment"
else
	bad "first boot failed: $(tail -30 /var/log/spaiter-vpn-firstboot.log)"
fi
cp /var/log/spaiter-vpn-firstboot.log "$WORK/apply.log"
assert "the installed binary is the release's" cmp -s "$BINARY" /usr/local/bin/spaiter-vpn
assert "the first-boot staging, credentials included, was removed" test ! -e /run/spaiter-vpn-firstboot
systemctl stop acceptance-release >/dev/null 2>&1
assert "the engine reports the pinned version" test "$(docker version --format '{{.Server.Version}}' 2>/dev/null)" = 29.9.3
assert "compose reports the pinned version" test "$(docker compose version --short 2>/dev/null | sed 's/^v//')" = 5.7.0
assert "dpkg holds exactly the pinned engine" test "$(dpkg-query -W -f '${Version}' docker-ce 2>/dev/null)" = "$WANT_ENGINE"
assert "the repository is restricted to the embedded key" grep -q 'Signed-By: /etc/apt/keyrings/spaiter-vpn-docker.asc' /etc/apt/sources.list.d/spaiter-vpn-docker.sources
assert "the installation is recorded" python3 - "$DATA_ROOT/bootstrap/platform.json" "$WANT_ENGINE" <<'PY'
import json, sys
record = json.load(open(sys.argv[1]))["docker"]
raise SystemExit(0 if record["packages"]["docker-ce"] == sys.argv[2] and record["engineVersion"] == "29.9.3" else 1)
PY
assert "the self-test passed on the new engine" grep -q 'self-test: passed' "$WORK/apply.log"
assert "the core is running" sh -c "docker ps --format '{{.Names}}' | grep -qx sing-box"
bootstrap status >"$WORK/status.log" 2>&1
assert "status reports the installed packages" grep -qF "docker-ce=$WANT_ENGINE" "$WORK/status.log"

case_begin "a second apply converges without installing again"
# By action id in the machine-readable plan: the work directory's own name
# contains "docker-install", so grepping the text plan matches its header.
bootstrap plan -f "$DESIRED" -json >"$WORK/plan2.json" 2>&1
assert "the second plan installs nothing" python3 - "$WORK/plan2.json" <<'PY'
import json, sys
actions = json.load(open(sys.argv[1]))["actions"]
raise SystemExit(1 if any(a["id"] in ("docker-install", "docker-compose-install") for a in actions) else 0)
PY
if bootstrap apply -yes -f "$DESIRED" >"$WORK/apply2.log" 2>&1; then
	ok "the second apply converged"
else
	bad "the second apply failed: $(tail -16 "$WORK/apply2.log")"
fi

printf '\n'
if [ "$FAILED" -eq 0 ]; then
	green "PASS — $PASSED checks"
	exit 0
fi
red "FAIL — $FAILED of $((PASSED + FAILED)) checks failed"
exit 1
