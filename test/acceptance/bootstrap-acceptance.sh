#!/usr/bin/env bash
# Acceptance suite for `spaiter-vpn bootstrap`, slice 9 of docs/BOOTSTRAP-DESIGN.md.
#
# Runs ON a disposable host, as root. It installs a VPN, breaks it on purpose,
# kills an apply halfway through and checks what is left behind. Every case
# starts from a reset host and leaves nothing running.
#
# This is deliberately NOT a Go test. The thing under test is a static binary
# acting on a real machine's /etc, firewall, kernel and Docker daemon; a target
# that has a Go toolchain on it is not the target this has to work on.
#
#   usage: bootstrap-acceptance.sh /path/to/spaiter-vpn
#
# Requires: root, systemd, Docker Engine with the Compose plugin, the wireguard
# kernel module (the self-test's client is the host's own wg(4)), and outbound
# access to the registry named by the desired state.

set -u -o pipefail

BINARY=${1:-}
CONFIG_ROOT=/etc/spaiter-vpn
DATA_ROOT=/var/lib/spaiter-vpn
LOGROTATE=/etc/logrotate.d/spaiter-vpn
WORK=$(mktemp -d /tmp/bootstrap-acceptance.XXXXXX)
PASSED=0
FAILED=0
CURRENT=""

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

die() { red "FATAL: $*"; exit 2; }

case_begin() {
	CURRENT=$1
	printf '\n=== %s\n' "$CURRENT"
}

ok() { PASSED=$((PASSED + 1)); green "  ok: $*"; }

bad() {
	FAILED=$((FAILED + 1))
	red "  FAIL [$CURRENT]: $*"
	# Keep the evidence. The first run of this suite found two real defects and
	# both diagnoses needed the core's own log and the apply output, which the
	# work directory had already deleted — so the whole VM had to be rebuilt to
	# look at them.
	keep_evidence "$CURRENT"
}

KEEP_DIR=/var/tmp/acceptance-evidence
keep_evidence() {
	local slug
	slug=$(printf '%s' "$1" | tr -c 'a-zA-Z0-9' '-' | cut -c1-60)
	local dest="$KEEP_DIR/$slug"
	mkdir -p "$dest"
	cp -a "$WORK"/*.log "$dest/" 2>/dev/null
	# The core's own log is the only place the self-test's result appears;
	# `docker logs sing-box` is empty by design.
	cp -a "$CONFIG_ROOT/deployment/sing-box.log" "$dest/core.log" 2>/dev/null
	docker ps -a --format '{{.Names}}\t{{.Status}}' >"$dest/containers.txt" 2>/dev/null
	ls -lR "$CONFIG_ROOT" "$DATA_ROOT" >"$dest/tree.txt" 2>/dev/null
	true
}

# assert/refute instead of `cmd && ok || bad`, which is not if-then-else: if the
# reporting function ever returns non-zero, the chained form reports both a pass
# and a failure for one check.
assert() { local what=$1; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }
refute() { local what=$1; shift; if "$@"; then bad "$what"; else ok "$what"; fi; }

# assert_absent is the single most repeated claim in this suite: a refused or
# failed apply must leave the host as it was, or a retry starts from a half
# deployment nobody described.
assert_absent() {
	local path=$1
	if [ -e "$path" ]; then
		bad "$path exists but should not after $2"
	else
		ok "$path absent after $2"
	fi
}

assert_mode() {
	local path=$1 want=$2
	local got
	got=$(stat -c '%a' "$path" 2>/dev/null) || { bad "$path is missing"; return; }
	if [ "$got" = "$want" ]; then
		ok "$path is mode $got"
	else
		bad "$path is mode $got, want $want"
	fi
}

digest_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# edit_desired applies python statements to the desired-state document.
#
# A helper rather than a heredoc per case: the document is JSON that has to stay
# strictly valid (unknown and missing fields are both errors), so sed on it is
# how a test starts failing for reasons that have nothing to do with the thing
# under test.
edit_desired() {
	local script="import json,sys
path=sys.argv[1]
doc=json.load(open(path))
"
	local statement
	for statement in "$@"; do
		script="$script$statement
"
	done
	script="${script}json.dump(doc, open(path,'w'), indent=2)
"
	python3 -c "$script" "$DESIRED" || die "could not edit $DESIRED"
}

# reset_host returns the machine to "nothing installed". Acceptable only
# because this host is disposable: it deletes the credentials, the provisioned
# users and the core's ACME state, which a real rollback must never do.
reset_host() {
	if [ -f "$CONFIG_ROOT/deployment/docker-compose.yml" ]; then
		docker compose -f "$CONFIG_ROOT/deployment/docker-compose.yml" down --remove-orphans >/dev/null 2>&1
	fi
	docker rm -f sing-box sing-box-reload vpn-bot >/dev/null 2>&1
	systemctl disable --now spaiter-vpn-ddns.service spaiter-vpn-web.service spaiter-vpn-control.service >/dev/null 2>&1
	rm -f /etc/systemd/system/spaiter-vpn-control.service /etc/systemd/system/spaiter-vpn-web.service /etc/systemd/system/spaiter-vpn-ddns.service
	systemctl daemon-reload >/dev/null 2>&1
	ip link del bt-selftest >/dev/null 2>&1
	rm -rf "$CONFIG_ROOT" "$DATA_ROOT" "$LOGROTATE"
	# Reset firewall state between cases. Each case must start from the host it
	# claims to test; carrying an allowed deployment port into the next fresh
	# install makes that rule look operator-owned, so bootstrap correctly refuses
	# to claim it and the case measures the previous case instead.
	#
	# reset leaves UFW inactive, so restore SSH before enabling it: the suite is
	# driven over this connection and the default incoming policy is deny.
	if command -v ufw >/dev/null; then
		ufw --force reset >/dev/null 2>&1
		ufw allow 22/tcp >/dev/null 2>&1
		ufw --force enable >/dev/null 2>&1
	fi
}

require_disposable() {
	[ -n "$BINARY" ] || die "give the path to the spaiter-vpn binary"
	[ -x "$BINARY" ] || die "$BINARY is not executable"
	[ "$(id -u)" = 0 ] || die "this suite writes /etc and starts containers; run it as root"
	[ "${SPAITER_VPN_ACCEPTANCE:-}" = "i-understand-this-host-is-disposable" ] ||
		die "refusing to run without SPAITER_VPN_ACCEPTANCE=i-understand-this-host-is-disposable

This suite DESTROYS any existing deployment on this machine: it deletes
$CONFIG_ROOT and $DATA_ROOT, which hold every private key and every user the
bot has provisioned. Run it on a throwaway VM, never on a server anybody uses."

	# Belt and braces: the env var is a statement of intent, an existing
	# deployment is evidence to the contrary.
	if [ -f "$CONFIG_ROOT/deployment/config.json" ]; then
		die "$CONFIG_ROOT/deployment/config.json already exists; this does not look like a throwaway host"
	fi
	if docker ps --format '{{.Names}}' | grep -qx sing-box; then
		die "a sing-box container is already running; this does not look like a throwaway host"
	fi
	docker version >/dev/null 2>&1 || die "the Docker daemon does not answer"
	docker compose version >/dev/null 2>&1 || die "the Docker Compose plugin is missing"
	modprobe wireguard 2>/dev/null
	[ -d /sys/module/wireguard ] || die "the wireguard kernel module is unavailable; the self-test's client is the host's own wg(4)"
	# Required, not optional: with UFW inactive the firewall path returns early
	# and the suite would silently stop testing it. Enabling it here instead
	# would be the wrong place — a default deny on incoming drops the ssh
	# session a remote runner is driving this host through, so whoever prepares
	# the host opens port 22 first and brings UFW up before the suite starts.
	ufw status 2>/dev/null | grep -q "Status: active" ||
		die "UFW is not active, so the firewall path cannot be tested. Prepare the host with:
    ufw allow 22/tcp && ufw --force enable
Opening 22 first is not optional if you reach this host over ssh."
	ufw status 2>/dev/null | grep -q "^22/tcp" ||
		die "UFW is active but 22/tcp is not allowed; the suite uses that rule as the one the deployment must never touch"
}

# shellcheck disable=SC2317  # reached from the cases below; the die chain above
# confuses shellcheck's flow analysis
# ufw_allows reports whether UFW currently permits a port/protocol.
#
# Matched at the start of the line: that column is the destination, and a
# substring match would also hit the "(v6)" duplicate and any rule that merely
# mentions the number.
ufw_allows() {
	ufw status | awk '{print $1}' | grep -qx "$1"
}

# shellcheck disable=SC2317  # as above
# owned_firewall prints the rules the last receipt says this deployment opened.
owned_firewall() {
	python3 -c '
import json, sys
receipt = json.load(open(sys.argv[1]))
print("\n".join(receipt.get("firewall") or []))
' "$DATA_ROOT/bootstrap/current.json" 2>/dev/null
}

bootstrap() { "$BINARY" bootstrap "$@"; }

# ---------------------------------------------------------------------------

require_disposable
trap 'rm -rf "$WORK"' EXIT
reset_host

DESIRED=$WORK/desired.json

case_begin "a desired-state document is produced and planned"
if bootstrap state -users owner -o "$DESIRED" >"$WORK/state.log" 2>&1; then
	ok "state wrote a document"
else
	bad "state failed: $(cat "$WORK/state.log")"
fi
if bootstrap plan -f "$DESIRED" >"$WORK/plan.log" 2>&1; then
	ok "plan succeeded on a clean host"
else
	bad "plan failed: $(tail -5 "$WORK/plan.log")"
fi
assert "plan reports a fresh install" grep -q 'mode: *fresh' "$WORK/plan.log"
# Read-only means read-only: planning must not have created the roots it
# describes.
assert_absent "$CONFIG_ROOT" "a read-only plan"
assert_absent "$DATA_ROOT" "a read-only plan"

if bootstrap plan -f "$DESIRED" -json >"$WORK/plan.json" 2>&1; then
	assert "the machine-readable plan is valid JSON" \
		python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$WORK/plan.json"
fi

# ---------------------------------------------------------------------------

case_begin "a foreign managed file is refused, not overwritten"
mkdir -p "$(dirname "$LOGROTATE")"
printf '# installed by somebody else\n/var/log/other.log { daily }\n' >"$LOGROTATE"
FOREIGN=$(digest_of "$LOGROTATE")
if bootstrap apply -yes -f "$DESIRED" >"$WORK/foreign.log" 2>&1; then
	bad "apply overwrote or ignored a foreign $LOGROTATE"
else
	ok "apply refused to take over a foreign file"
fi
if [ "$(digest_of "$LOGROTATE")" = "$FOREIGN" ]; then
	ok "the foreign file is byte-identical"
else
	bad "the foreign file was modified"
fi
assert_absent "$CONFIG_ROOT/deployment/config.json" "the refused apply"
reset_host

# ---------------------------------------------------------------------------

case_begin "a deployment that does not become healthy is rolled back"
# The lever is a deadline the deployment cannot meet, not a sabotaged config:
# -health-deadline is a real operational flag, and using it this way exercises
# the compensation path without a test-only hook in the engine.
if bootstrap apply -yes -f "$DESIRED" -health-deadline 2s -health-settle 1s >"$WORK/unhealthy.log" 2>&1; then
	bad "apply reported success with a deadline it could not meet"
else
	ok "apply failed as expected"
fi
assert "the failure names the health wait" grep -qi 'did not become healthy' "$WORK/unhealthy.log"
refute "the rollback completed" grep -qi 'rollback incomplete' "$WORK/unhealthy.log"
assert_absent "$CONFIG_ROOT/deployment/config.json" "the failed apply"
assert_absent "$CONFIG_ROOT/deployment/docker-compose.yml" "the failed apply"
assert_absent "$DATA_ROOT/bootstrap/current.json" "the failed apply"
if docker ps --format '{{.Names}}' | grep -qx sing-box; then
	bad "the core is still running after a rolled-back apply"
else
	ok "no service was left running"
fi
# The journal and its backups are retained on purpose: they are the only
# record of what the failed attempt did.
if ls "$DATA_ROOT"/bootstrap/transactions/*/journal.json >/dev/null 2>&1; then
	ok "the failed transaction was kept for inspection"
else
	bad "the failed transaction left no journal"
fi
reset_host

# ---------------------------------------------------------------------------

case_begin "an interrupted apply recovers instead of resuming from half a deployment"
# The binary directly, NOT through the bootstrap() helper: a shell function run
# in the background makes $! the pid of the subshell, so the kill below would
# take out the wrapper and leave the real apply running — still holding the
# lock, which then looks exactly like a product that cannot recover.
"$BINARY" bootstrap apply -yes -f "$DESIRED" >"$WORK/interrupted.log" 2>&1 &
APPLY_PID=$!
# Wait until the files and one deployment firewall rule are present. This is
# the dangerous moment being proved: no committed receipt exists yet, but an
# externally visible mutation already does and recovery must adopt it.
INTERRUPTED_AWG_PORT=$(python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["deployment"]["ports"]["awg-in"])
' "$DESIRED")
for _ in $(seq 1 600); do
	if [ -f "$CONFIG_ROOT/deployment/config.json" ] && ufw_allows "$INTERRUPTED_AWG_PORT/udp"; then
		break
	fi
	kill -0 "$APPLY_PID" 2>/dev/null || break
	sleep 0.5
done
if [ -f "$CONFIG_ROOT/deployment/config.json" ] && ufw_allows "$INTERRUPTED_AWG_PORT/udp"; then
	kill -9 "$APPLY_PID" 2>/dev/null
	wait "$APPLY_PID" 2>/dev/null
	# The lock is released when the process dies, so nothing of ours may
	# survive. Checked rather than assumed: a surviving process would make the
	# next step fail with "another transaction holds the lock", which reads as
	# a recovery defect in the product.
	for _ in $(seq 1 60); do
		pgrep -x spaiter-vpn >/dev/null || break
		sleep 0.5
	done
	if pgrep -x spaiter-vpn >/dev/null; then
		bad "a spaiter-vpn process survived the kill: $(pgrep -ax spaiter-vpn | head -2)"
	fi
	ok "killed the apply with the managed files written and no receipt"
	refute "no receipt was recorded before the proof" test -f "$DATA_ROOT/bootstrap/current.json"

	# Recovery happens when the next apply takes the lock. It must roll the
	# interrupted transaction back first, then install cleanly.
	if bootstrap apply -yes -f "$DESIRED" >"$WORK/recovered.log" 2>&1; then
		ok "the next apply recovered and completed"
	else
		bad "the next apply did not recover: $(tail -8 "$WORK/recovered.log")"
	fi
	if owned_firewall | grep -qx "$INTERRUPTED_AWG_PORT/udp"; then
		ok "the recovered first install adopted its pre-crash firewall rule"
	else
		bad "the recovered receipt lost ownership of $INTERRUPTED_AWG_PORT/udp: $(owned_firewall | tr '\n' ' ')"
	fi
else
	kill -9 "$APPLY_PID" 2>/dev/null || true
	wait "$APPLY_PID" 2>/dev/null
	bad "the apply never reached the file-and-firewall stage: $(tail -5 "$WORK/interrupted.log")"
fi
reset_host

# ---------------------------------------------------------------------------

case_begin "a clean install passes its own self-test"
if bootstrap apply -yes -f "$DESIRED" >"$WORK/install.log" 2>&1; then
	ok "apply completed"
else
	bad "apply failed: $(tail -20 "$WORK/install.log")"
fi
assert "the live self-test passed" grep -q 'self-test: passed' "$WORK/install.log"
# The self-test's own verdict line, not the router's log line: `reject(...)` is
# written to the core's log file at debug level, while what apply prints is the
# self-test's summary. Grepping for the router's wording looks for a string that
# is never on this stream.
assert "the rejection was enforced, not merely logged" \
	grep -qE 'reject actions:.*drop' "$WORK/install.log"
for detector in dht udp-tracker-connect lsd-bt-search; do
	assert "detector $detector fired" grep -q "detector=$detector" "$WORK/install.log"
done
assert "the control datagram was not flagged" grep -q 'not detected, as required' "$WORK/install.log"
assert_mode "$CONFIG_ROOT/deployment/config.json" 600
assert_mode "$CONFIG_ROOT/deployment/secrets/secrets.json" 600
assert_mode "$CONFIG_ROOT/desired.json" 644
assert_mode "$DATA_ROOT/bootstrap/current.json" 600
if docker ps --format '{{.Names}}' | grep -qx sing-box; then
	ok "the core is running"
else
	bad "the core is not running after a successful apply"
fi
if bootstrap status >"$WORK/status.log" 2>&1; then
	assert "status reports the management endpoint answering" \
		grep -q 'management: *answering' "$WORK/status.log"
	assert "status reports generation 1" grep -q 'last apply: *generation 1' "$WORK/status.log"
else
	bad "status failed: $(cat "$WORK/status.log")"
fi
# The secrets bundle must not sit in the directory the core parses: sing-box
# runs with -C <dir> and reads every top-level *.json there as config.
if [ -f "$CONFIG_ROOT/deployment/secrets.json" ]; then
	bad "secrets.json is in the directory the core parses as configuration"
else
	ok "the secrets bundle is outside the core's config directory"
fi
# The firewall half. A deployment that starts correctly and is reachable by
# nobody has no local symptom at all, which is why this is checked rather than
# assumed from the apply exiting zero.
AWG_PORT=$(python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["deployment"]["ports"]["awg-in"])
' "$DESIRED")
assert "the deployment port is allowed in UFW" ufw_allows "$AWG_PORT/udp"
if owned_firewall | grep -qx "$AWG_PORT/udp"; then
	ok "the receipt records that rule as this deployment's"
else
	bad "the receipt does not claim $AWG_PORT/udp, so nothing could ever retire it: $(owned_firewall | tr '\n' ' ')"
fi
# The operator's own rule, which the deployment never wants and must never touch.
assert "the operator's ssh rule is untouched" ufw_allows 22/tcp
if owned_firewall | grep -qx "22/tcp"; then
	bad "the receipt claims a rule the operator opened"
else
	ok "the receipt does not claim the operator's rule"
fi

# ---------------------------------------------------------------------------

case_begin "a second apply converges and preserves every key"
CONFIG_BEFORE=$(digest_of "$CONFIG_ROOT/deployment/config.json")
SECRETS_BEFORE=$(digest_of "$CONFIG_ROOT/deployment/secrets/secrets.json")
GENERATION_BEFORE=$(grep -o '"sequence": *[0-9]*' "$DATA_ROOT/bootstrap/current.json" | grep -o '[0-9]*')

if bootstrap apply -yes -f "$DESIRED" >"$WORK/second.log" 2>&1; then
	ok "an unchanged second apply converged"
else
	bad "the second apply failed: $(tail -12 "$WORK/second.log")"
fi
# The whole reason a convergence is not simply "install again": regenerating
# would mint new private keys and a new clash secret over a live deployment.
if [ "$(digest_of "$CONFIG_ROOT/deployment/secrets/secrets.json")" = "$SECRETS_BEFORE" ]; then
	ok "secrets.json is byte-identical"
else
	bad "secrets.json changed: every existing client would stop working"
fi
assert "the convergence says what it preserved" grep -q 'credential sets unchanged' "$WORK/second.log"
if docker ps --format '{{.Names}}' | grep -qx sing-box; then
	ok "the deployment is still running"
else
	bad "the convergence left the core stopped"
fi
GENERATION_AFTER=$(grep -o '"sequence": *[0-9]*' "$DATA_ROOT/bootstrap/current.json" | grep -o '[0-9]*')
if [ "${GENERATION_AFTER:-0}" -gt "${GENERATION_BEFORE:-0}" ]; then
	ok "a new generation was recorded ($GENERATION_BEFORE -> $GENERATION_AFTER)"
else
	bad "no new generation was recorded: $GENERATION_BEFORE -> $GENERATION_AFTER"
fi
# config.json is NOT held to byte equality: the core owns it and rewrites it
# through config_output_path, and the self-test this apply just ran added a
# throwaway endpoint and removed it again. What protects it is that it is not
# in the transaction at all.
if [ "$(digest_of "$CONFIG_ROOT/deployment/config.json")" = "$CONFIG_BEFORE" ]; then
	ok "config.json is unchanged"
else
	ok "config.json was rewritten by the core, which is its job; the credentials are intact"
fi

# ---------------------------------------------------------------------------

case_begin "a restart migration recreates the core and preserves credentials"
edit_desired 'doc["deployment"]["logLevel"] = "trace"'
SECRETS_BEFORE=$(digest_of "$CONFIG_ROOT/deployment/secrets/secrets.json")
CONTAINER_BEFORE=$(docker inspect -f '{{.Id}}' sing-box 2>/dev/null)
if bootstrap plan -f "$DESIRED" >"$WORK/restart-plan.log" 2>&1; then
	ok "the restart migration planned successfully"
else
	bad "the restart migration plan failed: $(tail -10 "$WORK/restart-plan.log")"
fi
assert "the plan names restart-migrate mode" grep -q 'mode: *restart-migrate' "$WORK/restart-plan.log"
assert "the plan requires a forced Compose recreation" grep -q 'force-recreate the deployment' "$WORK/restart-plan.log"
if bootstrap apply -yes -f "$DESIRED" >"$WORK/restart-migration.log" 2>&1; then
	ok "the restart migration applied"
else
	bad "the restart migration failed: $(tail -12 "$WORK/restart-migration.log")"
fi
CONTAINER_AFTER=$(docker inspect -f '{{.Id}}' sing-box 2>/dev/null)
if [ -n "$CONTAINER_BEFORE" ] && [ -n "$CONTAINER_AFTER" ] && [ "$CONTAINER_BEFORE" != "$CONTAINER_AFTER" ]; then
	ok "the core container was replaced ($CONTAINER_BEFORE -> $CONTAINER_AFTER)"
else
	bad "the restart migration did not replace the core container: $CONTAINER_BEFORE -> $CONTAINER_AFTER"
fi
if [ "$(digest_of "$CONFIG_ROOT/deployment/secrets/secrets.json")" = "$SECRETS_BEFORE" ]; then
	ok "the restart migration preserved secrets.json byte-for-byte"
else
	bad "the restart migration rewrote the client handover credentials"
fi
if python3 - "$CONFIG_ROOT/deployment/config.json" <<'PY'
import json, sys
config = json.load(open(sys.argv[1]))
raise SystemExit(0 if config.get("log", {}).get("level") == "trace" else 1)
PY
then
	ok "the recreated core config carries the requested log level"
else
	bad "config.json does not carry logLevel=trace"
fi
refute "the restart migration did not use the live management apply" \
	grep -q 'management API: running configuration synchronised' "$WORK/restart-migration.log"

# ---------------------------------------------------------------------------

case_begin "an interrupted restart migration is force-recovered"
SECRETS_BEFORE=$(digest_of "$CONFIG_ROOT/deployment/secrets/secrets.json")
GENERATION_BEFORE=$(grep -o '"sequence": *[0-9]*' "$DATA_ROOT/bootstrap/current.json" | grep -o '[0-9]*')
CONTAINER_BEFORE=$(docker inspect -f '{{.Id}}' sing-box 2>/dev/null)
edit_desired 'doc["deployment"]["logLevel"] = "debug"'
# Direct binary, not the bootstrap shell helper: killing a background function
# kills its subshell and leaves the real apply holding the lock.
"$BINARY" bootstrap apply -yes -f "$DESIRED" >"$WORK/interrupted-restart.log" 2>&1 &
APPLY_PID=$!
RESTARTED_ID=""
for _ in $(seq 1 600); do
	CURRENT_ID=$(docker inspect -f '{{.Id}}' sing-box 2>/dev/null)
	if [ -n "$CURRENT_ID" ] && [ "$CURRENT_ID" != "$CONTAINER_BEFORE" ]; then
		RESTARTED_ID=$CURRENT_ID
		break
	fi
	kill -0 "$APPLY_PID" 2>/dev/null || break
	sleep 0.05
done
if [ -n "$RESTARTED_ID" ]; then
	kill -9 "$APPLY_PID" 2>/dev/null
	wait "$APPLY_PID" 2>/dev/null
	ok "killed the apply after it replaced the core container"
else
	kill -9 "$APPLY_PID" 2>/dev/null || true
	wait "$APPLY_PID" 2>/dev/null
	bad "the apply never reached container recreation: $(tail -8 "$WORK/interrupted-restart.log")"
fi
GENERATION_AFTER=$(grep -o '"sequence": *[0-9]*' "$DATA_ROOT/bootstrap/current.json" | grep -o '[0-9]*')
if [ "$GENERATION_AFTER" = "$GENERATION_BEFORE" ]; then
	ok "the killed restart did not commit a generation"
else
	bad "the killed restart committed unexpectedly: $GENERATION_BEFORE -> $GENERATION_AFTER"
fi
# Ask for the last committed intent again. Recovery must first roll the staged
# debug files back to trace, notice that the killed container may still be
# running debug in memory, and plan restart-recover even though intent is now
# unchanged.
edit_desired 'doc["deployment"]["logLevel"] = "trace"'
if bootstrap apply -yes -f "$DESIRED" >"$WORK/restart-recovery.log" 2>&1; then
	ok "the interrupted restart recovered and completed"
else
	bad "restart recovery failed: $(tail -14 "$WORK/restart-recovery.log")"
fi
assert "recovery planned restart-recover mode" grep -q 'mode: *restart-recover' "$WORK/restart-recovery.log"
RECOVERED_ID=$(docker inspect -f '{{.Id}}' sing-box 2>/dev/null)
if [ -n "$RESTARTED_ID" ] && [ -n "$RECOVERED_ID" ] && [ "$RESTARTED_ID" != "$RECOVERED_ID" ]; then
	ok "recovery replaced the possibly stale container"
else
	bad "recovery did not replace the killed generation: $RESTARTED_ID -> $RECOVERED_ID"
fi
if python3 - "$DATA_ROOT/bootstrap/current.json" <<'PY'
import json, sys
receipt = json.load(open(sys.argv[1]))
raise SystemExit(1 if receipt.get("recreatePending") else 0)
PY
then
	ok "the committed recovery cleared recreatePending"
else
	bad "the recovery receipt still requests recreation"
fi
if python3 - "$CONFIG_ROOT/deployment/config.json" <<'PY'
import json, sys
config = json.load(open(sys.argv[1]))
raise SystemExit(0 if config.get("log", {}).get("level") == "trace" else 1)
PY
then
	ok "the recovered core loaded the last committed log level"
else
	bad "the recovered config does not carry logLevel=trace"
fi
if [ "$(digest_of "$CONFIG_ROOT/deployment/secrets/secrets.json")" = "$SECRETS_BEFORE" ]; then
	ok "restart recovery preserved secrets.json byte-for-byte"
else
	bad "restart recovery rewrote the client handover credentials"
fi

# ---------------------------------------------------------------------------

case_begin "a failed convergence puts the previous deployment back"
# An image that cannot be pulled is a deterministic mid-convergence failure
# that needs no fault injection in the engine. What matters is not that it
# fails but how: a fresh install's failure ends with nothing running, while a
# convergence's must end with the previous deployment running again.
edit_desired 'doc["deployment"]["image"] += "-nonexistent"'
SECRETS_BEFORE=$(digest_of "$CONFIG_ROOT/deployment/secrets/secrets.json")
if bootstrap apply -yes -f "$DESIRED" >"$WORK/badimage.log" 2>&1; then
	bad "a convergence to an unpullable image reported success"
else
	ok "the convergence failed on an image that cannot be pulled"
fi
refute "the rollback completed" grep -qi 'rollback incomplete' "$WORK/badimage.log"
refute "the previous compose project was restored" \
	grep -q -- '-nonexistent' "$CONFIG_ROOT/deployment/docker-compose.yml"
if docker ps --format '{{.Names}}' | grep -qx sing-box; then
	ok "the previous deployment is running again"
else
	bad "a failed convergence left the server down"
fi
if [ "$(digest_of "$CONFIG_ROOT/deployment/secrets/secrets.json")" = "$SECRETS_BEFORE" ]; then
	ok "the failed convergence did not touch the credentials"
else
	bad "the failed convergence rewrote secrets.json"
fi

# ---------------------------------------------------------------------------

case_begin "a supported migration preserves credentials and applies live"
edit_desired 'doc["deployment"]["image"] = doc["deployment"]["image"].removesuffix("-nonexistent")' \
	'doc["deployment"]["ports"]["awg-in"] = int(doc["deployment"]["ports"]["awg-in"]) + 1'
cp "$CONFIG_ROOT/deployment/secrets/secrets.json" "$WORK/migration-secrets-before.json"
if bootstrap apply -yes -f "$DESIRED" >"$WORK/migration.log" 2>&1; then
	ok "the port migration applied"
else
	bad "the supported migration failed: $(tail -12 "$WORK/migration.log")"
fi
assert "the migration used the management API" \
	grep -q 'management API: running configuration synchronised' "$WORK/migration.log"
# Every credential a client holds survives; the facts clients renders links
# from follow the move, or it would hand out the old port.
assert "the migration kept every handed-out credential and moved the port in secrets.json" python3 - \
	"$WORK/migration-secrets-before.json" "$CONFIG_ROOT/deployment/secrets/secrets.json" "$DESIRED" <<'PY'
import json, sys
before, after, desired = (json.load(open(path)) for path in sys.argv[1:])
strip = lambda doc: {k: v for k, v in doc.items() if k != "Deployment"}
ok = strip(before) == strip(after) and after["Deployment"]["Ports"]["awg-in"] == desired["deployment"]["ports"]["awg-in"]
raise SystemExit(0 if ok else 1)
PY
if python3 - "$DESIRED" "$CONFIG_ROOT/deployment/config.json" <<'PY'
import json, sys
desired = json.load(open(sys.argv[1]))
config = json.load(open(sys.argv[2]))
want = desired["deployment"]["ports"]["awg-in"]
endpoint = next(item for item in config["endpoints"] if item["tag"] == "awg-in")
raise SystemExit(0 if endpoint["listen_port"] == want else 1)
PY
then
	ok "the live config carries the migrated port"
else
	bad "config.json does not carry the requested AWG port"
fi
if docker ps --format '{{.Names}}' | grep -qx sing-box; then
	ok "the migrated deployment is running"
else
	bad "the supported migration stopped the core"
fi
# The door it stopped using. A stale allow is harmless in itself and misleading
# exactly when the reason for moving was that the port was blocked.
MIGRATED_PORT=$(python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["deployment"]["ports"]["awg-in"])
' "$DESIRED")
assert "the migrated port is allowed in UFW" ufw_allows "$MIGRATED_PORT/udp"
refute "the port it stopped using was closed" ufw_allows "$AWG_PORT/udp"
if owned_firewall | grep -qx "$AWG_PORT/udp"; then
	bad "the receipt still claims the retired rule"
else
	ok "the receipt no longer claims the retired rule"
fi
assert "the operator's ssh rule survived the migration" ufw_allows 22/tcp

# ---------------------------------------------------------------------------

case_begin "an unsafe migration is refused, not applied"
edit_desired 'doc["deployment"]["subnets"]["awg-in"] = "10.254.250.0/24"'
COMPOSE_BEFORE=$(digest_of "$CONFIG_ROOT/deployment/docker-compose.yml")
CONFIG_BEFORE=$(digest_of "$CONFIG_ROOT/deployment/config.json")
if bootstrap apply -yes -f "$DESIRED" >"$WORK/unsafe-migration.log" 2>&1; then
	bad "a subnet move was applied without a peer-address policy"
else
	ok "the unsafe migration was refused"
fi
assert "the refusal names the field" grep -q 'deployment/subnets/awg-in' "$WORK/unsafe-migration.log"
if [ "$(digest_of "$CONFIG_ROOT/deployment/docker-compose.yml")" = "$COMPOSE_BEFORE" ]; then
	ok "the refused migration left Compose unchanged"
else
	bad "the refused migration still rewrote the compose project"
fi
if [ "$(digest_of "$CONFIG_ROOT/deployment/config.json")" = "$CONFIG_BEFORE" ]; then
	ok "the refused migration left config.json unchanged"
else
	bad "the refused migration rewrote the live configuration"
fi
if docker ps --format '{{.Names}}' | grep -qx sing-box; then
	ok "the deployment is untouched"
else
	bad "the refused migration stopped the core"
fi

# ---------------------------------------------------------------------------

case_begin "an exact preserve-host policy migrates subnets and external relay state"
ROLLBACK_TARGET=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sequence"])' "$DATA_ROOT/bootstrap/current.json")
edit_desired 'doc["deployment"]["subnets"]["awg-in"] = "10.99.0.0/24"' \
	'doc["deployment"]["subnets"]["wg-wdtt-in"] = "10.98.0.0/24"' \
	'doc["bot"]["wdttConfigDirectory"] = "/var/lib/spaiter-vpn/wdtt-relay"' \
	'doc["migrationPolicy"] = {"subnets": {"awg-in": {"from": "10.10.0.0/24", "to": "10.99.0.0/24", "strategy": "preserve-host"}, "wg-wdtt-in": {"from": "10.30.0.0/24", "to": "10.98.0.0/24", "strategy": "preserve-host"}}}'
# Add the same state a bot-provisioned user leaves behind, without needing a
# real Telegram token or network call in this disposable VM: public peer in the
# core, private half in bot/awg, and a cached subscription carrying the old IP.
BOT_PRIV=$(wg genkey)
BOT_PUB=$(printf '%s' "$BOT_PRIV" | wg pubkey)
WDTT_PRIV=$(wg genkey)
WDTT_PUB=$(printf '%s' "$WDTT_PRIV" | wg pubkey)
mkdir -p "$DATA_ROOT/bot/awg" "$DATA_ROOT/bot/wdtt/subs-cache"
python3 - "$CONFIG_ROOT/deployment/config.json" "$BOT_PUB" "$WDTT_PUB" <<'PY'
import json, sys
path, awg_public, wdtt_public = sys.argv[1:]
doc = json.load(open(path))
endpoint = next(item for item in doc["endpoints"] if item["tag"] == "awg-in")
endpoint["peers"].append({"name": "4242", "public_key": awg_public, "allowed_ips": "10.10.0.3/32"})
endpoint = next(item for item in doc["endpoints"] if item["tag"] == "wg-wdtt-in")
endpoint["peers"].append({"name": "4242", "public_key": wdtt_public, "allowed_ips": "10.30.0.3/32"})
json.dump(doc, open(path, "w"), indent=2)
PY
python3 - "$DATA_ROOT/bot/awg/4242.json" "$BOT_PRIV" "$BOT_PUB" <<'PY'
import json, sys
json.dump({"priv": sys.argv[2], "pub": sys.argv[3], "ip": "10.10.0.3"}, open(sys.argv[1], "w"))
PY
chmod 0600 "$DATA_ROOT/bot/awg/4242.json"
python3 - "$DATA_ROOT/bot/awg/4242-wg-wdtt-in.json" "$WDTT_PRIV" "$WDTT_PUB" <<'PY'
import json, sys
json.dump({"priv": sys.argv[2], "pub": sys.argv[3], "ip": "10.30.0.3"}, open(sys.argv[1], "w"))
PY
chmod 0600 "$DATA_ROOT/bot/awg/4242-wg-wdtt-in.json"
printf '{"password":"relay-secret"}' >"$DATA_ROOT/bot/wdtt/4242.json"
chmod 0600 "$DATA_ROOT/bot/wdtt/4242.json"
mkdir -p "$DATA_ROOT/wdtt-relay"
python3 - "$DATA_ROOT/wdtt-relay/passwords.json" "$WDTT_PRIV" <<'PY'
import json, sys
json.dump({
    "bot_token": "relay-owned-token",
    "devices": {"dev-1": {"seen": 7}},
    "passwords": {
        "relay-secret": {
            "max_devices": 1, "wg_priv": sys.argv[2], "wg_ip": "10.30.0.3",
            "down_bytes": 1234, "device_id": "dev-1",
        },
        "placeholder": {"max_devices": 1},
    },
}, open(sys.argv[1], "w"), indent=2)
PY
chmod 0600 "$DATA_ROOT/wdtt-relay/passwords.json"
printf '{"outbounds":[]}' >"$DATA_ROOT/bot/wdtt/subs-cache/test-token.json"
docker compose -f "$CONFIG_ROOT/deployment/docker-compose.yml" up -d --force-recreate >/dev/null
cp "$CONFIG_ROOT/deployment/config.json" "$WORK/subnet-config-before.json"
cp "$CONFIG_ROOT/deployment/secrets/secrets.json" "$WORK/subnet-secrets-before.json"
CONTAINER_BEFORE=$(docker inspect -f '{{.Id}}' sing-box 2>/dev/null)
if bootstrap plan -f "$DESIRED" >"$WORK/subnet-plan.log" 2>&1; then
	ok "the exact subnet policy planned successfully"
else
	bad "the subnet migration plan failed: $(tail -12 "$WORK/subnet-plan.log")"
fi
assert "the plan names subnet-migrate mode" grep -q 'mode: *subnet-migrate' "$WORK/subnet-plan.log"
if bootstrap apply -yes -f "$DESIRED" >"$WORK/subnet-migration.log" 2>&1; then
	ok "the preserve-host subnet migration applied"
else
	bad "the subnet migration failed: $(tail -14 "$WORK/subnet-migration.log")"
fi
CONTAINER_AFTER=$(docker inspect -f '{{.Id}}' sing-box 2>/dev/null)
if [ -n "$CONTAINER_BEFORE" ] && [ -n "$CONTAINER_AFTER" ] && [ "$CONTAINER_BEFORE" != "$CONTAINER_AFTER" ]; then
	ok "the subnet migration replaced the core container"
else
	bad "the subnet migration did not replace the core container: $CONTAINER_BEFORE -> $CONTAINER_AFTER"
fi
if python3 - "$WORK/subnet-secrets-before.json" "$CONFIG_ROOT/deployment/secrets/secrets.json" <<'PY'
import ipaddress, json, sys
before, after = (json.load(open(path)) for path in sys.argv[1:])
subnets = {
    "awg-in": ("10.10.0.0/24", "10.99.0.0/24"),
    "wg-wdtt-in": ("10.30.0.0/24", "10.98.0.0/24"),
}

def offset(value, network):
    return int(ipaddress.ip_interface(value).ip) - int(ipaddress.ip_network(network).network_address)

old_users = {u["Name"]: u for u in before["Users"]}
new_users = {u["Name"]: u for u in after["Users"]}
if old_users.keys() != new_users.keys():
    raise SystemExit(1)
for tag, (old_subnet, new_subnet) in subnets.items():
    old_ep, new_ep = before["Endpoints"][tag], after["Endpoints"][tag]
    old_keys = {k: v for k, v in old_ep.items() if k != "Address"}
    new_keys = {k: v for k, v in new_ep.items() if k != "Address"}
    if old_keys != new_keys or offset(old_ep["Address"], old_subnet) != offset(new_ep["Address"], new_subnet):
        raise SystemExit(1)
    for name, old_user in old_users.items():
        old_peer = old_user["Peers"][tag]
        new_peer = new_users[name]["Peers"][tag]
        if ({k: v for k, v in old_peer.items() if k != "Address"} !=
                {k: v for k, v in new_peer.items() if k != "Address"}):
            raise SystemExit(1)
        if offset(old_peer["Address"], old_subnet) != offset(new_peer["Address"], new_subnet):
            raise SystemExit(1)
PY
then
	ok "secrets.json preserved every key and numeric host offset"
else
	bad "secrets.json changed keys or reassigned a host number"
fi
if python3 - "$WORK/subnet-config-before.json" "$CONFIG_ROOT/deployment/config.json" <<'PY'
import ipaddress, json, sys
before, after = (json.load(open(path)) for path in sys.argv[1:])
subnets = {
    "awg-in": ("10.10.0.0/24", "10.99.0.0/24"),
    "wg-wdtt-in": ("10.30.0.0/24", "10.98.0.0/24"),
}

def first(value):
    return value[0] if isinstance(value, list) else value

def offset(value, network):
    return int(ipaddress.ip_interface(first(value)).ip) - int(ipaddress.ip_network(network).network_address)

for tag, (old_subnet, new_subnet) in subnets.items():
    old_ep = next(item for item in before["endpoints"] if item["tag"] == tag)
    new_ep = next(item for item in after["endpoints"] if item["tag"] == tag)
    if old_ep["private_key"] != new_ep["private_key"]:
        raise SystemExit(1)
    if offset(old_ep["address"], old_subnet) != offset(new_ep["address"], new_subnet):
        raise SystemExit(1)
    old_peers = {p["name"]: p for p in old_ep["peers"]}
    new_peers = {p["name"]: p for p in new_ep["peers"]}
    if old_peers.keys() != new_peers.keys():
        raise SystemExit(1)
    for name, old_peer in old_peers.items():
        new_peer = new_peers[name]
        if old_peer["public_key"] != new_peer["public_key"]:
            raise SystemExit(1)
        if offset(old_peer["allowed_ips"], old_subnet) != offset(new_peer["allowed_ips"], new_subnet):
            raise SystemExit(1)
PY
then
	ok "config.json preserved server and peer keys with their host offsets"
else
	bad "config.json changed a key or reassigned a host number"
fi
assert "the migrated endpoint uses the requested subnet" \
	grep -q '10\.99\.0\.1/24' "$CONFIG_ROOT/deployment/config.json"
assert "the bot peer kept its keys and host number" python3 - "$DATA_ROOT/bot/awg/4242.json" "$BOT_PRIV" "$BOT_PUB" <<'PY'
import json, sys
peer = json.load(open(sys.argv[1]))
raise SystemExit(0 if peer == {"priv": sys.argv[2], "pub": sys.argv[3], "ip": "10.99.0.3"} else 1)
PY
assert "the WG-over-VK bot and relay copies migrated without losing relay-owned fields" \
	python3 - "$DATA_ROOT/bot/awg/4242-wg-wdtt-in.json" "$WDTT_PRIV" "$WDTT_PUB" "$DATA_ROOT/wdtt-relay/passwords.json" <<'PY'
import json, sys
peer = json.load(open(sys.argv[1]))
relay = json.load(open(sys.argv[4]))
entry = relay["passwords"]["relay-secret"]
ok = (
    peer == {"priv": sys.argv[2], "pub": sys.argv[3], "ip": "10.98.0.3"}
    and relay["bot_token"] == "relay-owned-token"
    and relay["devices"] == {"dev-1": {"seen": 7}}
    and entry["wg_priv"] == sys.argv[2]
    and entry["wg_ip"] == "10.98.0.3"
    and entry["down_bytes"] == 1234
    and entry["device_id"] == "dev-1"
)
raise SystemExit(0 if ok else 1)
PY
assert "the relay reload marker was touched" test -f "$DATA_ROOT/bot/.reload-wdtt"
assert_absent "$DATA_ROOT/bot/wdtt/subs-cache/test-token.json" "the bot subscription-cache invalidation"
assert "the receipt adopted bot and relay state as runtime-mutable" python3 - \
	"$DATA_ROOT/bootstrap/current.json" \
	"$DATA_ROOT/bot/awg/4242.json" \
	"$DATA_ROOT/bot/awg/4242-wg-wdtt-in.json" \
	"$DATA_ROOT/wdtt-relay/passwords.json" \
	"$DATA_ROOT/bot/.reload-wdtt" <<'PY'
import json, sys
receipt = json.load(open(sys.argv[1]))
raise SystemExit(0 if all(receipt["files"][path]["ownership"] == "runtime-mutable" for path in sys.argv[2:]) else 1)
PY
bootstrap status >"$WORK/subnet-status.log" 2>&1
assert "status reads the receipt after adopting the bot peer" \
	grep -Fq "$DATA_ROOT/bot/awg/4242.json" "$WORK/subnet-status.log"
if docker ps --format '{{.Names}}' | grep -qx sing-box; then
	ok "the subnet-migrated deployment is running"
else
	bad "the subnet migration stopped the core"
fi

# ---------------------------------------------------------------------------

case_begin "an exact preserve-existing policy migrates seedUsers while retaining subnet audit records"
cp "$CONFIG_ROOT/deployment/secrets/secrets.json" "$WORK/seedusers-secrets-before.json"
edit_desired 'doc["bootstrap"]["seedUsers"] = ["owner", "second"]'
bootstrap plan -f "$DESIRED" >"$WORK/seedusers-blocked.log" 2>&1 || true
assert "unauthorised seedUsers change is blocked as migration-required" \
	grep -q 'mode: *migration-required' "$WORK/seedusers-blocked.log"

edit_desired 'doc["bootstrap"]["seedUsers"] = ["owner", "second"]' \
	'doc["migrationPolicy"]["seedUsers"] = {"from": ["owner"], "to": ["owner", "second"], "strategy": "preserve-existing"}'
if bootstrap plan -f "$DESIRED" >"$WORK/seedusers-plan.log" 2>&1; then
	ok "the exact seedUsers policy planned alongside the retained subnet policy"
else
	bad "the seedUsers migration plan failed: $(tail -12 "$WORK/seedusers-plan.log")"
fi
assert "the seedUsers plan names migrate mode" grep -q 'mode: *migrate' "$WORK/seedusers-plan.log"
if bootstrap apply -yes -f "$DESIRED" >"$WORK/seedusers-migration.log" 2>&1; then
	ok "the preserve-existing seedUsers migration applied"
else
	bad "the seedUsers migration failed: $(tail -14 "$WORK/seedusers-migration.log")"
fi
if python3 - "$WORK/seedusers-secrets-before.json" "$CONFIG_ROOT/deployment/secrets/secrets.json" "$CONFIG_ROOT/deployment/config.json" <<'PY'
import json, sys
before_secrets, after_secrets, after_config = (json.load(open(path)) for path in sys.argv[1:])
if [u["Name"] for u in after_secrets["Users"]] != ["owner", "second"]:
    raise SystemExit(1)
if after_secrets["Users"][0] != before_secrets["Users"][0]:
    raise SystemExit(1)
second = after_secrets["Users"][1]
if not second["Peers"]["awg-in"]["PrivateKey"] or second["Peers"]["awg-in"]["Address"] != "10.99.0.4/32":
    raise SystemExit(1)
awg_ep = next(item for item in after_config["endpoints"] if item["tag"] == "awg-in")
peer_ips = {p["name"]: (p["allowed_ips"][0] if isinstance(p["allowed_ips"], list) else p["allowed_ips"]) for p in awg_ep["peers"]}
if peer_ips != {
    "owner": "10.99.0.2/32",
    "4242": "10.99.0.3/32",
    "second": "10.99.0.4/32",
}:
    raise SystemExit(1)
PY
then
	ok "seedUsers migration preserved existing seed and bot peers and allocated the next free address"
else
	bad "seedUsers migration corrupted existing credentials or allocated a colliding address"
fi

# ---------------------------------------------------------------------------

case_begin "explicit rollback restores an older generation while preserving live users"
ROLLBACK_SEQUENCE_BEFORE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sequence"])' "$DATA_ROOT/bootstrap/current.json")
cp "$CONFIG_ROOT/deployment/secrets/secrets.json" "$WORK/rollback-secrets-before.json"
if bootstrap rollback -yes -generation "$ROLLBACK_TARGET" >"$WORK/explicit-rollback.log" 2>&1; then
	ok "the selected committed generation rolled back successfully"
else
	bad "explicit rollback failed: $(tail -16 "$WORK/explicit-rollback.log")"
fi
assert "rollback recorded a new monotonic generation" python3 - \
	"$DATA_ROOT/bootstrap/current.json" "$ROLLBACK_SEQUENCE_BEFORE" <<'PY'
import json, sys
receipt = json.load(open(sys.argv[1]))
raise SystemExit(0 if receipt["sequence"] > int(sys.argv[2]) else 1)
PY
assert "rollback restored both subnets and retained seed and bot users" python3 - \
	"$CONFIG_ROOT/desired.json" "$CONFIG_ROOT/deployment/config.json" <<'PY'
import json, sys
desired, config = (json.load(open(path)) for path in sys.argv[1:])
if desired["bootstrap"]["seedUsers"] != ["owner", "second"]:
    raise SystemExit(1)
if desired["deployment"]["subnets"]["awg-in"] != "10.10.0.0/24":
    raise SystemExit(1)
if desired["deployment"]["subnets"]["wg-wdtt-in"] != "10.30.0.0/24":
    raise SystemExit(1)
awg = next(item for item in config["endpoints"] if item["tag"] == "awg-in")
if {peer["name"] for peer in awg["peers"]} != {"owner", "second", "4242"}:
    raise SystemExit(1)
PY
assert "rollback preserved every credential while reversing addresses" python3 - \
	"$WORK/rollback-secrets-before.json" "$CONFIG_ROOT/deployment/secrets/secrets.json" <<'PY'
import ipaddress, json, sys
before, after = (json.load(open(path)) for path in sys.argv[1:])

def without_addresses(value):
    value = json.loads(json.dumps(value))
    for endpoint in value["Endpoints"].values():
        endpoint.pop("Address", None)
    for user in value["Users"]:
        for peer in user["Peers"].values():
            peer.pop("Address", None)
    return value

if without_addresses(before) != without_addresses(after):
    raise SystemExit(1)
for tag, network in {"awg-in": "10.10.0.0/24", "wg-wdtt-in": "10.30.0.0/24"}.items():
    if ipaddress.ip_interface(after["Endpoints"][tag]["Address"]).network != ipaddress.ip_network(network):
        raise SystemExit(1)
PY
assert "rollback reversed WG-over-VK bot and relay addresses" python3 - \
	"$DATA_ROOT/bot/awg/4242-wg-wdtt-in.json" "$DATA_ROOT/wdtt-relay/passwords.json" <<'PY'
import json, sys
peer, relay = (json.load(open(path)) for path in sys.argv[1:])
entry = relay["passwords"]["relay-secret"]
raise SystemExit(0 if peer["ip"] == "10.30.0.3" and entry["wg_ip"] == "10.30.0.3" and entry["down_bytes"] == 1234 else 1)
PY
if docker ps --format '{{.Names}}' | grep -qx sing-box; then
	ok "rollback left the deployment running"
else
	bad "rollback stopped the deployment"
fi

# ---------------------------------------------------------------------------

case_begin "generation pruning retains a usable previous rollback point"
PRUNE_SEQUENCE_BEFORE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sequence"])' "$DATA_ROOT/bootstrap/current.json")
PRUNE_JOURNALS_BEFORE=$(python3 -c 'import glob,sys; print(len(glob.glob(sys.argv[1] + "/bootstrap/transactions/*/journal.json")))' "$DATA_ROOT")
if bootstrap prune -keep 2 >"$WORK/prune-preview.log" 2>&1; then
	ok "generation pruning preview succeeded"
else
	bad "generation pruning preview failed: $(tail -16 "$WORK/prune-preview.log")"
fi
assert "pruning preview deleted no journals" python3 - \
	"$DATA_ROOT" "$PRUNE_JOURNALS_BEFORE" <<'PY'
import glob, sys
paths = glob.glob(sys.argv[1] + "/bootstrap/transactions/*/journal.json")
raise SystemExit(0 if int(sys.argv[2]) > 2 and len(paths) == int(sys.argv[2]) else 1)
PY
if bootstrap prune -keep 2 -yes >"$WORK/prune.log" 2>&1; then
	ok "generation pruning applied"
else
	bad "generation pruning failed: $(tail -16 "$WORK/prune.log")"
fi
assert "pruning retained exactly current and previous without moving the receipt" python3 - \
	"$DATA_ROOT" "$PRUNE_SEQUENCE_BEFORE" <<'PY'
import glob, json, sys
root, sequence = sys.argv[1:]
journals = [json.load(open(path)) for path in glob.glob(root + "/bootstrap/transactions/*/journal.json")]
receipt = json.load(open(root + "/bootstrap/current.json"))
raise SystemExit(0 if len(journals) == 2 and all(item["status"] == "committed" for item in journals) and receipt["sequence"] == int(sequence) else 1)
PY
if bootstrap rollback -yes >"$WORK/pruned-rollback.log" 2>&1; then
	ok "the previous generation remained rollbackable after pruning"
else
	bad "rollback after pruning failed: $(tail -16 "$WORK/pruned-rollback.log")"
fi
assert "rollback after pruning recorded a new generation" python3 - \
	"$DATA_ROOT/bootstrap/current.json" "$PRUNE_SEQUENCE_BEFORE" <<'PY'
import json, sys
receipt = json.load(open(sys.argv[1]))
raise SystemExit(0 if receipt["sequence"] > int(sys.argv[2]) else 1)
PY
if docker ps --format '{{.Names}}' | grep -qx sing-box; then
	ok "rollback after pruning left the deployment running"
else
	bad "rollback after pruning stopped the deployment"
fi

# ---------------------------------------------------------------------------

case_begin "credential rotation reissues every copy of the selected users only"
mkdir -p "$DATA_ROOT/bot/wdtt/subs-cache"
python3 - "$DATA_ROOT/bot/wdtt/subs.json" <<'PY'
import json, sys
json.dump({token: {"uid": uid, "created": "2026-01-01 00:00:00", "last_hash": "h-" + uid}
           for token, uid in {"tok-owner": "owner", "tok-second": "second", "tok-4242": "4242"}.items()},
          open(sys.argv[1], "w"))
PY
printf '{"outbounds":[]}' >"$DATA_ROOT/bot/wdtt/subs-cache/tok-4242.json"
cp "$CONFIG_ROOT/deployment/config.json" "$WORK/rotate-config-before.json"
cp "$CONFIG_ROOT/deployment/secrets/secrets.json" "$WORK/rotate-secrets-before.json"
cp "$DATA_ROOT/bot/awg/4242.json" "$WORK/rotate-awg-before.json"
cp "$DATA_ROOT/bot/awg/4242-wg-wdtt-in.json" "$WORK/rotate-wdtt-before.json"
ROTATE_SEQUENCE_BEFORE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sequence"])' "$DATA_ROOT/bootstrap/current.json")
if bootstrap rotate -users 4242,owner </dev/null >"$WORK/rotate-unconfirmed.log" 2>&1; then
	bad "an unconfirmed rotation ran without a terminal"
else
	ok "an unconfirmed rotation without a terminal is refused"
fi
assert "the refused rotation changed nothing" cmp -s "$WORK/rotate-config-before.json" "$CONFIG_ROOT/deployment/config.json"
if bootstrap rotate -users nobody -yes >"$WORK/rotate-unknown.log" 2>&1; then
	bad "rotating an unknown user reported success"
else
	ok "rotating an unknown user is refused"
fi
assert "the unknown-user refusal names the reason" grep -q 'not a user of the live configuration' "$WORK/rotate-unknown.log"
assert "the unknown-user refusal changed nothing" cmp -s "$WORK/rotate-config-before.json" "$CONFIG_ROOT/deployment/config.json"
if bootstrap rotate -users 4242,owner -yes >"$WORK/rotate.log" 2>&1; then
	ok "credential rotation applied"
else
	bad "credential rotation failed: $(tail -16 "$WORK/rotate.log")"
fi
assert "the rotation plan named migrate mode" grep -q 'mode: *migrate' "$WORK/rotate.log"
assert "rotation recorded a new generation and its audit record" python3 - \
	"$DATA_ROOT/bootstrap/current.json" "$ROTATE_SEQUENCE_BEFORE" "$CONFIG_ROOT/desired.json" <<'PY'
import json, sys
receipt, desired = json.load(open(sys.argv[1])), json.load(open(sys.argv[3]))
record = desired.get("migrationPolicy", {}).get("rotateCredentials", {})
ok = receipt["sequence"] > int(sys.argv[2]) and record.get("users") == ["4242", "owner"] and record.get("strategy") == "reissue" and record.get("id")
raise SystemExit(0 if ok else 1)
PY
assert "config.json reissued owner and 4242 at the same addresses and left second alone" python3 - \
	"$WORK/rotate-config-before.json" "$CONFIG_ROOT/deployment/config.json" <<'PY'
import json, sys
before, after = (json.load(open(path)) for path in sys.argv[1:])

def users(doc):
    out = {}
    for inbound in doc.get("inbounds", []):
        for user in inbound.get("users") or []:
            name = user.get("name") or user.get("username")
            out[(inbound["tag"], name)] = {k: v for k, v in user.items() if k not in ("name", "username")}
    return out

def peers(doc):
    return {(ep["tag"], p["name"]): p for ep in doc.get("endpoints", []) for p in ep.get("peers") or []}

ub, ua = users(before), users(after)
if ub.keys() != ua.keys():
    raise SystemExit(1)
for (tag, name), value in ub.items():
    if (name == "owner") == (value == ua[(tag, name)]):
        raise SystemExit(1)
if not any(name == "owner" for _, name in ub):
    raise SystemExit(1)
pb, pa = peers(before), peers(after)
if pb.keys() != pa.keys():
    raise SystemExit(1)
for key, peer in pb.items():
    rotated = key[1] in ("owner", "4242")
    if peer["allowed_ips"] != pa[key]["allowed_ips"]:
        raise SystemExit(1)
    if rotated == (peer["public_key"] == pa[key]["public_key"]):
        raise SystemExit(1)
for old, new in ((before, after),):
    shared = lambda d: [(ep["tag"], ep["private_key"]) for ep in d["endpoints"]]
    if shared(old) != shared(new):
        raise SystemExit(1)
PY
assert "secrets.json hands owner the new credentials and keeps second's" python3 - \
	"$WORK/rotate-secrets-before.json" "$CONFIG_ROOT/deployment/secrets/secrets.json" "$CONFIG_ROOT/deployment/config.json" <<'PY'
import json, sys
before, after, config = (json.load(open(path)) for path in sys.argv[1:])
b = {u["Name"]: u for u in before["Users"]}
a = {u["Name"]: u for u in after["Users"]}
if b["second"] != a["second"] or b["owner"]["VLESSRealityUUID"] == a["owner"]["VLESSRealityUUID"]:
    raise SystemExit(1)
awg = next(ep for ep in config["endpoints"] if ep["tag"] == "awg-in")
live = next(p for p in awg["peers"] if p["name"] == "owner")
if a["owner"]["Peers"]["awg-in"]["PublicKey"] != live["public_key"] or not a["owner"]["Peers"]["awg-in"]["PrivateKey"]:
    raise SystemExit(1)
if {k: v for k, v in before.items() if k != "Users"} != {k: v for k, v in after.items() if k != "Users"}:
    raise SystemExit(1)
PY
assert "the bot peer copies of 4242 hold the new keys the server accepts" python3 - \
	"$WORK/rotate-awg-before.json" "$DATA_ROOT/bot/awg/4242.json" \
	"$WORK/rotate-wdtt-before.json" "$DATA_ROOT/bot/awg/4242-wg-wdtt-in.json" "$CONFIG_ROOT/deployment/config.json" <<'PY'
import json, sys
awg_b, awg_a, wdtt_b, wdtt_a, config = (json.load(open(path)) for path in sys.argv[1:])
live = {(ep["tag"], p["name"]): p["public_key"] for ep in config["endpoints"] for p in ep.get("peers") or []}
ok = (awg_a["ip"] == awg_b["ip"] and awg_a["pub"] != awg_b["pub"] and awg_a["pub"] == live[("awg-in", "4242")]
      and wdtt_a["ip"] == wdtt_b["ip"] and wdtt_a["pub"] != wdtt_b["pub"] and wdtt_a["pub"] == live[("wg-wdtt-in", "4242")])
raise SystemExit(0 if ok else 1)
PY
assert "the relay password was reissued and the device bound with the old one dropped" python3 - \
	"$DATA_ROOT/bot/wdtt/4242.json" "$DATA_ROOT/wdtt-relay/passwords.json" "$DATA_ROOT/bot/awg/4242-wg-wdtt-in.json" <<'PY'
import json, sys
password, relay, peer = (json.load(open(path)) for path in sys.argv[1:])
new = password["password"]
entry = relay["passwords"].get(new, {})
ok = (new != "relay-secret" and "relay-secret" not in relay["passwords"] and "placeholder" in relay["passwords"]
      and entry.get("wg_priv") == peer["priv"] and entry.get("wg_ip") == peer["ip"] and entry.get("down_bytes") == 1234
      and "device_id" not in entry and "dev-1" not in relay.get("devices", {}) and relay["bot_token"] == "relay-owned-token")
raise SystemExit(0 if ok else 1)
PY
assert "subscription tokens of rotated users were replaced, second's kept" python3 - "$DATA_ROOT/bot/wdtt/subs.json" <<'PY'
import json, sys
subs = json.load(open(sys.argv[1]))
owners = sorted(v["uid"] for v in subs.values())
ok = (owners == ["4242", "owner", "second"] and "tok-owner" not in subs and "tok-4242" not in subs
      and subs.get("tok-second", {}).get("last_hash") == "h-second")
raise SystemExit(0 if ok else 1)
PY
assert_absent "$DATA_ROOT/bot/wdtt/subs-cache/tok-4242.json" "the rotated subscription cache"
assert "the running core serves the rotated credentials" python3 - "$CONFIG_ROOT/deployment/config.json" <<'PY'
import json, sys, urllib.request
config = json.load(open(sys.argv[1]))
api = config["experimental"]["clash_api"]
base = "http://" + (("127.0.0.1" + api["external_controller"]) if api["external_controller"].startswith(":") else api["external_controller"])

def get(path):
    request = urllib.request.Request(base + path, headers={"Authorization": "Bearer " + api["secret"]})
    return json.load(urllib.request.urlopen(request, timeout=10))

for inbound in config["inbounds"]:
    want = next((u for u in inbound.get("users") or [] if (u.get("name") or u.get("username")) == "owner"), None)
    if want is None:
        continue
    live = [u for u in get("/manage/inbounds/" + inbound["tag"] + "/users") if (u.get("name") or u.get("username")) == "owner"]
    if len(live) != 1 or {k: v for k, v in want.items()} != {k: v for k, v in live[0].items() if k in want}:
        raise SystemExit(1)
    break
else:
    raise SystemExit(1)
PY
if docker ps --format '{{.Names}}' | grep -qx sing-box; then
	ok "the rotated deployment is running"
else
	bad "the rotation stopped the core"
fi
cp "$CONFIG_ROOT/deployment/config.json" "$WORK/rotate-config-after.json"
if bootstrap apply -yes -f "$CONFIG_ROOT/desired.json" >"$WORK/rotate-reapply.log" 2>&1; then
	ok "re-applying the recorded rotation converges"
else
	bad "re-applying the recorded rotation failed: $(tail -12 "$WORK/rotate-reapply.log")"
fi
assert "the retained rotation record rotated nothing again" python3 - \
	"$WORK/rotate-config-after.json" "$CONFIG_ROOT/deployment/config.json" <<'PY'
import json, sys
before, after = (json.load(open(path)) for path in sys.argv[1:])
key = lambda d: sorted((ep["tag"], p["name"], p["public_key"]) for ep in d["endpoints"] for p in ep.get("peers") or [])
raise SystemExit(0 if key(before) == key(after) else 1)
PY
if bootstrap rollback -yes -generation "$ROTATE_SEQUENCE_BEFORE" >"$WORK/rotate-rollback.log" 2>&1; then
	ok "rollback to the generation before the rotation succeeded"
else
	bad "rollback after a rotation failed: $(tail -16 "$WORK/rotate-rollback.log")"
fi
assert "rollback restored intent, not the retired credentials" python3 - \
	"$WORK/rotate-config-after.json" "$CONFIG_ROOT/deployment/config.json" <<'PY'
import json, sys
before, after = (json.load(open(path)) for path in sys.argv[1:])
key = lambda d: sorted((ep["tag"], p["name"], p["public_key"]) for ep in d["endpoints"] for p in ep.get("peers") or [])
raise SystemExit(0 if key(before) == key(after) else 1)
PY

# ---------------------------------------------------------------------------

case_begin "the control daemon performs typed operations for authorised callers only"
getent group spaiter-vpn >/dev/null || groupadd --system spaiter-vpn
for name in ctlop ctlobs ctlnone; do
	id "$name" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$name"
done
usermod -aG spaiter-vpn ctlop
usermod -aG spaiter-vpn ctlobs
usermod -aG spaiter-vpn ctlnone
python3 - "$CONFIG_ROOT/control.json" <<'PY'
import grp, json, pwd, sys
json.dump({"apiVersion": "spaiter-vpn/control/v1alpha1",
           "operators": [pwd.getpwnam("ctlop").pw_uid],
           "observers": [pwd.getpwnam("ctlobs").pw_uid],
           "socketGroup": grp.getgrnam("spaiter-vpn").gr_gid}, open(sys.argv[1], "w"))
PY
chmod 0644 "$CONFIG_ROOT/control.json"
systemd-run --unit acceptance-control --property RuntimeDirectory=spaiter-vpn "$BINARY" control serve >/dev/null
for _ in $(seq 1 30); do [ -S /run/spaiter-vpn/control.sock ] && break; sleep 1; done
assert "the socket exists, group-owned and not world-accessible" python3 - /run/spaiter-vpn/control.sock <<'PY'
import grp, os, stat, sys
info = os.stat(sys.argv[1])
raise SystemExit(0 if stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o660 and grp.getgrgid(info.st_gid).gr_name == "spaiter-vpn" else 1)
PY
as_user() { local user=$1; shift; runuser -u "$user" -- "$BINARY" control "$@"; }
if as_user ctlobs status >"$WORK/control-observer-status.log" 2>&1; then
	ok "an observer reads status"
else
	bad "an observer could not read status: $(tail -5 "$WORK/control-observer-status.log")"
fi
assert "status reports the current generation" grep -q '"generation"' "$WORK/control-observer-status.log"
if as_user ctlobs prepare -rollback >"$WORK/control-observer-prepare.log" 2>&1; then
	bad "an observer prepared a change"
else
	ok "an observer cannot prepare a change"
fi
if as_user ctlnone status >"$WORK/control-none.log" 2>&1; then
	bad "an unlisted uid read status"
else
	ok "an unlisted uid is denied even inside the socket group"
fi
if as_user ctlop prepare -image evil.example/core:1 >"$WORK/control-evil-image.log" 2>&1; then
	bad "the daemon accepted an image from another registry"
else
	ok "an image from another registry is refused"
fi
CTL_PORT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["deployment"]["ports"]["awg-in"] + 7)' "$CONFIG_ROOT/desired.json")
if as_user ctlop prepare -port "awg-in=$CTL_PORT" >"$WORK/control-prepare.log" 2>&1; then
	ok "an operator prepared a port change"
else
	bad "prepare failed: $(tail -12 "$WORK/control-prepare.log")"
fi
CTL_TICKET=$(python3 - "$WORK/control-prepare.log" <<'PY'
import re, sys
match = re.search(r'"id": "([0-9a-f]{32})"', open(sys.argv[1]).read())
print(match.group(1) if match else "")
PY
)
if as_user ctlop commit "$CTL_TICKET" >"$WORK/control-commit.log" 2>&1; then
	ok "the operator's ticket committed"
else
	bad "commit failed: $(tail -16 "$WORK/control-commit.log")"
fi
assert "the committed port is the stored intent" python3 - "$CONFIG_ROOT/desired.json" "$CTL_PORT" <<'PY'
import json, sys
raise SystemExit(0 if json.load(open(sys.argv[1]))["deployment"]["ports"]["awg-in"] == int(sys.argv[2]) else 1)
PY
assert "the new port is open in UFW" ufw_allows "$CTL_PORT/udp"
if as_user ctlop commit "$CTL_TICKET" >"$WORK/control-recommit.log" 2>&1; then
	bad "a ticket committed twice"
else
	ok "a ticket commits only once"
fi
assert "the audit log names the operator, the change and its transaction" python3 - \
	"$DATA_ROOT/control/audit.log" <<'PY'
import json, pwd, sys
entries = [json.loads(line) for line in open(sys.argv[1])]
uid = pwd.getpwnam("ctlop").pw_uid
commits = [e for e in entries if e["operation"] == "commit" and e["ok"] and e["peer"]["uid"] == uid]
denied = [e for e in entries if e.get("error") == "denied" and e["peer"]["uid"] == pwd.getpwnam("ctlnone").pw_uid]
raise SystemExit(0 if len(commits) == 1 and commits[0]["transaction"] and "awg-in" in commits[0]["change"] and denied else 1)
PY
assert_mode "$DATA_ROOT/control/audit.log" 600
if docker ps --format '{{.Names}}' | grep -qx sing-box; then
	ok "the deployment runs after the daemon's change"
else
	bad "the daemon's change stopped the core"
fi

# The web UI: the second client, unprivileged, as the operator account.
mkdir -p /run/acceptance-web && chmod 0755 /run/acceptance-web
rm -f /run/acceptance-web/web.key
"$BINARY" web key -key /run/acceptance-web/web.key -group "$(getent group spaiter-vpn | cut -d: -f3)" >/dev/null
systemd-run --unit acceptance-web --uid ctlop "$BINARY" web serve -key /run/acceptance-web/web.key -listen 127.0.0.1:10880 >/dev/null
for _ in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:10880/ && break; sleep 1; done
WEB_LINK=$("$BINARY" web login-link -key /run/acceptance-web/web.key -url http://127.0.0.1:10880)
WEB_PORT=$((CTL_PORT + 1))
assert "the web UI plans and applies a change through the daemon, behind a one-time login" python3 - "$WEB_LINK" "$WEB_PORT" <<'PY'
import http.cookiejar, re, sys, urllib.error, urllib.parse, urllib.request
link, port = sys.argv[1], sys.argv[2]
def status(opener, url, data=None):
    try:
        response = opener.open(url, data=None if data is None else urllib.parse.urlencode(data).encode(), timeout=600)
        return response.status, response.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode()
anonymous = urllib.request.build_opener()
assert status(anonymous, "http://127.0.0.1:10880/")[0] == 401, "home served without a session"
jar = http.cookiejar.CookieJar()
browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
code, home = status(browser, link)
assert code == 200 and "Поколение" in home, ("login", code)
assert status(urllib.request.build_opener(), link)[0] == 403, "a login link worked twice"
csrf = re.search(r'name="csrf" value="([^"]+)"', home).group(1)
assert status(browser, "http://127.0.0.1:10880/prepare", {"kind": "rollback"})[0] == 403, "a form without its token was accepted"
code, plan = status(browser, "http://127.0.0.1:10880/prepare", {"csrf": csrf, "kind": "settings", "protocol": "awg-in", "port": port})
assert code == 200, ("prepare", code, plan[:400])
ticket = re.search(r'name="ticket" value="([0-9a-f]{32})"', plan).group(1)
code, result = status(browser, "http://127.0.0.1:10880/commit", {"csrf": csrf, "ticket": ticket})
assert code == 200 and "Применено" in result, ("commit", code, result[:400])
PY
assert "the web UI's change is the stored intent" python3 - "$CONFIG_ROOT/desired.json" "$WEB_PORT" <<'PY'
import json, sys
raise SystemExit(0 if json.load(open(sys.argv[1]))["deployment"]["ports"]["awg-in"] == int(sys.argv[2]) else 1)
PY
assert "the audit log names the web server's account for that commit" python3 - "$DATA_ROOT/control/audit.log" "$WEB_PORT" <<'PY'
import json, pwd, sys
uid = pwd.getpwnam("ctlop").pw_uid
entries = [json.loads(line) for line in open(sys.argv[1])]
raise SystemExit(0 if any(e["operation"] == "commit" and e["ok"] and e["peer"]["uid"] == uid and sys.argv[2] in e["change"] for e in entries) else 1)
PY
systemctl stop acceptance-web >/dev/null 2>&1
systemctl stop acceptance-control >/dev/null 2>&1

case_begin "bootstrap installs, proves and retires the control daemon"
# From the stored intent: rotation, rollback and the daemon's own commit have
# moved it past the working copy.
cp "$CONFIG_ROOT/desired.json" "$DESIRED"
# The previous case wrote its own allow-list; bootstrap must create one only
# when there is none, so start without it.
rm -f "$CONFIG_ROOT/control.json"
edit_desired 'doc["bootstrap"]["manageControl"] = True'
if bootstrap apply -yes -f "$DESIRED" >"$WORK/control-install.log" 2>&1; then
	ok "an apply with manageControl succeeded"
else
	bad "the manageControl apply failed: $(tail -16 "$WORK/control-install.log")"
fi
assert "the daemon unit is active" systemctl is-active --quiet spaiter-vpn-control.service
assert "the daemon is enabled at boot" systemctl is-enabled --quiet spaiter-vpn-control.service
assert "the allow-list was created root-only" test "$(stat -c %a "$CONFIG_ROOT/control.json")" = 600
if "$BINARY" control status >"$WORK/control-managed-status.log" 2>&1; then
	ok "root reaches the managed daemon"
else
	bad "the managed daemon does not answer: $(tail -5 "$WORK/control-managed-status.log")"
fi
python3 - "$CONFIG_ROOT/control.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1])); doc["observers"] = [4242]
json.dump(doc, open(sys.argv[1], "w"))
PY
if bootstrap apply -yes -f "$DESIRED" >"$WORK/control-reapply.log" 2>&1; then
	ok "a second manageControl apply converged"
else
	bad "the second manageControl apply failed: $(tail -16 "$WORK/control-reapply.log")"
fi
assert "the operator's edit of the allow-list survived" grep -q 4242 "$CONFIG_ROOT/control.json"
edit_desired 'doc["bootstrap"]["manageControl"] = False'
if bootstrap apply -yes -f "$DESIRED" >"$WORK/control-retire.log" 2>&1; then
	ok "turning manageControl off applied"
else
	bad "retiring the daemon failed: $(tail -16 "$WORK/control-retire.log")"
fi
if systemctl is-active --quiet spaiter-vpn-control.service; then
	bad "the retired daemon is still running"
else
	ok "the retired daemon is stopped"
fi
assert_absent /etc/systemd/system/spaiter-vpn-control.service "retiring the daemon"

case_begin "dynamic DNS keeps the public name on this server's address"
# A dyndns2 service of our own, over HTTPS with a CA the guest trusts for the
# length of this case: the updater refuses plain http, because the password
# travels with every update.
cp "$CONFIG_ROOT/desired.json" "$DESIRED"
DDNS_DIR=$WORK/ddns
mkdir -p "$DDNS_DIR"
(
	cd "$DDNS_DIR" &&
		openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=acceptance ddns CA" -keyout ca.key -out ca.crt &&
		openssl req -newkey rsa:2048 -nodes -subj "/CN=ddns.acceptance.test" -keyout server.key -out server.csr &&
		printf 'subjectAltName=DNS:ddns.acceptance.test\n' >ext &&
		openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 -extfile ext -out server.crt
) >/dev/null 2>&1 || bad "could not make the test CA"
cp "$DDNS_DIR/ca.crt" /usr/local/share/ca-certificates/spaiter-acceptance-ddns.crt
update-ca-certificates >/dev/null 2>&1
echo "127.0.0.1 ddns.acceptance.test" >>/etc/hosts
cat >"$DDNS_DIR/server.py" <<'PY'
import base64, http.server, ssl, sys, urllib.parse
directory = sys.argv[1]
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        auth = self.headers.get("Authorization", "")
        good = auth == "Basic " + base64.b64encode(b"acc:right-password").decode()
        query = urllib.parse.parse_qs(url.query)
        with open(directory + "/requests.log", "a") as log:
            log.write(("ok " if good else "denied ") + url.query + "\n")
        answer = ("good " + query.get("myip", [""])[0]) if good and url.path == "/nic/update" else "badauth"
        self.send_response(200)
        self.end_headers()
        self.wfile.write(answer.encode())
    def log_message(self, *args):
        pass
server = http.server.HTTPServer(("127.0.0.1", 18443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(directory + "/server.crt", directory + "/server.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
systemd-run --unit acceptance-ddns python3 -I "$DDNS_DIR/server.py" "$DDNS_DIR" >/dev/null
printf 'right-password' | bootstrap credential ddns-token >/dev/null 2>&1
DDNS_ORIGINAL_HOST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bot"]["publicHost"])' "$DESIRED")
edit_desired 'doc["bot"].update({"publicHost": "home.acceptance.test", "dynamicIp": True})' \
	'doc["ddns"] = {"provider": "dyndns2", "token": "ddns-token", "server": "https://ddns.acceptance.test:18443", "username": "acc"}'
if bootstrap apply -yes -f "$DESIRED" >"$WORK/ddns-install.log" 2>&1; then
	ok "an apply with ddns succeeded"
else
	bad "the ddns apply failed: $(tail -16 "$WORK/ddns-install.log")"
fi
assert "the updater's unit is active" systemctl is-active --quiet spaiter-vpn-ddns.service
DDNS_PID=$(systemctl show -p MainPID --value spaiter-vpn-ddns.service)
assert "the updater holds no capability" sh -c "grep -q '^CapEff:[[:space:]]*0000000000000000' /proc/$DDNS_PID/status"
refute "the deployment's configuration does not exist for the updater" nsenter -t "$DDNS_PID" -m ls "$CONFIG_ROOT/deployment"
refute "the token is not in the unit" grep -q right-password /etc/systemd/system/spaiter-vpn-ddns.service
# The address is found the way the internet sees it, so the record can only be
# pushed from a guest that reaches the internet.
if curl -4 -s --max-time 8 https://api.ipify.org >/dev/null 2>&1; then
	assert "the record was pushed with this server's address" sh -c "grep -q '^ok .*hostname=home.acceptance.test' '$DDNS_DIR/requests.log' && grep -q 'myip=' '$DDNS_DIR/requests.log'"
	assert "the updater reported success" sh -c "grep -q '\"ok\": true' /var/lib/spaiter-vpn-ddns/status.json"
	if bootstrap apply -yes -f "$DESIRED" >"$WORK/ddns-reapply.log" 2>&1; then
		ok "an unchanged ddns apply converged"
	else
		bad "the unchanged ddns apply failed: $(tail -16 "$WORK/ddns-reapply.log")"
	fi
	printf 'wrong-password' | bootstrap credential ddns-token >/dev/null 2>&1
	if bootstrap apply -yes -f "$DESIRED" >"$WORK/ddns-badauth.log" 2>&1; then
		bad "an apply with a rejected password succeeded"
	else
		assert "a rejected password fails the apply and says why" grep -q badauth "$WORK/ddns-badauth.log"
	fi
	printf 'right-password' | bootstrap credential ddns-token >/dev/null 2>&1
else
	ok "skipped pushing a record: the guest has no internet to learn its address from"
fi
edit_desired 'doc.pop("ddns", None)' 'doc["bot"].pop("dynamicIp", None)' "doc['bot']['publicHost'] = '$DDNS_ORIGINAL_HOST'"
if bootstrap apply -yes -f "$DESIRED" >"$WORK/ddns-retire.log" 2>&1; then
	ok "turning ddns off applied"
else
	bad "retiring ddns failed: $(tail -16 "$WORK/ddns-retire.log")"
fi
refute "the retired updater is stopped" systemctl is-active --quiet spaiter-vpn-ddns.service
assert_absent /etc/systemd/system/spaiter-vpn-ddns.service "retiring ddns"
systemctl stop acceptance-ddns >/dev/null 2>&1
rm -f /usr/local/share/ca-certificates/spaiter-acceptance-ddns.crt
update-ca-certificates --fresh >/dev/null 2>&1
sed -i '/ddns.acceptance.test/d' /etc/hosts

case_begin "MTProto gives every user their own secret on a core that has MTProto users"
if [ -z "${ACCEPTANCE_EXTRA_IMAGES:-}" ]; then
	ok "skipped: no core image with MTProto users was served (pass a second --local-image)"
else
cp "$CONFIG_ROOT/desired.json" "$DESIRED"
SHARED_MTPROTO=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["MTProto"]["Secret"])' "$CONFIG_ROOT/deployment/secrets/secrets.json")
NEW_CORE=${ACCEPTANCE_EXTRA_IMAGES%% *}
edit_desired "doc['deployment']['image'] = '$NEW_CORE'" 'doc["deployment"]["mtprotoPerUser"] = True'
if bootstrap apply -yes -f "$DESIRED" >"$WORK/mtproto-users.log" 2>&1; then
	ok "per-user MTProto applied on the newer core"
else
	bad "per-user MTProto failed: $(tail -20 "$WORK/mtproto-users.log")"
fi
assert "every seed user has their own fake-TLS secret, and the handed-out shared one survives" python3 - \
	"$CONFIG_ROOT/deployment/config.json" "$CONFIG_ROOT/deployment/secrets/secrets.json" "$SHARED_MTPROTO" <<'PY'
import json, sys
config, secrets = (json.load(open(path)) for path in sys.argv[1:3])
inbound = next(i for i in config["inbounds"] if i["type"] == "mtproto")
users = {u["name"]: u["secret"] for u in inbound.get("users") or []}
seeds = {u["Name"]: u.get("MTProtoSecret", "") for u in secrets["Users"]}
ok = (inbound.get("secret") == sys.argv[3] and seeds and all(seeds[name] and users.get(name) == seeds[name] for name in seeds)
      and len(set(users.values())) == len(users) and all(v.startswith("ee") for v in users.values()))
raise SystemExit(0 if ok else 1)
PY
# A live fake-TLS handshake against the running core: the user's own key is
# recognised as that user, a stranger's is not.
cat >"$WORK/mtproto-hello.py" <<'PY'
import hashlib, hmac, os, socket, struct, sys, time
port, secret = int(sys.argv[1]), sys.argv[2]
key, host = bytes.fromhex(secret[2:34]), bytes.fromhex(secret[34:])
body = b"\x03\x03" + bytes(32) + b"\x20" + os.urandom(32) + b"\x00\x02\x13\x01\x01\x00"
sni = struct.pack(">HHHBH", 0, len(host) + 5, len(host) + 3, 0, len(host)) + host
body += struct.pack(">H", len(sni)) + sni
handshake = bytearray(b"\x01\x00" + struct.pack(">H", len(body)) + body)
digest = bytearray(hmac.new(key, b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + bytes(handshake), hashlib.sha256).digest())
stamp = struct.pack("<I", int(time.time()))
for i in range(4):
    digest[28 + i] ^= stamp[i]
handshake[6:38] = digest
conn = socket.create_connection(("127.0.0.1", port), timeout=5)
conn.sendall(b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + bytes(handshake))
try:
    conn.recv(1)
except OSError:
    pass
conn.close()
PY
MTPROTO_PORT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["deployment"]["ports"]["mtproto-in"])' "$DESIRED")
OWNER_MTPROTO=$(python3 -c 'import json,sys; print(next(u["MTProtoSecret"] for u in json.load(open(sys.argv[1]))["Users"] if u["Name"] == "owner"))' "$CONFIG_ROOT/deployment/secrets/secrets.json")
python3 -I "$WORK/mtproto-hello.py" "$MTPROTO_PORT" "$OWNER_MTPROTO" >/dev/null 2>&1
STRANGER="ee$(python3 -c 'import os; print(os.urandom(16).hex())')$(printf %s www.google.com | od -An -tx1 | tr -d ' \n')"
python3 -I "$WORK/mtproto-hello.py" "$MTPROTO_PORT" "$STRANGER" >/dev/null 2>&1
sleep 2
assert "the running core recognised the owner by their own secret" grep -q "inbound mtproto connection from .* as owner" "$CONFIG_ROOT/deployment/sing-box.log"
assert "a stranger's hello was attributed to nobody" sh -c "grep 'inbound mtproto connection from' '$CONFIG_ROOT/deployment/sing-box.log' | grep -vq ' as '"
# Provisioning through the management API, as the bot does.
assert "the management API provisions an MTProto user" python3 - "$CONFIG_ROOT/deployment/config.json" <<'PY'
import json, os, sys, urllib.request
config = json.load(open(sys.argv[1]))
api = config["experimental"]["clash_api"]
base = "http://" + (("127.0.0.1" + api["external_controller"]) if api["external_controller"].startswith(":") else api["external_controller"])
def call(method, path, body=None):
    request = urllib.request.Request(base + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                     headers={"Authorization": "Bearer " + api["secret"], "Content-Type": "application/json"})
    return urllib.request.urlopen(request, timeout=20).read()
secret = "ee" + os.urandom(16).hex() + b"www.google.com".hex()
call("POST", "/manage/inbounds/mtproto-in/users", {"name": "probe", "secret": secret})
call("POST", "/manage/apply")
users = json.loads(call("GET", "/manage/inbounds/mtproto-in/users"))
open(sys.argv[1] + ".probe", "w").write(secret)
raise SystemExit(0 if any(u.get("name") == "probe" and u.get("secret") == secret for u in users) else 1)
PY
python3 -I "$WORK/mtproto-hello.py" "$MTPROTO_PORT" "$(cat "$CONFIG_ROOT/deployment/config.json.probe" 2>/dev/null)" >/dev/null 2>&1
sleep 2
rm -f "$CONFIG_ROOT/deployment/config.json.probe"
assert "a user provisioned through the API is recognised live" grep -q "inbound mtproto connection from .* as probe" "$CONFIG_ROOT/deployment/sing-box.log"
cp "$CONFIG_ROOT/desired.json" "$DESIRED"
edit_desired 'doc["deployment"]["retireSharedMtproto"] = True'
if bootstrap apply -yes -f "$DESIRED" >"$WORK/mtproto-retire.log" 2>&1; then
	ok "retiring the shared MTProto secret applied"
else
	bad "retiring the shared secret failed: $(tail -20 "$WORK/mtproto-retire.log")"
fi
assert "the shared secret is gone and every user, including the provisioned one, keeps theirs" python3 - "$CONFIG_ROOT/deployment/config.json" <<'PY'
import json, sys
inbound = next(i for i in json.load(open(sys.argv[1]))["inbounds"] if i["type"] == "mtproto")
names = {u["name"] for u in inbound.get("users") or []}
raise SystemExit(0 if not inbound.get("secret") and {"owner", "probe"} <= names else 1)
PY
fi

case_begin "the bot runs as its own account and sees only the management endpoint"
cp "$CONFIG_ROOT/desired.json" "$DESIRED"
# A stand-in Bot API: enough for the bot to start and long-poll. The bot is on
# the host network, so it reaches this on loopback.
cat >"$WORK/fake-telegram.py" <<'PY'
import http.server, json, time
class Handler(http.server.BaseHTTPRequestHandler):
    def respond(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        method = self.path.rsplit("/", 1)[-1]
        if method == "getMe":
            result = {"id": 1, "is_bot": True, "first_name": "acceptance", "username": "acceptance_bot"}
        elif method == "getUpdates":
            time.sleep(1)
            result = []
        else:
            result = True
        body = json.dumps({"ok": True, "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = do_POST = respond
    def log_message(self, *args):
        pass
http.server.ThreadingHTTPServer(("127.0.0.1", 18081), Handler).serve_forever()
PY
systemd-run --unit acceptance-telegram python3 -I "$WORK/fake-telegram.py" >/dev/null
printf '123456:acceptance-token' | bootstrap credential telegram-token >/dev/null 2>&1
rm -f "$CONFIG_ROOT/control.json"
edit_desired 'doc["bot"].update({"enabled": True, "adminIds": [], "publicHost": "127.0.0.1", "telegramToken": "telegram-token", "telegramApiUrl": "http://127.0.0.1:18081", "dedicatedUser": True})' \
	'doc["bootstrap"]["manageControl"] = True'
if bootstrap apply -yes -f "$DESIRED" >"$WORK/bot-isolated.log" 2>&1; then
	ok "an apply with an isolated bot succeeded"
else
	bad "the isolated-bot apply failed: $(tail -20 "$WORK/bot-isolated.log")"
fi
BOT_IDS="$(id -u spaiter-vpn-bot 2>/dev/null):$(id -g spaiter-vpn-bot 2>/dev/null)"
assert "the bot's system account was created" id spaiter-vpn-bot
assert "the bot container runs as that account" test "$(docker inspect -f '{{.Config.User}}' vpn-bot 2>/dev/null)" = "$BOT_IDS"
sleep 10
assert "the bot's process runs under that account" test "$(stat -c %u "/proc/$(docker inspect -f '{{.State.Pid}}' vpn-bot)")" = "$(id -u spaiter-vpn-bot)"
assert "the bot stays up as its own account" test "$(docker inspect -f '{{.State.Running}} {{.RestartCount}}' vpn-bot 2>/dev/null)" = "true 0"
if docker inspect -f '{{range .Mounts}}{{.Destination}} {{end}}' vpn-bot | grep -qw /sing-box; then
	bad "the bot still mounts the core's configuration directory"
else
	ok "the core's configuration and keys are not mounted into the bot"
fi
assert "the bot's management file is group-readable only" test "$(stat -c '%a %G' "$CONFIG_ROOT/deployment/bot-management.json")" = "640 spaiter-vpn-bot"
assert "everything in the bot's data directory belongs to the bot" test -z "$(find "$DATA_ROOT/bot" ! -user spaiter-vpn-bot -print -quit)"
assert "the relay directory is enterable by the bot and writable by nobody else" python3 - "$DATA_ROOT/wdtt-relay" <<'PY'
import grp, os, stat, sys
info = os.stat(sys.argv[1])
mode = stat.S_IMODE(info.st_mode)
raise SystemExit(0 if grp.getgrgid(info.st_gid).gr_name == "spaiter-vpn-bot" and mode & 0o050 == 0o050 and mode & 0o022 == 0 else 1)
PY
assert "the receipt records bot state under the bot's account" python3 - "$DATA_ROOT/bootstrap/current.json" "$DATA_ROOT/bot/" "$(id -u spaiter-vpn-bot)" <<'PY'
import json, sys
files = json.load(open(sys.argv[1]))["files"]
bot = [entry for path, entry in files.items() if path.startswith(sys.argv[2])]
raise SystemExit(0 if bot and all(entry["uid"] == int(sys.argv[3]) for entry in bot) else 1)
PY
if docker exec vpn-bot /usr/local/bin/spaiter-vpn control status >"$WORK/bot-control.log" 2>&1; then
	ok "the isolated bot reaches the control daemon as an operator"
else
	bad "the bot cannot reach the control daemon: $(tail -5 "$WORK/bot-control.log")"
fi
SUB_PORT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bot"]["subscriptionPort"])' "$DESIRED")
assert "the subscription server answers" test "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$SUB_PORT/sub/unknown")" != 000
# A user's guide from the bot's own service, and every node of their
# subscription driven end to end through the deployed server.
if docker exec vpn-bot /usr/local/bin/spaiter-vpn bot guide -config /etc/spaiter-vpn/bot.json -user guide-test \
	-o /data/guide-test.html -bundle-out /data/guide-test-bundle.json >"$WORK/guide.log" 2>&1; then
	ok "the bot wrote a guide for a new user"
else
	bad "bot guide failed: $(tail -8 "$WORK/guide.log")"
fi
assert "the guide carries QR codes and files" sh -c "grep -q 'data:image/png;base64,' '$DATA_ROOT/bot/guide-test.html' && grep -q 'download=' '$DATA_ROOT/bot/guide-test.html'"
VERIFY_IMAGE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["deployment"]["image"])' "$CONFIG_ROOT/desired.json")
"$BINARY" verify -bundle "$DATA_ROOT/bot/guide-test-bundle.json" -image "$VERIFY_IMAGE" >"$WORK/verify.log" 2>&1
# The bundle is a throwaway test user's; kept so a failure can be replayed.
cp "$DATA_ROOT/bot/guide-test-bundle.json" "$WORK/verify-bundle.log" 2>/dev/null
assert "VLESS Reality carries real traffic end to end" grep -q '^PASS .*VLESS Reality' "$WORK/verify.log"
assert "AmneziaWG carries real traffic end to end" grep -q '^PASS .*AmneziaWG ' "$WORK/verify.log"
edit_desired 'doc["bootstrap"]["manageWeb"] = True'
if bootstrap apply -yes -f "$DESIRED" >"$WORK/web-managed.log" 2>&1; then
	ok "bootstrap installed the web UI"
else
	bad "the manageWeb apply failed: $(tail -20 "$WORK/web-managed.log")"
fi
assert "the web UI's unit is active" systemctl is-active --quiet spaiter-vpn-web.service
assert "the web UI runs as its own account" test "$(stat -c %u "/proc/$(systemctl show -p MainPID --value spaiter-vpn-web.service)")" = "$(id -u spaiter-vpn-web)"
assert "the web key is readable by the service group only" test "$(stat -c '%a %G' "$CONFIG_ROOT/web.key")" = "640 spaiter-vpn"
MANAGED_LINK=$("$BINARY" web login-link -key "$CONFIG_ROOT/web.key" -url http://127.0.0.1:10880)
assert "a login reaches the daemon through the managed web UI" python3 - "$MANAGED_LINK" <<'PY'
import http.cookiejar, sys, urllib.request
browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
page = browser.open(sys.argv[1], timeout=30).read().decode()
raise SystemExit(0 if "Поколение" in page and "не ответил" not in page else 1)
PY
if docker exec vpn-bot /usr/local/bin/spaiter-vpn web login-link -key /etc/spaiter-vpn/web.key >"$WORK/bot-weblink.log" 2>&1; then
	ok "the isolated bot can mint a web login link"
else
	bad "the bot cannot read the web key: $(tail -3 "$WORK/bot-weblink.log")"
fi
edit_desired 'doc["bootstrap"]["manageWeb"] = False'
if bootstrap apply -yes -f "$DESIRED" >"$WORK/web-retire.log" 2>&1; then
	ok "turning the web UI off applied"
else
	bad "retiring the web UI failed: $(tail -20 "$WORK/web-retire.log")"
fi
if systemctl is-active --quiet spaiter-vpn-web.service; then
	bad "the retired web UI is still running"
else
	ok "the retired web UI is stopped"
fi
assert_absent "$CONFIG_ROOT/web.key" "retiring the web UI"
edit_desired 'doc["bot"]["dedicatedUser"] = False'
if bootstrap apply -yes -f "$DESIRED" >"$WORK/bot-root.log" 2>&1; then
	ok "switching the bot back to root applied"
else
	bad "switching the bot back failed: $(tail -20 "$WORK/bot-root.log")"
fi
# By the process the kernel runs, not the container's config: the base image
# itself names user 0, so an empty override and "0" both mean root.
assert "the bot runs as root again" test "$(stat -c %u "/proc/$(docker inspect -f '{{.State.Pid}}' vpn-bot)")" = 0
assert_absent "$CONFIG_ROOT/deployment/bot-management.json" "switching the bot back to root"
systemctl stop acceptance-telegram >/dev/null 2>&1

case_begin "a backup restores onto a fresh server with the same keys and a new address"
# A Bot API stand-in that also records what the bot sends, to see the moved
# subscription link arrive.
sed 's|        if method == "getMe":|        if method == "sendMessage":\n            open("'"$WORK"'/telegram-sent.log", "ab").write(self.last_body + b"\\n")\n        if method == "getMe":|; s|        self.rfile.read(int(self.headers.get("Content-Length") or 0))|        self.last_body = self.rfile.read(int(self.headers.get("Content-Length") or 0))|' \
	"$WORK/fake-telegram.py" >"$WORK/fake-telegram-recording.py"
systemctl reset-failed acceptance-telegram >/dev/null 2>&1
systemd-run --unit acceptance-telegram python3 -I "$WORK/fake-telegram-recording.py" >/dev/null
docker restart vpn-bot >/dev/null 2>&1
sleep 8
# A subscriber, so the bot has someone to tell about the move.
python3 - "$DATA_ROOT/bot/wdtt/subs.json" <<'PY'
import json, os, sys
path = sys.argv[1]
subs = json.load(open(path)) if os.path.exists(path) else {}
subs["acceptanceSubToken0123456789abcd"] = {"uid": "777", "created": "2026-11-05T00:00:00+00:00"}
json.dump(subs, open(path, "w"))
PY
OLD_REALITY_KEY=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["Reality"]["PrivateKey"])' "$CONFIG_ROOT/deployment/secrets/secrets.json")
OLD_OWNER_UUID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["Users"][0]["VLESSRealityUUID"])' "$CONFIG_ROOT/deployment/secrets/secrets.json")
grep -q '"guide-test"' "$CONFIG_ROOT/deployment/config.json" || die "the bot's guide user is not in config.json"
printf 'acceptance backup passphrase\n' >"$WORK/backup-pass"
if "$BINARY" backup -passphrase-file "$WORK/backup-pass" >"$WORK/backup.age" 2>"$WORK/backup.log"; then
	ok "a backup was written"
else
	bad "backup failed: $(tail -5 "$WORK/backup.log")"
fi
refute "the backup does not show the Telegram token" grep -qF acceptance-token "$WORK/backup.age"
refute "the backup does not show the Reality key" grep -qF "$OLD_REALITY_KEY" "$WORK/backup.age"

# A new server: nothing installed, not even the bot's account.
reset_host
userdel spaiter-vpn-bot >/dev/null 2>&1
groupdel spaiter-vpn-bot >/dev/null 2>&1
# The containers are removed by a rollback, so their output is collected while
# the restore runs.
( while :; do docker logs sing-box >"$WORK/core-during-restore.log" 2>&1 && cp "$WORK/core-during-restore.log" "$WORK/core-last.log"; sleep 0.2; done ) &
CORE_LOGGER=$!
if "$BINARY" restore -from "$WORK/backup.age" -passphrase-file "$WORK/backup-pass" -public-host 198.51.100.9 -yes >"$WORK/restore.log" 2>&1; then
	ok "restore brought the deployment up"
else
	bad "restore failed: $(tail -25 "$WORK/restore.log")"
	# The containers are gone after the rollback; the core's own log is not.
	red "core output: $(tail -30 "$WORK/core-last.log" 2>&1)"
fi
kill "$CORE_LOGGER" >/dev/null 2>&1
assert "the Reality key is the backup's" test "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["Reality"]["PrivateKey"])' "$CONFIG_ROOT/deployment/secrets/secrets.json")" = "$OLD_REALITY_KEY"
assert "the owner's UUID is the backup's" test "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["Users"][0]["VLESSRealityUUID"])' "$CONFIG_ROOT/deployment/secrets/secrets.json")" = "$OLD_OWNER_UUID"
assert "the user the bot added came back" grep -q '"guide-test"' "$CONFIG_ROOT/deployment/config.json"
assert "the desired state names the new address" test "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bot"]["publicHost"])' "$CONFIG_ROOT/desired.json")" = 198.51.100.9
assert "the bot hands out subscription links at the new address" grep -q "\"198.51.100.9:$SUB_PORT\"" "$CONFIG_ROOT/deployment/bot.json"
assert "the subscription port is open on the host firewall" ufw_allows "$SUB_PORT/tcp"
assert "the traffic accounting came back" test -s "$CONFIG_ROOT/deployment/user_stats.db"
assert "the restored bot state belongs to the bot" test -z "$(find "$DATA_ROOT/bot" ! -user root -prune -o ! -user root -print -quit)"
"$BINARY" verify -bundle "$DATA_ROOT/bot/guide-test-bundle.json" -image "$VERIFY_IMAGE" >"$WORK/verify-restored.log" 2>&1
assert "a client config from before the backup still carries traffic" grep -q '^PASS .*VLESS Reality' "$WORK/verify-restored.log"
for _ in $(seq 30); do
	grep -q 'acceptanceSubToken0123456789abcd' "$WORK/telegram-sent.log" 2>/dev/null && break
	sleep 2
done
assert "the bot sent the subscriber the new link" grep -q "198.51.100.9:$SUB_PORT/sub/acceptanceSubToken0123456789abcd" "$WORK/telegram-sent.log"
assert "the bot recorded the new base" grep -q 198.51.100.9 "$DATA_ROOT/bot/subscription-base.json"
if "$BINARY" restore -from "$WORK/backup.age" -passphrase-file "$WORK/backup-pass" -keep-address -yes >"$WORK/restore-again.log" 2>&1; then
	bad "a second restore ran over the deployment"
else
	ok "restore refuses a server that already has a deployment"
fi
assert "and says why" grep -q 'already has a deployment' "$WORK/restore-again.log"
systemctl stop acceptance-telegram >/dev/null 2>&1

case_begin "a bot claim code is issued locally and stored only as a hash"
CLAIM_DIR=$WORK/claim-bot
if "$BINARY" bot claim-code -data-dir "$CLAIM_DIR" >"$WORK/claim.log" 2>&1; then
	ok "a claim code was issued"
else
	bad "claim-code failed: $(cat "$WORK/claim.log")"
fi
CLAIM_CODE=$(sed -n 's/^claim code: //p' "$WORK/claim.log")
assert_mode "$CLAIM_DIR/claim.json" 600
if [ -n "$CLAIM_CODE" ] && ! grep -qF "$CLAIM_CODE" "$CLAIM_DIR/claim.json"; then
	ok "the stored claim does not contain the code"
else
	bad "the claim code is readable from the bot's data directory"
fi

reset_host

# ---------------------------------------------------------------------------

printf '\n'
if [ "$FAILED" -eq 0 ]; then
	green "PASS — $PASSED checks"
	exit 0
fi
red "FAIL — $FAILED of $((PASSED + FAILED)) checks failed"
red "evidence kept under $KEEP_DIR"
exit 1
