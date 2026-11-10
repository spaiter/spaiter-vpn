#!/usr/bin/env bash
# Goroutine-leak probe for a core image.
#
# Runs ON a disposable host, as root, through run-on-qemu-vm.sh --suite. It
# installs a VPN with the core image under test, turns that core's debug
# listener on, drives the live self-test through it a few times and fetches the
# goroutineleak profile (runtime/pprof, generally available since Go 1.27:
# goroutines blocked on a primitive no runnable goroutine can reach) before and
# after the traffic. The profiles are printed in full on stdout, which the
# runner streams, and kept under /var/tmp/acceptance-evidence as well.
#
#   run-on-qemu-vm.sh --binary ./spaiter-vpn --suite test/acceptance/goroutineleak-probe.sh \
#       --local-image <the image the binary installs by default> \
#       --local-image <the core image to probe>
#
# The second --local-image is the one probed: the runner hands every image but
# the first to the suite in ACCEPTANCE_EXTRA_IMAGES, exactly as it does for the
# bootstrap suite's "newer core" case.
set -u -o pipefail
BINARY=${1:-}
CONFIG_ROOT=/etc/spaiter-vpn
DEBUG_LISTEN=127.0.0.1:9091
WORK=$(mktemp -d /tmp/goroutineleak-probe.XXXXXX)
EVIDENCE=/var/tmp/acceptance-evidence/goroutineleak
PASSED=0
FAILED=0

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
die() { red "FATAL: $*"; exit 2; }
ok() { PASSED=$((PASSED + 1)); green "  ok: $*"; }
bad() { FAILED=$((FAILED + 1)); red "  FAIL: $*"; }
assert() { local what=$1; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }

[ -n "$BINARY" ] && [ -x "$BINARY" ] || die "usage: goroutineleak-probe.sh /path/to/spaiter-vpn"
[ "$(id -u)" = 0 ] || die "must run as root"
[ "${SPAITER_VPN_ACCEPTANCE:-}" = "i-understand-this-host-is-disposable" ] ||
	die "refusing to install on a host not marked disposable"
CORE=${ACCEPTANCE_EXTRA_IMAGES%% *}
[ -n "$CORE" ] || die "pass the core image to probe as the second --local-image"
mkdir -p "$EVIDENCE"

bootstrap() { "$BINARY" bootstrap "$@"; }
# profile <name> <query> <out>: fetches one pprof profile from the core's debug
# listener; the exit status is curl's, the HTTP status is checked by the caller.
profile() {
	curl -sS -m 60 -o "$3" -w '%{http_code}' "http://$DEBUG_LISTEN/debug/pprof/$1?$2"
}
# The core refuses this profile without force=1: it marks what it reports as leaked for good,
# and the awg endpoint's gVisor stack always looks leaked to it (its processors park in
# pkg/sleep.(*Sleeper), whose waker the GC cannot see), so the next packet that wakes one is a
# fatal "bad g->status in ready". Forced here because this host is disposable. Expect the stacks
# through sleep.(*Sleeper).Fetch from tcp.(*processor).start -- 16 of them, constant -- and
# treat anything else as a finding.
total_of() { sed -n '1s/.*total \([0-9]*\).*/\1/p' "$1"; }

printf '\n=== install with %s\n' "$CORE"
DESIRED=$WORK/desired.json
bootstrap state -users owner -o "$DESIRED" >"$WORK/state.log" 2>&1 || die "state failed: $(cat "$WORK/state.log")"
python3 - "$DESIRED" "$CORE" <<'PY'
import json, sys
path, image = sys.argv[1:3]
doc = json.load(open(path))
doc["deployment"]["image"] = image
json.dump(doc, open(path, "w"), indent=2)
PY
if bootstrap apply -yes -f "$DESIRED" >"$WORK/install.log" 2>&1; then
	ok "apply completed on $CORE"
else
	bad "apply failed: $(tail -20 "$WORK/install.log")"
	cp -a "$WORK"/*.log "$EVIDENCE/"
	exit 1
fi
assert "the live self-test passed on the new core" grep -q 'self-test: passed' "$WORK/install.log"

printf '\n=== turn the debug listener on\n'
CONFIG=$CONFIG_ROOT/deployment/config.json
python3 - "$CONFIG" "$DEBUG_LISTEN" <<'PY'
import json, os, sys
path, listen = sys.argv[1:3]
doc = json.load(open(path))
doc.setdefault("experimental", {})["debug"] = {"listen": listen}
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(doc, f, indent=2)
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY
docker compose -f "$CONFIG_ROOT/deployment/docker-compose.yml" up -d --force-recreate >"$WORK/recreate.log" 2>&1 ||
	die "recreate failed: $(cat "$WORK/recreate.log")"
for _ in $(seq 1 60); do
	curl -sf -m 2 "http://$DEBUG_LISTEN/debug/memory" >"$WORK/memory-0.json" 2>/dev/null && break
	sleep 1
done
assert "the debug listener answers" test -s "$WORK/memory-0.json"
docker exec "$(docker compose -f "$CONFIG_ROOT/deployment/docker-compose.yml" ps -q | head -1)" sing-box version 2>/dev/null | head -2 | sed 's/^/  /'

printf '\n=== profiles before traffic\n'
code=$(profile goroutineleak 'debug=1&force=1' "$WORK/goroutineleak-0.txt")
assert "goroutineleak profile is served (HTTP $code)" test "$code" = 200
code=$(profile goroutine debug=1 "$WORK/goroutine-0.txt")
assert "goroutine profile is served (HTTP $code)" test "$code" = 200
echo "  goroutines: $(total_of "$WORK/goroutine-0.txt"), leaked: $(total_of "$WORK/goroutineleak-0.txt")"

printf '\n=== traffic: the self-test, three times\n'
for i in 1 2 3; do
	if "$BINARY" selftest -config "$CONFIG" >"$WORK/selftest-$i.log" 2>&1; then
		ok "self-test $i passed"
	else
		bad "self-test $i failed: $(tail -5 "$WORK/selftest-$i.log")"
	fi
done
sleep 5

printf '\n=== profiles after traffic\n'
code=$(profile goroutineleak 'debug=1&force=1' "$WORK/goroutineleak-1.txt")
assert "goroutineleak profile is served (HTTP $code)" test "$code" = 200
code=$(profile goroutine debug=1 "$WORK/goroutine-1.txt")
assert "goroutine profile is served (HTTP $code)" test "$code" = 200
profile goroutineleak 'debug=0&force=1' "$WORK/goroutineleak-1.pb.gz" >/dev/null
profile goroutine debug=0 "$WORK/goroutine-1.pb.gz" >/dev/null
curl -sf -m 5 "http://$DEBUG_LISTEN/debug/memory" >"$WORK/memory-1.json" 2>/dev/null
echo "  goroutines: $(total_of "$WORK/goroutine-1.txt"), leaked: $(total_of "$WORK/goroutineleak-1.txt")"

printf '\n=== goroutineleak after traffic (debug=1, full)\n'
cat "$WORK/goroutineleak-1.txt"
printf '\n=== memory after traffic\n'
cat "$WORK/memory-1.json"
printf '\n=== goroutine profile after traffic, stacks with the highest counts\n'
grep -E '^[0-9]+ @' "$WORK/goroutine-1.txt" | sort -rn | head -12

cp -a "$WORK"/* "$EVIDENCE/"
printf '\n=== binary profiles, base64 (go tool pprof reads them)\n'
for f in goroutineleak-1.pb.gz goroutine-1.pb.gz; do
	printf -- '--- %s\n' "$f"
	base64 -w0 "$WORK/$f"
	printf '\n'
done

printf '\n%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" = 0 ]
