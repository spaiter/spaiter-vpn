#!/usr/bin/env bash
# Diagnostic for the bootstrap suite's "MTProto gives every user their own
# secret" case: installs with the default core, switches to the core under test
# with mtprotoPerUser on (exactly what the suite does) and then prints the
# pieces the suite's assertion compares, one condition per line, so a failure
# names its reason. Disposable host only: it prints the throwaway install's
# MTProto secrets.
#
#   run-on-qemu-vm.sh --binary ./spaiter-vpn --suite test/acceptance/mtproto-diag.sh \
#       --local-image <default image> --local-image <core under test>
set -u -o pipefail
BINARY=${1:-}
CONFIG_ROOT=/etc/spaiter-vpn
WORK=$(mktemp -d /tmp/mtproto-diag.XXXXXX)
[ -n "$BINARY" ] && [ -x "$BINARY" ] || { echo "usage: mtproto-diag.sh /path/to/spaiter-vpn" >&2; exit 2; }
[ "${SPAITER_VPN_ACCEPTANCE:-}" = "i-understand-this-host-is-disposable" ] || { echo "host not marked disposable" >&2; exit 2; }
NEW_CORE=${ACCEPTANCE_EXTRA_IMAGES%% *}
[ -n "$NEW_CORE" ] || { echo "pass the core under test as the second --local-image" >&2; exit 2; }
bootstrap() { "$BINARY" bootstrap "$@"; }
DESIRED=$WORK/desired.json
edit_desired() {
	local script="import json,sys
path=sys.argv[1]
doc=json.load(open(path))
"
	local s; for s in "$@"; do script="$script$s
"; done
	python3 -c "${script}json.dump(doc, open(path,'w'), indent=2)
" "$DESIRED"
}

echo "=== binary: $("$BINARY" version)"
echo "=== install with the default core"
bootstrap state -users owner -o "$DESIRED" >"$WORK/state.log" 2>&1 || { cat "$WORK/state.log"; exit 1; }
echo "default image: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["deployment"]["image"])' "$DESIRED")"
bootstrap apply -yes -f "$DESIRED" >"$WORK/install.log" 2>&1 || { tail -20 "$WORK/install.log"; exit 1; }
grep -q 'self-test: passed' "$WORK/install.log" && echo "self-test: passed on the default core"
SECRETS=$CONFIG_ROOT/deployment/secrets/secrets.json
CONFIG=$CONFIG_ROOT/deployment/config.json
SHARED=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["MTProto"]["Secret"])' "$SECRETS")
echo "shared secret before: $SHARED"
echo "--- mtproto inbound before"
python3 - "$CONFIG" "$SECRETS" <<'PY'
import json, sys
config, secrets = (json.load(open(p)) for p in sys.argv[1:3])
ib = next((i for i in config["inbounds"] if i["type"] == "mtproto"), None)
print(json.dumps({k: ib.get(k) for k in ("tag", "secret", "users")} if ib else None, indent=1))
print("seed users:", [(u["Name"], u.get("MTProtoSecret", "<absent>")) for u in secrets["Users"]])
PY

echo "=== switch to $NEW_CORE with mtprotoPerUser"
cp "$CONFIG_ROOT/desired.json" "$DESIRED"
edit_desired "doc['deployment']['image'] = '$NEW_CORE'" 'doc["deployment"]["mtprotoPerUser"] = True'
if bootstrap apply -yes -f "$DESIRED" >"$WORK/mtproto-users.log" 2>&1; then
	echo "apply: ok"
else
	echo "apply: FAILED"; tail -30 "$WORK/mtproto-users.log"
fi
grep -iE 'mtproto|warning|secret' "$WORK/mtproto-users.log" | head -20 | sed 's/^/  log: /'
echo "--- mtproto inbound after"
python3 - "$CONFIG" "$SECRETS" "$SHARED" <<'PY'
import json, sys
config, secrets = (json.load(open(p)) for p in sys.argv[1:3])
shared = sys.argv[3]
ib = next(i for i in config["inbounds"] if i["type"] == "mtproto")
print(json.dumps({k: ib.get(k) for k in ("tag", "secret", "users")}, indent=1))
users = {u["name"]: u["secret"] for u in ib.get("users") or []}
seeds = {u["Name"]: u.get("MTProtoSecret", "") for u in secrets["Users"]}
print("seed users:", seeds)
print("cond shared survives     :", ib.get("secret") == shared, repr(ib.get("secret")), "vs", repr(shared))
print("cond seeds non-empty     :", bool(seeds))
for name, s in seeds.items():
    print(f"cond seed {name!r} has secret and matches inbound user: {bool(s) and users.get(name) == s} (seed={s!r}, inbound={users.get(name)!r})")
print("cond user secrets unique :", len(set(users.values())) == len(users))
print("cond all start with ee   :", all(v.startswith('ee') for v in users.values()), list(users.values()))
PY
echo "=== core in use"
docker ps --format '{{.Names}} {{.Image}} {{.Status}}'
