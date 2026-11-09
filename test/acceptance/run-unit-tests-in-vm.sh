#!/usr/bin/env bash
# Runs the Go unit tests, as root, inside a disposable QEMU/KVM virtual machine
# that has what the tests otherwise have to skip or fake: a real Docker with
# compose, a kernel with WireGuard, ufw/nftables/iptables, gpg, logrotate and
# systemd.
#
# Why a VM and not "sudo go test" on the host: the tests that only make sense as
# root create WireGuard interfaces, edit firewall rules and talk to systemd. A
# VM has its own kernel, so none of that can touch the machine it runs on.
#
# The test binaries are compiled here (static, with coverage instrumentation)
# and shipped to the guest, so the guest needs no Go toolchain. Each package's
# binary runs in its own directory of a copy of the source tree, which is where
# `go test` would have run it. Coverage profiles come back to --out.
#
#   usage: run-unit-tests-in-vm.sh [--out DIR] [--mem MB] [--cpus N] [--port P]
#                                  [--only PATTERN] [--keep]
#
# Needs on PATH: go, git, qemu-system-x86_64, qemu-img, cloud-localds, ssh, scp,
# ssh-keygen, curl. On NixOS:
#
#   nix shell nixpkgs#go nixpkgs#qemu nixpkgs#cloud-utils nixpkgs#openssh --command \
#     test/acceptance/run-unit-tests-in-vm.sh

set -eu -o pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
MODULE=github.com/spaiter/spaiter-vpn
OUT=""
ONLY=""
KEEP=0
MEM=${VM_MEMORY:-12288}
CPUS=${VM_CPUS:-8}
PORT=${VM_SSH_PORT:-2244}
DISK=${VM_DISK:-24G}
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/spaiter-vpn-acceptance
IMAGE_URL=${IMAGE_URL:-https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img}
PER_PACKAGE_TIMEOUT=${PER_PACKAGE_TIMEOUT:-20m}

while [ $# -gt 0 ]; do
	case $1 in
	--out) OUT=$2; shift ;;
	--only) ONLY=$2; shift ;;
	--keep) KEEP=1 ;;
	--mem) MEM=$2; shift ;;
	--cpus) CPUS=$2; shift ;;
	--port) PORT=$2; shift ;;
	*) echo "unknown argument $1" >&2; exit 2 ;;
	esac
	shift
done

for tool in go git qemu-system-x86_64 qemu-img cloud-localds ssh scp ssh-keygen curl; do
	command -v "$tool" >/dev/null || { echo "$tool is not on PATH" >&2; exit 2; }
done
[ -w /dev/kvm ] || { echo "/dev/kvm is not writable" >&2; exit 2; }

mkdir -p "$CACHE/runs"
WORK=$(mktemp -d "$CACHE/runs/unit-vm.XXXXXX")
OUT=${OUT:-$WORK/results}
mkdir -p "$OUT"
QEMU_PID=""

# shellcheck disable=SC2317  # invoked from a trap
cleanup() {
	if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
		kill "$QEMU_PID" 2>/dev/null || true
		wait "$QEMU_PID" 2>/dev/null || true
	fi
	if [ "$KEEP" = 1 ]; then
		echo "== kept $WORK (console log, overlay disk, ssh key)"
	else
		# Results may live inside WORK when --out was not given.
		case $OUT in "$WORK"/*) ;; *) rm -rf "$WORK" ;; esac
	fi
}
trap cleanup EXIT

# --- 1. test binaries --------------------------------------------------------
echo "== building the test binaries (static, instrumented)"
BIN=$WORK/tests
mkdir -p "$BIN"
: >"$BIN/index"
cd "$REPO"
while read -r pkg; do
	rel=${pkg#"$MODULE"/}
	[ -n "$ONLY" ] && ! grep -qE "$ONLY" <<<"$rel" && continue
	name=${rel//\//_}
	if CGO_ENABLED=0 go test -c -cover -covermode=atomic -o "$BIN/$name.test" "$pkg" 2>"$WORK/build-$name.log"; then
		printf '%s %s\n' "$name" "$rel" >>"$BIN/index"
	else
		echo "   build failed: $rel (see $WORK/build-$name.log)" >&2
		KEEP=1
	fi
done < <(go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./internal/... ./cmd/...)
echo "   $(wc -l <"$BIN/index") test binaries"

echo "== packing the source tree (tracked files at HEAD)"
git -C "$REPO" archive --format=tar HEAD | gzip -1 >"$WORK/src.tar.gz"

# --- 2. the guest ------------------------------------------------------------
BASE=$CACHE/$(basename "$IMAGE_URL")
if [ ! -f "$BASE" ]; then
	echo "== downloading $(basename "$IMAGE_URL")"
	curl -fL --no-progress-meter -o "$BASE.part" "$IMAGE_URL"
	mv "$BASE.part" "$BASE"
fi

echo "== preparing a throwaway overlay disk"
qemu-img create -f qcow2 -b "$BASE" -F qcow2 "$WORK/root.qcow2" "$DISK" >/dev/null
ssh-keygen -t ed25519 -N '' -C unit-tests -f "$WORK/key" >/dev/null
PUBKEY=$(cat "$WORK/key.pub")

cat >"$WORK/user-data" <<EOF
#cloud-config
users:
  - name: tester
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    ssh_authorized_keys:
      - $PUBKEY
package_update: true
packages:
  - docker.io
  - docker-compose-v2
  - wireguard-tools
  - ufw
  - nftables
  - iptables
  - gnupg
  - logrotate
  - acl
  - python3
runcmd:
  - [systemctl, enable, --now, docker]
  - [modprobe, wireguard]
  # Same order as the acceptance runner: port 22 first, or enabling the
  # firewall drops the ssh session driving the guest.
  - [ufw, allow, 22/tcp]
  - [sed, -i, 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/', /etc/default/ufw]
  - [ufw, --force, enable]
EOF
printf 'instance-id: unit-tests\nlocal-hostname: unit-tests\n' >"$WORK/meta-data"
cloud-localds "$WORK/seed.iso" "$WORK/user-data" "$WORK/meta-data"

echo "== booting the guest (${MEM}MB, ${CPUS} cpus, kvm, ssh on 127.0.0.1:$PORT)"
nice -n 10 qemu-system-x86_64 \
	-enable-kvm -cpu host -m "$MEM" -smp "$CPUS" \
	-display none -serial "file:$WORK/console.log" \
	-device virtio-rng-pci \
	-drive "if=virtio,file=$WORK/root.qcow2,format=qcow2" \
	-drive "if=virtio,file=$WORK/seed.iso,format=raw,media=cdrom" \
	-netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-:22" \
	-device virtio-net-pci,netdev=n0 &
QEMU_PID=$!

COMMON_OPTS=(-i "$WORK/key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
	-o LogLevel=ERROR -o ConnectTimeout=5)
SSH_OPTS=("${COMMON_OPTS[@]}" -p "$PORT")
SCP_OPTS=("${COMMON_OPTS[@]}" -P "$PORT")
# shellcheck disable=SC2029
# -n: the loop below reads the package index from stdin, which ssh would eat.
guest() { ssh -n "${SSH_OPTS[@]}" tester@127.0.0.1 "$@"; }

echo "== waiting for ssh"
for _ in $(seq 1 120); do
	kill -0 "$QEMU_PID" 2>/dev/null || { echo "qemu exited; console tail:" >&2; tail -30 "$WORK/console.log" >&2; exit 1; }
	if guest true 2>/dev/null; then break; fi
	sleep 5
done
guest true || { echo "the guest never accepted ssh" >&2; tail -40 "$WORK/console.log" >&2; exit 1; }

echo "== waiting for cloud-init (packages) to finish"
guest "sudo cloud-init status --wait" || true
guest "sudo docker version >/dev/null && sudo docker compose version >/dev/null && sudo wg --version && sudo ufw status | head -1" || {
	echo "the guest is missing what the tests need:" >&2
	guest "sudo cloud-init status --long; sudo journalctl -u docker --no-pager | tail -20" >&2 || true
	exit 1
}

# --- 3. run ------------------------------------------------------------------
echo "== pushing the test binaries and the source"
scp "${SCP_OPTS[@]}" -r "$BIN" tester@127.0.0.1:/tmp/tests >/dev/null
scp "${SCP_OPTS[@]}" "$WORK/src.tar.gz" tester@127.0.0.1:/tmp/src.tar.gz >/dev/null
guest "sudo rm -rf /src && sudo mkdir -p /src /cov /logs && sudo chmod 1777 /cov /logs && sudo tar -C /src -xzf /tmp/src.tar.gz && sudo chmod -R a+rX /src && sudo chmod 0755 /tmp/tests/*.test"

echo "== running every package as root"
: >"$OUT/summary.txt"
FAILED=0
while read -r name rel; do
	printf '   %-40s ' "$rel"
	set +e
	guest "cd /src/$rel && sudo env SPAITER_REAL_DOCKER=1 SPAITER_REAL_FIREWALL=1 HOME=/root GOFLAGS=-mod=mod timeout $PER_PACKAGE_TIMEOUT /tmp/tests/$name.test -test.count=1 -test.timeout=$PER_PACKAGE_TIMEOUT -test.coverprofile=/cov/$name.out -test.v >/logs/$name.log 2>&1; echo \$? >/logs/$name.rc" 2>/dev/null
	guest "sudo test -r /logs/$name.rc" 2>/dev/null
	rc=$(guest "sudo cat /logs/$name.rc" 2>/dev/null || echo "?")
	set -e
	pct=$(guest "sudo grep -aoE 'coverage: [0-9.]+%' /logs/$name.log | tail -1" 2>/dev/null || true)
	if [ "$rc" = 0 ]; then
		echo "ok   ${pct}"
	else
		echo "FAIL rc=$rc ${pct}"
		FAILED=$((FAILED + 1))
	fi
	printf '%s rc=%s %s\n' "$rel" "$rc" "$pct" >>"$OUT/summary.txt"
done <"$BIN/index"

echo "== collecting profiles and logs into $OUT"
mkdir -p "$OUT/cov" "$OUT/logs"
guest "sudo tar -C / -cf - cov logs" | tar -C "$OUT" -xf -
mv "$OUT/cov" "$OUT/profiles" 2>/dev/null || true

echo "== $FAILED package(s) failed"
[ "$FAILED" -eq 0 ]
