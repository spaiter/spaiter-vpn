#!/usr/bin/env bash
# Runs the bootstrap acceptance suite in a disposable LXD virtual machine.
#
# A VM, not a container, and that is not a preference: the suite's self-test
# creates a real WireGuard interface and the core attaches an XDP program to a
# real NIC. A container would share this machine's kernel, which means a bad
# test run could replace the XDP program of the deployment running here.
#
#   usage: run-on-lxd-vm.sh [--keep] [--name NAME] [--image IMAGE]
#
# VM_MEMORY overrides the guest's memory limit; the default is deliberately
# modest so this can run on a host that is already busy.
#
# What it needs from the host, and nothing more: an initialised LXD with a
# storage pool and a network. It does NOT initialise LXD — doing that creates a
# bridge and a storage pool on the machine you are sitting on, which is an
# operator's decision, not a test script's.

set -eu -o pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
NAME=bootstrap-acceptance
KEEP=0
IMAGE=ubuntu:24.04

while [ $# -gt 0 ]; do
	case $1 in
	--keep) KEEP=1 ;;
	--name) NAME=$2; shift ;;
	--image) IMAGE=$2; shift ;;
	*) echo "unknown argument $1" >&2; exit 2 ;;
	esac
	shift
done

command -v lxc >/dev/null || { echo "lxc is not installed" >&2; exit 2; }
if ! lxc storage list >/dev/null 2>&1; then
	cat >&2 <<'MSG'
LXD does not answer. Initialise it deliberately, on a machine where adding a
bridge and a storage pool is acceptable:

  sudo lxd init

Then re-run this script.
MSG
	exit 2
fi

# A static binary, because the target has no Go toolchain and should not need
# one: what is being tested is the artifact an operator downloads.
BIN=$(mktemp /tmp/spaiter-vpn-acceptance.XXXXXX)
trap 'rm -f "$BIN"' EXIT
echo "== building a static binary"
( cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BIN" ./cmd/spaiter-vpn )

# shellcheck disable=SC2317  # invoked from a trap
cleanup_vm() {
	if [ "$KEEP" = 1 ]; then
		echo "== keeping $NAME; delete it with: lxc delete --force $NAME"
		return
	fi
	echo "== deleting $NAME"
	lxc delete --force "$NAME" >/dev/null 2>&1 || true
}

lxc delete --force "$NAME" >/dev/null 2>&1 || true
echo "== launching $NAME from $IMAGE"
lxc launch "$IMAGE" "$NAME" --vm \
	-c limits.cpu=2 -c "limits.memory=${VM_MEMORY:-2GiB}" -d root,size=20GiB >/dev/null
trap 'cleanup_vm' EXIT

echo "== waiting for the guest agent and cloud-init"
for _ in $(seq 1 120); do
	if lxc exec "$NAME" -- cloud-init status --wait >/dev/null 2>&1; then break; fi
	sleep 5
done
lxc exec "$NAME" -- true || { echo "the VM never became reachable" >&2; exit 1; }

# The registry the desired state names resolves to this site's public address,
# and a DS-Lite line has no hairpin NAT, so a guest on the LAN cannot reach it
# by name. Pointing the name at the reverse proxy's LAN address keeps the TLS
# name intact while skipping the round trip that cannot happen.
if [ -n "${REGISTRY_LAN_ADDRESS:-}" ] && [ -n "${REGISTRY_HOST:-}" ]; then
	echo "== mapping $REGISTRY_HOST to $REGISTRY_LAN_ADDRESS inside the VM"
	lxc exec "$NAME" -- sh -c "printf '%s %s\n' '$REGISTRY_LAN_ADDRESS' '$REGISTRY_HOST' >> /etc/hosts"
fi

echo "== installing Docker Engine and the Compose plugin"
lxc exec "$NAME" -- sh -c '
	set -e
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y -qq docker.io docker-compose-v2 wireguard-tools >/dev/null
	systemctl enable --now docker >/dev/null
	modprobe wireguard
'

echo "== pushing the binary and the suite"
lxc file push "$BIN" "$NAME/usr/local/bin/spaiter-vpn" --mode 0755 >/dev/null
lxc file push "$HERE/bootstrap-acceptance.sh" "$NAME/root/bootstrap-acceptance.sh" --mode 0755 >/dev/null

echo "== running the suite"
set +e
lxc exec "$NAME" --env SPAITER_VPN_ACCEPTANCE=i-understand-this-host-is-disposable -- \
	/root/bootstrap-acceptance.sh /usr/local/bin/spaiter-vpn
RC=$?
set -e
exit "$RC"
