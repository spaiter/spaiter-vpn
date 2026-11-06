#!/usr/bin/env bash
# Runs the bootstrap acceptance suite in a disposable QEMU/KVM virtual machine.
#
# A VM, not a container, and that is a safety requirement rather than a
# preference: the suite's self-test creates a WireGuard interface and the core
# attaches an XDP program to a NIC. A container shares the host kernel, so a bad
# run could replace the XDP program of a deployment running on the host itself.
#
# Nothing is installed on the host and no host interface is created. Networking
# is QEMU's user-mode stack, which gives the guest outbound access and a
# forwarded ssh port on loopback; the base image is cached and the per-run disk
# is a throwaway overlay on top of it.
#
#   usage: run-on-qemu-vm.sh --binary PATH [--suite PATH] [--keep]
#                            [--local-image REF] [--no-docker]
#
# --local-image serves an image from this host's Docker to the guest under its
# own registry name, for when that registry is not reachable from the guest.
# A throwaway TLS registry on the guest's loopback answers for that name, so
# every `docker compose pull` the suite triggers still goes through a real
# registry and a missing tag still fails the way it would in production. The
# registry is a pinned standalone binary, not a container, so it works in a
# guest that has no Docker yet.
#
# --no-docker leaves Docker out of the guest, for the suite that proves
# bootstrap.installDocker (docker-install-acceptance.sh).
#
# VM_ACCEL may be `kvm` (default) or `tcg`. TCG is slower, but is useful on a
# host whose KVM vCPUs fail to wake from halt or where /dev/kvm is unavailable.
#
# On NixOS, or anywhere else without a permanent install:
#
#   nix shell nixpkgs#qemu nixpkgs#cloud-utils --command \
#     ./run-on-qemu-vm.sh --binary ./spaiter-vpn

set -eu -o pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BINARY=""
SUITE=$HERE/bootstrap-acceptance.sh
KEEP=0
LOCAL_IMAGES=()
NO_DOCKER=0
# The CNCF distribution registry, pinned by version and by the digest its own
# release publishes.
REGISTRY_URL=https://github.com/distribution/distribution/releases/download/v2.8.3/registry_2.8.3_linux_amd64.tar.gz
REGISTRY_SHA256=b1f750ecbe09f38e2143e22c61a25e3da2afe1510d9522859230b480e642ceff
MEM=${VM_MEMORY:-4096}
CPUS=${VM_CPUS:-4}
PORT=${VM_SSH_PORT:-2242}
DISK=${VM_DISK:-24G}
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/spaiter-vpn-acceptance
IMAGE_URL=${IMAGE_URL:-https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img}
ACCEL=${VM_ACCEL:-kvm}

while [ $# -gt 0 ]; do
	case $1 in
	--binary) BINARY=$2; shift ;;
	--suite) SUITE=$2; shift ;;
	--keep) KEEP=1 ;;
	--local-image) LOCAL_IMAGES+=("$2"); shift ;;
	--no-docker) NO_DOCKER=1 ;;
	--mem) MEM=$2; shift ;;
	--cpus) CPUS=$2; shift ;;
	--port) PORT=$2; shift ;;
	*) echo "unknown argument $1" >&2; exit 2 ;;
	esac
	shift
done

[ -n "$BINARY" ] || { echo "--binary is required" >&2; exit 2; }
[ -f "$BINARY" ] || { echo "$BINARY does not exist" >&2; exit 2; }
[ -f "$SUITE" ] || { echo "$SUITE does not exist" >&2; exit 2; }
for image in "${LOCAL_IMAGES[@]}"; do
	case $image in
	*/*) ;;
	*) echo "--local-image needs a registry-qualified reference, got $image" >&2; exit 2 ;;
	esac
	docker image inspect "$image" >/dev/null 2>&1 || { echo "$image is not in this host's Docker" >&2; exit 2; }
done
for tool in qemu-system-x86_64 qemu-img cloud-localds ssh scp ssh-keygen curl; do
	command -v "$tool" >/dev/null || { echo "$tool is not on PATH" >&2; exit 2; }
done
case $ACCEL in
kvm)
	[ -w /dev/kvm ] || { echo "/dev/kvm is not writable; use VM_ACCEL=tcg or enable hardware virtualisation" >&2; exit 2; }
	QEMU_ACCEL=(-enable-kvm -cpu host)
	;;
tcg)
	# The comma belongs to qemu's option value, not to the array.
	# shellcheck disable=SC2054
	QEMU_ACCEL=(-accel tcg,thread=multi -cpu max)
	;;
*) echo "VM_ACCEL must be kvm or tcg, got $ACCEL" >&2; exit 2 ;;
esac

mkdir -p "$CACHE"
BASE=$CACHE/$(basename "$IMAGE_URL")
if [ ! -f "$BASE" ]; then
	echo "== downloading $(basename "$IMAGE_URL")"
	# No progress meter: this log is read with tail, and a carriage-return
	# progress bar fills it with thousands of partial lines.
	curl -fL --no-progress-meter -o "$BASE.part" "$IMAGE_URL"
	mv "$BASE.part" "$BASE"
fi

# On disk, beside the cached image, not in /tmp: the overlay disk grows by
# gigabytes over a run, and on a host where /tmp is a small tmpfs it fills that
# filesystem — and the memory behind it — until the guest's writes fail.
mkdir -p "$CACHE/runs"
WORK=$(mktemp -d "$CACHE/runs/acceptance-vm.XXXXXX")
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
		rm -rf "$WORK"
	fi
}
trap cleanup EXIT

echo "== preparing a throwaway overlay disk"
qemu-img create -f qcow2 -b "$BASE" -F qcow2 "$WORK/root.qcow2" "$DISK" >/dev/null

ssh-keygen -t ed25519 -N '' -C acceptance -f "$WORK/key" >/dev/null
PUBKEY=$(cat "$WORK/key.pub")

# cloud-init installs what the suite needs at first boot, so the run does not
# depend on an ssh round trip for provisioning.
DOCKER_PACKAGES="  - docker.io
  - docker-compose-v2
"
DOCKER_RUNCMD="  - [systemctl, enable, --now, docker]
"
if [ "$NO_DOCKER" = 1 ]; then
	DOCKER_PACKAGES=""
	DOCKER_RUNCMD=""
fi
cat >"$WORK/user-data" <<EOF
#cloud-config
users:
  - name: acceptance
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    ssh_authorized_keys:
      - $PUBKEY
package_update: true
packages:
$DOCKER_PACKAGES  - wireguard-tools
  - ufw
runcmd:
$DOCKER_RUNCMD  - [modprobe, wireguard]
  # UFW is brought up so the suite exercises the firewall path against a real
  # rule set instead of skipping it. The order is the whole hazard: enabling it
  # applies a default deny on incoming, which drops the ssh session this runner
  # drives the guest through, so port 22 is opened FIRST. It also doubles as the
  # rule the suite checks is never touched — one the operator owns and the
  # deployment never wants.
  - [ufw, allow, 22/tcp]
  # ACCEPT on forward, matching how a host that also runs Docker has to be set
  # up: the default DROP breaks container networking, and finding that out
  # through a deployment that starts and serves nobody is the failure this
  # whole suite exists to catch.
  - [sed, -i, 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/', /etc/default/ufw]
  - [ufw, --force, enable]
EOF
printf 'instance-id: acceptance\nlocal-hostname: acceptance\n' >"$WORK/meta-data"
cloud-localds "$WORK/seed.iso" "$WORK/user-data" "$WORK/meta-data"

echo "== booting the guest (${MEM}MB, ${CPUS} cpus, $ACCEL acceleration, ssh on 127.0.0.1:$PORT)"
qemu-system-x86_64 \
	"${QEMU_ACCEL[@]}" -m "$MEM" -smp "$CPUS" \
	-display none -serial "file:$WORK/console.log" \
	-monitor "unix:$WORK/monitor.sock,server=on,wait=off" \
	-device virtio-rng-pci \
	-drive "if=virtio,file=$WORK/root.qcow2,format=qcow2" \
	-drive "if=virtio,file=$WORK/seed.iso,format=raw,media=cdrom" \
	-netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-:22" \
	-device virtio-net-pci,netdev=n0 &
QEMU_PID=$!

# Two arrays, because scp spells the port -P while ssh spells it -p, and -p to
# scp means "preserve timestamps" — so sharing one array makes scp read the port
# number as a source filename.
COMMON_OPTS=(-i "$WORK/key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
	-o LogLevel=ERROR -o ConnectTimeout=5)
SSH_OPTS=("${COMMON_OPTS[@]}" -p "$PORT")
SCP_OPTS=("${COMMON_OPTS[@]}" -P "$PORT")
# Every command passed here is a literal written in this script, so the
# client-side expansion shellcheck warns about is the intended one.
# shellcheck disable=SC2029
guest() { ssh "${SSH_OPTS[@]}" acceptance@127.0.0.1 "$@"; }

echo "== waiting for ssh"
for _ in $(seq 1 120); do
	kill -0 "$QEMU_PID" 2>/dev/null || { echo "qemu exited; console tail:" >&2; tail -30 "$WORK/console.log" >&2; exit 1; }
	if guest true 2>/dev/null; then break; fi
	sleep 5
done
guest true || { echo "the guest never accepted ssh; console tail:" >&2; tail -40 "$WORK/console.log" >&2; exit 1; }

echo "== waiting for cloud-init to finish"
guest "sudo cloud-init status --wait" || true
if [ "$NO_DOCKER" = 1 ]; then
	if guest "command -v docker" >/dev/null 2>&1; then
		echo "the guest has Docker although --no-docker was given" >&2
		exit 1
	fi
else
	# Through sudo: the unprivileged user is deliberately not in the docker
	# group, and the suite runs as root anyway. Checking without sudo reports a
	# daemon that is running perfectly as missing.
	guest "sudo docker version >/dev/null && sudo docker compose version >/dev/null" || {
		echo "Docker did not come up in the guest:" >&2
		guest "sudo cloud-init status --long; sudo journalctl -u docker --no-pager | tail -20" >&2 || true
		exit 1
	}
fi

if [ "${#LOCAL_IMAGES[@]}" -gt 0 ]; then
	REG_TARBALL=$CACHE/$(basename "$REGISTRY_URL")
	if [ ! -f "$REG_TARBALL" ]; then
		echo "== downloading $(basename "$REGISTRY_URL")"
		curl -fL --no-progress-meter -o "$REG_TARBALL.part" "$REGISTRY_URL"
		mv "$REG_TARBALL.part" "$REG_TARBALL"
	fi
	echo "$REGISTRY_SHA256  $REG_TARBALL" | sha256sum -c --quiet - || { echo "$REG_TARBALL does not match its pinned digest" >&2; exit 1; }
	scp "${SCP_OPTS[@]}" "$REG_TARBALL" "$HERE/push-oci.py" acceptance@127.0.0.1:/tmp/ >/dev/null
	guest "sudo mkdir -p /opt/acceptance-registry && sudo tar -C /opt/acceptance-registry -xzf /tmp/$(basename "$REG_TARBALL") registry"
fi
# One loopback registry per registry name, each answering for that name with
# its own certificate, so an image keeps the exact reference the suite uses.
SERVED_REGISTRIES=" "
for image in "${LOCAL_IMAGES[@]}"; do
	REG_HOSTPORT=${image%%/*}
	REG_NAME=${REG_HOSTPORT%%:*}
	REG_PORT=443
	case $REG_HOSTPORT in *:*) REG_PORT=${REG_HOSTPORT##*:} ;; esac
	REG_REST=${image#*/}
	REG_REPO=${REG_REST%:*}
	REG_TAG=${REG_REST##*:}
	REG_DIR=/opt/acceptance-registry/$REG_NAME-$REG_PORT
	if [ "${SERVED_REGISTRIES#* $REG_HOSTPORT }" = "$SERVED_REGISTRIES" ]; then
		SERVED_REGISTRIES="$SERVED_REGISTRIES$REG_HOSTPORT "
		guest "set -e
			sudo mkdir -p $REG_DIR/data /etc/docker/certs.d/$REG_HOSTPORT
			sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \\
				-subj /CN=$REG_NAME -addext subjectAltName=DNS:$REG_NAME \\
				-keyout $REG_DIR/key.pem -out $REG_DIR/cert.pem 2>/dev/null
			sudo cp $REG_DIR/cert.pem /etc/docker/certs.d/$REG_HOSTPORT/ca.crt
			printf '127.0.0.1 %s\\n' '$REG_NAME' | sudo tee -a /etc/hosts >/dev/null
			printf '%s\\n' 'version: 0.1' 'storage:' '  filesystem:' '    rootdirectory: $REG_DIR/data' \\
				'http:' '  addr: 127.0.0.1:$REG_PORT' '  tls:' '    certificate: $REG_DIR/cert.pem' '    key: $REG_DIR/key.pem' |
				sudo tee $REG_DIR/config.yml >/dev/null
			sudo systemd-run --unit acceptance-registry-$REG_PORT --property Restart=always /opt/acceptance-registry/registry serve $REG_DIR/config.yml >/dev/null
			for _ in \$(seq 1 30); do curl -fsS --cacert $REG_DIR/cert.pem https://$REG_NAME:$REG_PORT/v2/ >/dev/null 2>&1 && break; sleep 1; done"
	fi
	echo "== serving $image to the guest from a loopback registry"
	docker save "$image" -o "$WORK/image.tar"
	scp "${SCP_OPTS[@]}" "$WORK/image.tar" acceptance@127.0.0.1:/tmp/image.tar >/dev/null
	guest "python3 -I /tmp/push-oci.py /tmp/image.tar https://$REG_NAME:$REG_PORT '$REG_REPO' '$REG_TAG' $REG_DIR/cert.pem && rm -f /tmp/image.tar"
done
# The suite learns the extra images it may switch to.
EXTRA_IMAGES="${LOCAL_IMAGES[*]:1}"

echo "== pushing the binary and the suite"
scp "${SCP_OPTS[@]}" "$BINARY" acceptance@127.0.0.1:/tmp/spaiter-vpn >/dev/null
scp "${SCP_OPTS[@]}" "$SUITE" acceptance@127.0.0.1:/tmp/bootstrap-acceptance.sh >/dev/null
guest "chmod 0755 /tmp/spaiter-vpn /tmp/bootstrap-acceptance.sh"

# The registry name resolves publicly; a guest behind QEMU's user-mode stack
# reaches it through the host's resolver and routing. Override only if that path
# does not exist on your network.
if [ -n "${REGISTRY_HOST:-}" ] && [ -n "${REGISTRY_LAN_ADDRESS:-}" ]; then
	echo "== mapping $REGISTRY_HOST to $REGISTRY_LAN_ADDRESS in the guest"
	guest "printf '%s %s\n' '$REGISTRY_LAN_ADDRESS' '$REGISTRY_HOST' | sudo tee -a /etc/hosts >/dev/null"
fi

echo "== running the suite"
set +e
guest "sudo env SPAITER_VPN_ACCEPTANCE=i-understand-this-host-is-disposable ACCEPTANCE_EXTRA_IMAGES='${EXTRA_IMAGES:-}' /tmp/bootstrap-acceptance.sh /tmp/spaiter-vpn"
RC=$?
set -e

if [ "$RC" -ne 0 ]; then
	echo "== collecting the evidence the suite kept"
	guest "sudo tar -C /var/tmp -cf - acceptance-evidence 2>/dev/null" >"$WORK/evidence.tar" || true
	if [ -s "$WORK/evidence.tar" ]; then
		mkdir -p "$WORK/evidence" && tar -C "$WORK/evidence" -xf "$WORK/evidence.tar"
		echo "   evidence: $WORK/evidence"
		KEEP=1
	fi
fi

echo "== powering the guest off"
guest "sudo poweroff" >/dev/null 2>&1 || true
for _ in $(seq 1 20); do kill -0 "$QEMU_PID" 2>/dev/null || break; sleep 1; done

exit "$RC"
