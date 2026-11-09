#!/usr/bin/env bash
#
# Generate our own BitTorrent test captures in a fully isolated lab.
#
# WHY THIS EXISTS
# ---------------
# The MSE and mid-transfer fixtures used to come from a third-party university
# project that carried no licence and contained its authors' real residential
# traffic. This script replaces them with captures we own outright.
#
# WHY IT CANNOT TOUCH THE INTERNET
# --------------------------------
# Both clients run in network namespaces joined by a single veth pair. Neither
# namespace is given a default route, so there is no path off the pair at all:
# a stray announce to a public tracker or a DHT bootstrap cannot leave, because
# there is nowhere for it to go. That is a structural guarantee, not a config
# flag, and it is the point of the design. DHT, PEX, LSD, UPnP and NAT-PMP are
# additionally disabled in both clients as defence in depth.
#
# The content is a file of random bytes generated here, so no third party's
# data and no copyrighted material is involved -- not even an Ubuntu ISO.
#
# Peer discovery uses minitracker.py, running inside the seeder namespace.
#
# The two ends are deliberately different implementations (Transmission seeds,
# aria2 leeches) so the captured handshake is a real cross-client MSE
# negotiation rather than one implementation talking to itself.
#
# Requires: root (netns), transmission-daemon, transmission-remote, aria2c,
#           mktorrent, tcpdump, python3.

set -euo pipefail

NS_SEED=btlab-seed
NS_LEECH=btlab-leech
IP_SEED=10.77.0.1
IP_LEECH=10.77.0.2
PEER_PORT=51413
TRACKER_PORT=6969
CONTENT_MB=${CONTENT_MB:-64}
PIECE_LEN=${PIECE_LEN:-18}   # 2^18 = 256 KiB
LOSS=${LOSS:-0.3%}
DELAY=${DELAY:-12ms}

LAB=$(mktemp -d /tmp/btlab.XXXXXX)
OUT=${OUT:-$(cd "$(dirname "$0")/../testdata/pcap/true-positive" && pwd)}
TOOLS=$(cd "$(dirname "$0")" && pwd)

cleanup() {
  set +e
  ip netns pids $NS_SEED  2>/dev/null | xargs -r kill 2>/dev/null
  ip netns pids $NS_LEECH 2>/dev/null | xargs -r kill 2>/dev/null
  sleep 0.5
  ip netns pids $NS_SEED  2>/dev/null | xargs -r kill -9 2>/dev/null
  ip netns pids $NS_LEECH 2>/dev/null | xargs -r kill -9 2>/dev/null
  ip netns del $NS_SEED  2>/dev/null
  ip netns del $NS_LEECH 2>/dev/null
  rm -rf "$LAB"
}
trap cleanup EXIT

echo "== lab dir: $LAB"
echo "== output:  $OUT"

# ---------------------------------------------------------------- namespaces
ip netns del $NS_SEED  2>/dev/null || true
ip netns del $NS_LEECH 2>/dev/null || true
ip netns add $NS_SEED
ip netns add $NS_LEECH

ip link add veth-s type veth peer name veth-l
ip link set veth-s netns $NS_SEED
ip link set veth-l netns $NS_LEECH

ip netns exec $NS_SEED  ip addr add $IP_SEED/30  dev veth-s
ip netns exec $NS_LEECH ip addr add $IP_LEECH/30 dev veth-l
ip netns exec $NS_SEED  ip link set veth-s up
ip netns exec $NS_LEECH ip link set veth-l up
ip netns exec $NS_SEED  ip link set lo up
ip netns exec $NS_LEECH ip link set lo up

# Disable segmentation offload on both ends. Without this, tcpdump on a veth
# records pre-segmentation superframes of up to 64 KiB -- sizes that never
# appear on a real NIC. A detector measured against those gets optimistically
# high per-packet rates, because one superframe carries many BitTorrent
# messages. Offload off means MTU-sized packets, like the wire.
for pair in "$NS_SEED veth-s" "$NS_LEECH veth-l"; do
  set -- $pair
  ip netns exec "$1" ethtool -K "$2" tso off gso off gro off tx off sg off >/dev/null 2>&1 || true
  ip netns exec "$1" ip link set dev "$2" gso_max_size 1500 >/dev/null 2>&1 || true
  ip netns exec "$1" ip link set dev "$2" gro_max_size 1500 >/dev/null 2>&1 || true
done

# Make the traffic look less like a sterile loopback benchmark.
ip netns exec $NS_LEECH tc qdisc add dev veth-l root netem delay "$DELAY" loss "$LOSS" || true

# Prove the isolation rather than asserting it: no default route must exist,
# and an off-link destination must be unreachable.
for ns in $NS_SEED $NS_LEECH; do
  if ip netns exec $ns ip route show default | grep -q .; then
    echo "FATAL: $ns has a default route; refusing to run" >&2
    exit 1
  fi
done
if ip netns exec $NS_LEECH ping -c1 -W1 1.1.1.1 >/dev/null 2>&1; then
  echo "FATAL: $NS_LEECH can reach the internet; refusing to run" >&2
  exit 1
fi
echo "== isolation verified: no default route, 1.1.1.1 unreachable"

# ------------------------------------------------------------------- content
mkdir -p "$LAB/seed" "$LAB/leech" "$LAB/tr-config"
dd if=/dev/urandom of="$LAB/seed/payload.bin" bs=1M count="$CONTENT_MB" status=none
echo "== content: ${CONTENT_MB} MiB of random bytes"

mktorrent -l "$PIECE_LEN" \
  -a "http://$IP_SEED:$TRACKER_PORT/announce" \
  -n payload.bin \
  -o "$LAB/payload.torrent" \
  "$LAB/seed/payload.bin" >/dev/null
transmission-show "$LAB/payload.torrent" | grep -iE "hash|piece" | head -3 | sed "s/^/   torrent: /"

# ------------------------------------------------------------------- tracker
ip netns exec $NS_SEED python3 "$TOOLS/minitracker.py" "$IP_SEED" "$TRACKER_PORT" &
sleep 1

# -------------------------------------------------------------------- seeder
# encryption: 0=prefer-plain 1=prefer-encrypted 2=require-encrypted
cat > "$LAB/tr-config/settings.json" <<JSON
{
  "bind-address-ipv4": "$IP_SEED",
  "dht-enabled": false,
  "download-dir": "$LAB/seed",
  "encryption": 2,
  "incomplete-dir-enabled": false,
  "lpd-enabled": false,
  "peer-port": $PEER_PORT,
  "peer-port-random-on-start": false,
  "pex-enabled": false,
  "port-forwarding-enabled": false,
  "rpc-authentication-required": false,
  "rpc-bind-address": "127.0.0.1",
  "rpc-enabled": true,
  "rpc-port": 9091,
  "rpc-whitelist-enabled": false,
  "utp-enabled": true
}
JSON

ip netns exec $NS_SEED transmission-daemon \
  --config-dir "$LAB/tr-config" --foreground --log-level=error &
sleep 2

ip netns exec $NS_SEED transmission-remote 127.0.0.1:9091 \
  -a "$LAB/payload.torrent" >/dev/null
sleep 1
ip netns exec $NS_SEED transmission-remote 127.0.0.1:9091 -l | sed 's/^/   seeder: /'

# ------------------------------------------------------------------- capture
ip netns exec $NS_LEECH tcpdump -i veth-l -s 0 -w "$LAB/full.pcap" \
  -U "not port $TRACKER_PORT" 2>/dev/null &
TCPDUMP_PID=$!
sleep 1

# -------------------------------------------------------------------- leecher
echo "== leeching"
ip netns exec $NS_LEECH aria2c \
  --dir="$LAB/leech" \
  --bt-require-crypto=true \
  --bt-min-crypto-level=arc4 \
  --enable-dht=false \
  --enable-dht6=false \
  --enable-peer-exchange=false \
  --bt-enable-lpd=false \
  --listen-port=51500 \
  --seed-time=0 \
  --summary-interval=0 \
  --console-log-level=warn \
  --bt-stop-timeout=120 \
  "$LAB/payload.torrent" 2>&1 | tail -5 | sed 's/^/   leecher: /' || true

sleep 2
kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

# -------------------------------------------------------------------- verify
if ! cmp -s "$LAB/seed/payload.bin" "$LAB/leech/payload.bin"; then
  echo "FATAL: transferred file does not match the original" >&2
  exit 1
fi
echo "== transfer verified byte-identical"

# --------------------------------------------------------------------- split
# own_mse_handshake: the start of the session, where the MSE negotiation lives.
# own_mid_transfer:  a slice from the middle, i.e. steady-state piece traffic
#                    with no handshake in it.
TOTAL=$(tcpdump -r "$LAB/full.pcap" 2>/dev/null | wc -l)
echo "== captured $TOTAL packets"

python3 "$TOOLS/split-capture.py" "$LAB/full.pcap" \
  "$OUT/own_mse_handshake.pcap" "$OUT/own_mid_transfer.pcap"

ls -l "$OUT/own_mse_handshake.pcap" "$OUT/own_mid_transfer.pcap"
echo "== done"
