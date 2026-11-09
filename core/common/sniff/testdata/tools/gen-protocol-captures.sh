#!/usr/bin/env bash
#
# Generate owned fixtures for the BitTorrent sub-protocols that had no test
# capture of their own: LSD (BEP 14), UDP tracker (BEP 15), the extension
# protocol and ut_metadata (BEP 10 / BEP 9), FAST (BEP 6), PEX (BEP 11),
# uTP (BEP 29), DHT (BEP 5) and IPv6 peer traffic.
#
# Usage: gen-protocol-captures.sh [scenario ...]      (default: all)
# Scenarios: plaintext lsd udptracker utp dht ipv6 pex msebulk
#
# ISOLATION
# ---------
# Same guarantee as gen-own-captures.sh and for the same reason: every client
# runs in a network namespace, none of which is given a default route, so
# nothing can leave the lab. A stray announce or DHT bootstrap has nowhere to
# go. The script asserts this before doing anything and aborts if it does not
# hold. Content is locally generated random bytes.
#
# Topology: a switch namespace holding a bridge, plus three peer namespaces.
# The tracker runs in the switch namespace.
#
#   btlab-p1 (10.77.0.1, fd00:77::1) ─┐
#   btlab-p2 (10.77.0.2, fd00:77::2) ─┼─ br0 in btlab-sw (10.77.0.254)
#   btlab-p3 (10.77.0.3, fd00:77::3) ─┘
#
# Requires: root, transmission-daemon, transmission-remote, aria2c, mktorrent,
#           tcpdump, python3, ethtool, iptables.

set -euo pipefail

SW=btlab-sw
PEERS=3
NET4=10.77.0
NET6=fd00:77::
TRACKER4=10.77.0.254
TRACKER_PORT=6969
CONTENT_MB=${CONTENT_MB:-32}
PIECE_LEN=${PIECE_LEN:-17}      # 2^17 = 128 KiB -> more pieces, more messages

TOOLS=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$(cd "$TOOLS/../testdata/pcap/true-positive" && pwd)}
LAB=$(mktemp -d /tmp/btproto.XXXXXX)

SCENARIOS=("$@")
if [ ${#SCENARIOS[@]} -eq 0 ]; then
  SCENARIOS=(plaintext lsd udptracker utp dht ipv6 pex)
fi

say() { echo "== $*"; }

ns()   { ip netns exec "$1" "${@:2}"; }
pexec() { ns "btlab-p$1" "${@:2}"; }

lab_down() {
  set +e
  for i in $(seq 1 $PEERS); do
    ip netns pids "btlab-p$i" 2>/dev/null | xargs -r kill -9 2>/dev/null
    ip netns del "btlab-p$i" 2>/dev/null
  done
  ip netns pids $SW 2>/dev/null | xargs -r kill -9 2>/dev/null
  ip netns del $SW 2>/dev/null
  set -e
}

cleanup() {
  lab_down
  if [ -n "${KEEP_LAB:-}" ]; then
    echo "== KEEP_LAB set, leaving $LAB in place for inspection"
  else
    rm -rf "$LAB"
  fi
}
trap cleanup EXIT

lab_up() {
  lab_down
  ip netns add $SW
  ns $SW ip link add br0 type bridge
  # Disable multicast snooping. It is on by default, and with no IGMP querier
  # on the segment the bridge filters multicast instead of flooding it -- which
  # silently kills LSD (BEP 14), whose announces go to 239.192.152.143:6771.
  # The first LSD run captured nothing but ICMPv6 router solicitations because
  # of this.
  ns $SW ip link set br0 type bridge mcast_snooping 0 || true
  ns $SW ip link set br0 up
  ns $SW ip link set lo up
  ns $SW ip addr add $TRACKER4/24 dev br0
  ns $SW ip addr add ${NET6}254/64 dev br0 nodad

  for i in $(seq 1 $PEERS); do
    ip netns add "btlab-p$i"
    ip link add "vp$i" type veth peer name "vb$i"
    ip link set "vp$i" netns "btlab-p$i"
    ip link set "vb$i" netns $SW
    ns $SW ip link set "vb$i" master br0
    ns $SW ip link set "vb$i" up
    pexec $i ip link set lo up
    pexec $i ip addr add "$NET4.$i/24" dev "vp$i"
    pexec $i ip addr add "${NET6}$i/64" dev "vp$i" nodad
    pexec $i ip link set "vp$i" up
    # Multicast needs an explicit route, because these namespaces deliberately
    # have no default route. Transmission's LPD joins the group with
    # IP_ADD_MEMBERSHIP and an unspecified interface, so the kernel consults
    # the routing table for 239.192.152.143 -- finds nothing -- and the join
    # fails with ENODEV ("Couldn't initialize LPD: No such device"). In other
    # words the isolation itself broke LSD. These are link-scoped routes: they
    # select the veth for multicast and provide no path off the segment, so
    # the isolation assertions below still hold.
    pexec $i ip route add 224.0.0.0/4 dev "vp$i" 2>/dev/null || true
    pexec $i ip -6 route add ff00::/8 dev "vp$i" 2>/dev/null || true
    # Offload off: a veth otherwise hands tcpdump pre-segmentation superframes
    # of up to 64 KiB, sizes that never occur on a real NIC and that flatter a
    # per-packet detector.
    pexec $i ethtool -K "vp$i" tso off gso off gro off tx off sg off >/dev/null 2>&1 || true
    pexec $i ip link set dev "vp$i" gso_max_size 1500 >/dev/null 2>&1 || true
    ns $SW ethtool -K "vb$i" tso off gso off gro off tx off sg off >/dev/null 2>&1 || true
  done

  # Isolation is the whole point, so prove it instead of trusting it.
  for n in $SW $(for i in $(seq 1 $PEERS); do echo "btlab-p$i"; done); do
    if ns "$n" ip route show default | grep -q .; then
      echo "FATAL: $n has a default route; refusing to run" >&2; exit 1
    fi
    if ns "$n" ip -6 route show default | grep -q .; then
      echo "FATAL: $n has an IPv6 default route; refusing to run" >&2; exit 1
    fi
  done
  if pexec 1 ping -c1 -W1 1.1.1.1 >/dev/null 2>&1; then
    echo "FATAL: lab can reach the internet; refusing to run" >&2; exit 1
  fi
  say "isolation verified (no default route v4/v6, 1.1.1.1 unreachable)"
}

make_content() {
  mkdir -p "$LAB/content"
  [ -f "$LAB/content/payload.bin" ] || \
    dd if=/dev/urandom of="$LAB/content/payload.bin" bs=1M count="$CONTENT_MB" status=none
}

# make_torrent <out.torrent> [announce-url|none] [extra mktorrent args...]
make_torrent() {
  local out=$1 announce=$2; shift 2
  local args=(-l "$PIECE_LEN" -n payload.bin -o "$out")
  [ "$announce" != "none" ] && args+=(-a "$announce")
  mktorrent "${args[@]}" "$@" "$LAB/content/payload.bin" >/dev/null
}

# tr_config <dir> <bind4> <port> <enc> <dht> <pex> <lpd> <utp>
tr_config() {
  local dir=$1 bind=$2 port=$3 enc=$4 dht=$5 pex=$6 lpd=$7 utp=$8
  mkdir -p "$dir"
  cat > "$dir/settings.json" <<JSON
{
  "bind-address-ipv4": "$bind",
  "dht-enabled": $dht,
  "download-dir": "$dir/dl",
  "encryption": $enc,
  "lpd-enabled": $lpd,
  "peer-port": $port,
  "peer-port-random-on-start": false,
  "pex-enabled": $pex,
  "port-forwarding-enabled": false,
  "rpc-authentication-required": false,
  "rpc-bind-address": "127.0.0.1",
  "rpc-enabled": true,
  "rpc-port": 9091,
  "rpc-whitelist-enabled": false,
  "utp-enabled": $utp
}
JSON
  mkdir -p "$dir/dl"
}

start_tracker() {
  ns $SW python3 "$TOOLS/minitracker.py" "$TRACKER4" "$TRACKER_PORT" \
    >"$LAB/tracker.log" 2>&1 &
  sleep 1
}

# start_capture <peer-idx> <outfile> [filter]
CAP_PID=""
start_capture() {
  local i=$1 out=$2; shift 2
  pexec "$i" tcpdump -i "vp$i" -s 0 -U -w "$out" "$@" 2>/dev/null &
  CAP_PID=$!
  sleep 1
}
stop_capture() {
  sleep 2
  [ -n "$CAP_PID" ] && { kill $CAP_PID 2>/dev/null || true; wait $CAP_PID 2>/dev/null || true; }
  CAP_PID=""
}

# seed_transmission <peer-idx> <config-dir> <torrent>
seed_transmission() {
  local i=$1 dir=$2 torrent=$3
  cp "$LAB/content/payload.bin" "$dir/dl/payload.bin"
  pexec "$i" transmission-daemon --config-dir "$dir" --foreground --log-level=error \
    >>"$LAB/tr$i.log" 2>&1 &
  sleep 2
  pexec "$i" transmission-remote 127.0.0.1:9091 -a "$torrent" >/dev/null
  sleep 1
}

# start_transmission <peer-idx> <config-dir> [torrent]
start_transmission() {
  local i=$1 dir=$2 torrent=${3:-}
  pexec "$i" transmission-daemon --config-dir "$dir" --foreground --log-level=error \
    >>"$LAB/tr$i.log" 2>&1 &
  sleep 2
  [ -n "$torrent" ] && pexec "$i" transmission-remote 127.0.0.1:9091 -a "$torrent" >/dev/null
  sleep 1
}

# wait_complete <peer-idx> <seconds>
# Poll instead of sleeping blindly, so a broken scenario fails loudly rather
# than quietly writing a capture that is too short to prove anything.
wait_complete() {
  local i=$1 deadline=$(( SECONDS + $2 ))
  while [ $SECONDS -lt $deadline ]; do
    if pexec "$i" transmission-remote 127.0.0.1:9091 -l 2>/dev/null | grep -q "100%"; then
      say "peer $i reached 100%"
      return 0
    fi
    sleep 2
  done
  echo "FATAL: peer $i did not complete within $2s" >&2
  pexec "$i" transmission-remote 127.0.0.1:9091 -l 2>&1 | sed 's/^/   /' >&2
  exit 1
}

ARIA_COMMON=(--summary-interval=0 --console-log-level=warn --seed-time=0
             --enable-peer-exchange=false --bt-enable-lpd=false --allow-overwrite=true)

say "lab dir: $LAB"
say "output:  $OUT"
make_content
say "content: ${CONTENT_MB} MiB random bytes"

# ---------------------------------------------------------------- scenarios

scenario_plaintext() {
  say "scenario plaintext: FAST (BEP 6) + extension protocol (BEP 10) + ut_metadata advert"
  lab_up; start_tracker
  make_torrent "$LAB/pt.torrent" "http://$TRACKER4:$TRACKER_PORT/announce"
  # encryption 0 = prefer plaintext, so the handshake and its reserved bytes --
  # where FAST and the extension protocol are negotiated -- stay readable.
  #
  # Both ends are Transmission. aria2 was tried as the leecher first and
  # behaved unreproducibly in this topology: it announced successfully, the
  # tracker answered with a valid compact peer list (verified by curl), the
  # seeder was listening and reachable by TCP from the leecher namespace, and
  # aria2 still would not complete. The cross-implementation case is already
  # covered by the MSE fixtures from gen-own-captures.sh, so this is not worth
  # more time.
  tr_config "$LAB/p1" "$NET4.1" 51413 0 false true false true
  tr_config "$LAB/p2" "$NET4.2" 51414 0 false true false true
  seed_transmission 1 "$LAB/p1" "$LAB/pt.torrent"
  start_capture 2 "$LAB/plaintext.pcap" "not port $TRACKER_PORT"
  start_transmission 2 "$LAB/p2" "$LAB/pt.torrent"
  wait_complete 2 120
  stop_capture
  install_fixture "$LAB/plaintext.pcap" own_plaintext_bep6_bep10.pcap 1500
}

scenario_lsd() {
  say "scenario lsd: Local Service Discovery (BEP 14)"
  lab_up
  # No tracker in the torrent at all, so the peers can only find each other by
  # LSD multicast -- which is exactly what this fixture must contain.
  make_torrent "$LAB/lsd.torrent" none
  tr_config "$LAB/l1" "$NET4.1" 51413 0 false false true true
  tr_config "$LAB/l2" "$NET4.2" 51414 0 false false true true
  seed_transmission 1 "$LAB/l1" "$LAB/lsd.torrent"
  # Filter to the multicast discovery only. Unfiltered, LSD succeeds and the
  # peers then transfer the whole payload, which buried 2 interesting packets
  # in 48000 and a 37 MB fixture. The transfer itself is covered elsewhere.
  start_capture 2 "$LAB/lsd.pcap" "udp port 6771 or igmp"
  start_transmission 2 "$LAB/l2" "$LAB/lsd.torrent"
  # Transmission's LPD announce interval is 4 minutes, so a short window
  # catches only the IGMP join and no BT-SEARCH at all. This sleep is the
  # single slowest part of the generator and that is unavoidable.
  sleep 290
  stop_capture
  install_fixture "$LAB/lsd.pcap" own_lsd_bep14.pcap 0
}

scenario_udptracker() {
  say "scenario udptracker: UDP tracker protocol (BEP 15)"
  lab_up; start_tracker
  make_torrent "$LAB/udp.torrent" "udp://$TRACKER4:$TRACKER_PORT/announce"
  tr_config "$LAB/u1" "$NET4.1" 51413 0 false false false true
  tr_config "$LAB/u2" "$NET4.2" 51414 0 false false false true
  seed_transmission 1 "$LAB/u1" "$LAB/udp.torrent"
  # Capture only the tracker conversation: the peer transfer is covered by
  # other fixtures and would bury the handful of interesting packets.
  start_capture 2 "$LAB/udptracker.pcap" "udp port $TRACKER_PORT"
  start_transmission 2 "$LAB/u2" "$LAB/udp.torrent"
  sleep 25
  stop_capture
  install_fixture "$LAB/udptracker.pcap" own_udp_tracker_bep15.pcap 0
}

scenario_utp() {
  say "scenario utp: Micro Transport Protocol (BEP 29)"
  lab_up; start_tracker
  make_torrent "$LAB/utp.torrent" "http://$TRACKER4:$TRACKER_PORT/announce"
  tr_config "$LAB/t1" "$NET4.1" 51413 0 false false false true
  tr_config "$LAB/t2" "$NET4.2" 51414 0 false false false true
  # Drop TCP on the peer ports so the only way to move data is uTP over UDP.
  for i in 1 2; do
    pexec $i iptables -A OUTPUT -p tcp --dport 51413 -j DROP
    pexec $i iptables -A OUTPUT -p tcp --dport 51414 -j DROP
    pexec $i iptables -A INPUT  -p tcp --dport 51413 -j DROP
    pexec $i iptables -A INPUT  -p tcp --dport 51414 -j DROP
  done
  seed_transmission 1 "$LAB/t1" "$LAB/utp.torrent"
  start_capture 2 "$LAB/utp.pcap" "not port $TRACKER_PORT"
  start_transmission 2 "$LAB/t2" "$LAB/utp.torrent"
  wait_complete 2 180
  stop_capture
  install_fixture "$LAB/utp.pcap" own_utp_bep29.pcap 1200
}

scenario_dht() {
  say "scenario dht: DHT (BEP 5) between two nodes"
  lab_up
  make_torrent "$LAB/dht.torrent" none
  mkdir -p "$LAB/d1dl" "$LAB/d2dl"
  cp "$LAB/content/payload.bin" "$LAB/d1dl/payload.bin"
  # aria2 will bootstrap its DHT against the address we hand it, so two nodes
  # form a closed two-node DHT with no bootstrap server involved.
  pexec 1 aria2c "${ARIA_COMMON[@]}" --dir="$LAB/d1dl" --seed-time=5 \
    --enable-dht=true --dht-listen-port=6881 --dht-entry-point="$NET4.2:6882" \
    --listen-port=51413 --bt-seed-unverified=true \
    "$LAB/dht.torrent" >>"$LAB/aria1.log" 2>&1 &
  sleep 2
  start_capture 2 "$LAB/dht.pcap"
  pexec 2 aria2c "${ARIA_COMMON[@]}" --dir="$LAB/d2dl" \
    --enable-dht=true --dht-listen-port=6882 --dht-entry-point="$NET4.1:6881" \
    --listen-port=51500 --bt-stop-timeout=40 \
    "$LAB/dht.torrent" 2>&1 | tail -2 | sed 's/^/   node2: /' || true
  stop_capture
  install_fixture "$LAB/dht.pcap" own_dht_bep5.pcap 0
}

scenario_ipv6() {
  say "scenario ipv6: peer traffic over IPv6"
  lab_up; start_tracker
  make_torrent "$LAB/v6.torrent" "http://[${NET6}254]:$TRACKER_PORT/announce"
  tr_config "$LAB/v1" "$NET4.1" 51413 0 false false false true
  tr_config "$LAB/v2" "$NET4.2" 51414 0 false false false true
  # Bind both peers to their IPv6 literals and announce over IPv6, so the
  # tracker hands out v6 peers and the peer connection itself is IPv6.
  for n in 1 2; do
    python3 "$TOOLS/set-json-key.py" "$LAB/v$n/settings.json" \
      bind-address-ipv6 "${NET6}$n"
  done
  seed_transmission 1 "$LAB/v1" "$LAB/v6.torrent"
  start_capture 2 "$LAB/ipv6.pcap" "ip6"
  start_transmission 2 "$LAB/v2" "$LAB/v6.torrent"
  wait_complete 2 180
  stop_capture
  install_fixture "$LAB/ipv6.pcap" own_ipv6_peer.pcap 1500
}

scenario_pex() {
  say "scenario pex: Peer Exchange (BEP 11) with three peers"
  lab_up; start_tracker
  make_torrent "$LAB/pex.torrent" "http://$TRACKER4:$TRACKER_PORT/announce"
  for i in 1 2 3; do
    tr_config "$LAB/x$i" "$NET4.$i" $((51412 + i)) 0 false true false true
  done
  seed_transmission 1 "$LAB/x1" "$LAB/pex.torrent"
  start_transmission 2 "$LAB/x2" "$LAB/pex.torrent"
  start_transmission 3 "$LAB/x3" "$LAB/pex.torrent"
  # Capture on peer 3, which should learn about the others partly via ut_pex.
  start_capture 3 "$LAB/pex.pcap" "not port $TRACKER_PORT"
  sleep 40
  stop_capture
  install_fixture "$LAB/pex.pcap" own_pex_bep11.pcap 1500
}

scenario_msebulk() {
  say "scenario msebulk: many MSE handshakes for threshold work"
  # One TCP connection is made per (peer, torrent) pair, each with its own MSE
  # handshake, so N torrents across 3 peers yields on the order of N*pairs
  # handshakes in a single run. The point is sample size: tuning an entropy
  # threshold on the 2 flows a single-torrent lab produces is not tuning.
  local count=${MSE_TORRENTS:-25}
  lab_up; start_tracker
  mkdir -p "$LAB/bulk"
  for n in $(seq 1 "$count"); do
    # Distinct content per torrent, otherwise they share an info_hash and
    # collapse into one swarm with one connection.
    dd if=/dev/urandom of="$LAB/bulk/payload$n.bin" bs=1M count=2 status=none
    mktorrent -l 15 -a "http://$TRACKER4:$TRACKER_PORT/announce" \
      -n "payload$n.bin" -o "$LAB/bulk/t$n.torrent" "$LAB/bulk/payload$n.bin" >/dev/null
  done
  say "created $count torrents of 2 MiB each"

  # encryption 2 = required, on every peer, so every one of those connections
  # must negotiate MSE.
  # Only the seeder needs a Transmission config now.
  tr_config "$LAB/m1" "$NET4.1" 51413 2 false false false true
  cp "$LAB/bulk"/payload*.bin "$LAB/m1/dl/"

  pexec 1 transmission-daemon --config-dir "$LAB/m1" --foreground --log-level=error \
    >>"$LAB/tr1.log" 2>&1 &
  sleep 3
  for n in $(seq 1 "$count"); do
    pexec 1 transmission-remote 127.0.0.1:9091 -a "$LAB/bulk/t$n.torrent" >/dev/null
  done
  sleep 3

  start_capture 2 "$LAB/msebulk.pcap" "tcp and not port $TRACKER_PORT"
  # aria2 is the initiator, not Transmission.
  #
  # Transmission with "encryption": 2 correctly REFUSES plaintext as the
  # responder -- it answers a 68-byte plaintext handshake with RST -- but it
  # still *sends* plaintext as the initiator, so a Transmission-to-Transmission
  # run produces no connections at all: 30 flows, each one plaintext handshake
  # followed by RST, and not one byte transferred. aria2 with
  # --bt-require-crypto=true does initiate MSE, which is why the original MSE
  # fixtures came out of a Transmission/aria2 pair.
  #
  # Every torrent on the command line becomes its own peer connection, so the
  # handshake count scales with $count.
  local torrents=()
  for n in $(seq 1 "$count"); do torrents+=("$LAB/bulk/t$n.torrent"); done
  pexec 2 aria2c "${ARIA_COMMON[@]}" --dir="$LAB/m2dl" \
    --bt-require-crypto=true --bt-min-crypto-level=arc4 \
    --enable-dht=false --listen-port=51500 --bt-stop-timeout=120 \
    --max-concurrent-downloads="$count" \
    "${torrents[@]}" 2>&1 | tail -3 | sed 's/^/   leecher: /' || true
  stop_capture

  python3 "$TOOLS/extract-flow-starts.py" "$LAB/msebulk.pcap" \
    "$OUT/own_mse_many_flows.pcap" 4
  say "wrote own_mse_many_flows.pcap ($(stat -c%s "$OUT/own_mse_many_flows.pcap") bytes)"
}

# install_fixture <src> <name> <max-packets 0=all>
install_fixture() {
  local src=$1 name=$2 limit=$3
  if [ ! -s "$src" ]; then
    echo "FATAL: $name: capture is empty" >&2; exit 1
  fi
  if [ "$limit" -gt 0 ]; then
    python3 "$TOOLS/trim-capture.py" "$src" "$OUT/$name" "$limit"
  else
    cp "$src" "$OUT/$name"
  fi
  say "wrote $name ($(stat -c%s "$OUT/$name") bytes, $(tcpdump -r "$OUT/$name" 2>/dev/null | wc -l) packets)"
}

for s in "${SCENARIOS[@]}"; do
  case $s in
    plaintext)  scenario_plaintext ;;
    lsd)        scenario_lsd ;;
    udptracker) scenario_udptracker ;;
    utp)        scenario_utp ;;
    dht)        scenario_dht ;;
    ipv6)       scenario_ipv6 ;;
    pex)        scenario_pex ;;
    msebulk)    scenario_msebulk ;;
    *) echo "unknown scenario: $s" >&2; exit 1 ;;
  esac
done

say "all requested scenarios done"
