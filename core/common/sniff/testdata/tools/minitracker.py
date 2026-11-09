#!/usr/bin/env python3
"""Minimal BitTorrent HTTP tracker for the isolated capture lab.

Exists so the two clients in the lab can find each other without DHT, PEX,
LSD or any contact with a public tracker. It serves exactly one purpose and
deliberately has no features: no stats, no scrape, no persistence, no
multi-torrent bookkeeping beyond a dict in memory.

It is part of the reproducible fixture generator; see gen-own-captures.sh.
"""

import socket
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote_to_bytes, urlparse

# info_hash -> {peer_id: (ip, port)}
# ip is a plain address string; IPv4-mapped IPv6 sources are normalised to
# their dotted-quad form so a peer that reached us over a dual-stack socket is
# not recorded as a separate IPv6 peer.
SWARMS: dict[bytes, dict[bytes, tuple[str, int]]] = {}


def normalise_ip(addr: str) -> str:
    return addr[7:] if addr.startswith("::ffff:") else addr


def bencode(value) -> bytes:
    if isinstance(value, int):
        return b"i%de" % value
    if isinstance(value, bytes):
        return b"%d:%s" % (len(value), value)
    if isinstance(value, str):
        return bencode(value.encode())
    if isinstance(value, list):
        return b"l" + b"".join(bencode(v) for v in value) + b"e"
    if isinstance(value, dict):
        out = b"d"
        for key in sorted(value):
            out += bencode(key) + bencode(value[key])
        return out + b"e"
    raise TypeError(type(value))


def compact_peers(peers: dict[bytes, tuple[str, int]], exclude: bytes) -> bytes:
    """BEP 23 compact IPv4 peer list: 4-byte address + 2-byte port each."""
    out = b""
    for peer_id, (ip, port) in peers.items():
        if peer_id == exclude or ":" in ip:
            continue
        out += socket.inet_aton(ip) + struct.pack(">H", port)
    return out


def compact_peers6(peers: dict[bytes, tuple[str, int]], exclude: bytes) -> bytes:
    """BEP 7 compact IPv6 peer list: 16-byte address + 2-byte port each.

    IPv6 peers must go in a separate "peers6" key; putting them in "peers"
    would make clients read 16-byte addresses as four 6-byte v4 entries.
    """
    out = b""
    for peer_id, (ip, port) in peers.items():
        if peer_id == exclude or ":" not in ip:
            continue
        out += socket.inet_pton(socket.AF_INET6, ip) + struct.pack(">H", port)
    return out


class Handler(BaseHTTPRequestHandler):
    # HTTP/1.0, so each response closes the connection.
    #
    # This was HTTP/1.1 with a single-threaded HTTPServer, and that
    # combination quietly broke every multi-peer scenario: the seeder kept its
    # connection alive between announces, which blocked the single server
    # thread, so the leecher's announce was not answered until the seeder's
    # connection timed out. The visible symptoms were a BrokenPipeError in the
    # tracker log and a leecher sitting at "Idle 0%" with no peers -- neither
    # of which points at keep-alive. Threading plus connection-per-request
    # removes both failure modes.
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *args):
        # Log to stderr so the generator's log shows which paths clients ask
        # for. Silence here once cost an hour of guessing why a scenario hung.
        sys.stderr.write("[tracker] %s\n" % (fmt % args))

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/scrape"):
            # Clients scrape as a matter of course; answer minimally rather
            # than 404, so a real failure stands out in the log.
            body = bencode({b"files": {}})
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if not parsed.path.startswith("/announce"):
            self.send_error(404)
            return

        # info_hash and peer_id are raw bytes, so they must not go through
        # the str-based parse_qs path or they get mangled by UTF-8 decoding.
        raw = {}
        for pair in parsed.query.split("&"):
            if "=" not in pair:
                continue
            key, _, val = pair.partition("=")
            raw.setdefault(key, unquote_to_bytes(val))
        text = parse_qs(parsed.query)

        info_hash = raw.get(b"info_hash") or raw.get("info_hash")
        peer_id = raw.get(b"peer_id") or raw.get("peer_id")
        if not info_hash or not peer_id:
            self.send_error(400)
            return

        try:
            port = int(text.get("port", ["0"])[0])
        except ValueError:
            port = 0
        event = text.get("event", [""])[0]
        ip = normalise_ip(self.client_address[0])

        swarm = SWARMS.setdefault(info_hash, {})
        if event == "stopped":
            swarm.pop(peer_id, None)
        elif port:
            swarm[peer_id] = (ip, port)

        body = bencode(
            {
                b"interval": 30,
                b"min interval": 10,
                b"complete": 1,
                b"incomplete": max(0, len(swarm) - 1),
                b"peers": compact_peers(swarm, exclude=peer_id),
                b"peers6": compact_peers6(swarm, exclude=peer_id),
            }
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# --------------------------------------------------------------- BEP 15 (UDP)

PROTOCOL_ID = 0x41727101980
ACTION_CONNECT = 0
ACTION_ANNOUNCE = 1
ACTION_ERROR = 3


def udp_tracker(host: str, port: int) -> None:
    """Serve the UDP tracker protocol (BEP 15).

    Only connect and announce are implemented -- no scrape, and the
    connection_id is a constant rather than a rotating token, because the
    lab has exactly two trusted clients and a real token adds nothing to
    the captured wire format.
    """
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(("::", port))
    connection_id = 0x1122334455667788

    while True:
        try:
            data, addr = sock.recvfrom(2048)
        except OSError:
            continue
        if len(data) < 16:
            continue

        req_conn, action, txn = struct.unpack(">QII", data[:16])

        if action == ACTION_CONNECT:
            if req_conn != PROTOCOL_ID:
                continue
            sock.sendto(struct.pack(">IIQ", ACTION_CONNECT, txn, connection_id), addr)
            continue

        if action != ACTION_ANNOUNCE or len(data) < 98:
            sock.sendto(
                struct.pack(">II", ACTION_ERROR, txn) + b"bad request", addr
            )
            continue

        info_hash = data[16:36]
        peer_id = data[36:56]
        event = struct.unpack(">I", data[80:84])[0]
        peer_port = struct.unpack(">H", data[96:98])[0]

        swarm = SWARMS.setdefault(info_hash, {})
        if event == 3:  # stopped
            swarm.pop(peer_id, None)
        elif peer_port:
            swarm[peer_id] = (normalise_ip(addr[0]), peer_port)

        body = struct.pack(
            ">IIIII",
            ACTION_ANNOUNCE,
            txn,
            30,                        # interval
            max(0, len(swarm) - 1),    # leechers
            1,                         # seeders
        ) + compact_peers(swarm, exclude=peer_id)
        sock.sendto(body, addr)


class DualStackServer(ThreadingHTTPServer):
    """Listen on :: with IPV6_V6ONLY off, so one socket serves v4 and v6.

    The IPv6 scenario announces to http://[fd00:77::254]:6969/, and an
    IPv4-only listener made that scenario time out with no indication of why.
    """

    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


if __name__ == "__main__":
    # The host argument is kept for compatibility but ignored: binding :: is
    # what makes the tracker reachable over both families.
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 6969

    # Both transports share SWARMS, so a peer that announced over HTTP is
    # visible to one that announced over UDP.
    threading.Thread(target=udp_tracker, args=("::", port), daemon=True).start()
    DualStackServer(("::", port), Handler).serve_forever()
