#!/usr/bin/env python3
"""Assert that each owned fixture really contains the protocol it claims to.

A generator script can succeed, produce a plausible-looking capture, and still
have failed to exercise the protocol the fixture is named after -- a disabled
option, a client that fell back to TCP, a tracker that was never contacted. A
fixture like that is worse than no fixture, because the test it feeds will pass
while checking nothing.

So every owned fixture gets a positive assertion here, and this runs as part
of the Go test suite (TestOwnedFixtureMarkers) rather than only at generation
time, which also catches a bad re-generation later.

Usage: verify-fixtures.py <dir>     (exit 1 on any failure)
"""

import os
import struct
import sys

LSD_GROUP = "239.192.152.143"
UTP_PORT_MIN = 1024
TRACKER_PROTOCOL_ID = 0x41727101980


def packets(path):
    """Yield (linktype, raw_frame) for a classic pcap or pcapng file."""
    data = open(path, "rb").read()
    magic = data[:4]

    if magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"):
        # The bytes on disk are the magic as written by the capturing host, so
        # d4c3b2a1 on disk means little-endian and a1b2c3d4 means big-endian --
        # the opposite of what the constant's spelling suggests.
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
        linktype = struct.unpack(endian + "I", data[20:24])[0]
        off = 24
        while off + 16 <= len(data):
            incl = struct.unpack(endian + "I", data[off + 8 : off + 12])[0]
            if incl > 262144:
                return
            yield linktype, data[off + 16 : off + 16 + incl]
            off += 16 + incl
        return

    # pcapng: walk blocks, we only care about EPB (type 6) payloads.
    off = 0
    linktype = 1
    while off + 12 <= len(data):
        btype, blen = struct.unpack("<II", data[off : off + 8])
        if blen < 12 or off + blen > len(data):
            return
        if btype == 0x00000001:  # IDB
            linktype = struct.unpack("<H", data[off + 8 : off + 10])[0]
        elif btype == 6:  # EPB
            caplen = struct.unpack("<I", data[off + 20 : off + 24])[0]
            yield linktype, data[off + 28 : off + 28 + caplen]
        off += blen


def decode(frame, linktype):
    """Return (proto, src, dst, sport, dport, payload) or None."""
    if linktype != 1 or len(frame) < 14:
        return None
    etype = struct.unpack(">H", frame[12:14])[0]
    rest = frame[14:]

    if etype == 0x0800:
        if len(rest) < 20:
            return None
        ihl = (rest[0] & 0xF) * 4
        proto = rest[9]
        src = ".".join(str(b) for b in rest[12:16])
        dst = ".".join(str(b) for b in rest[16:20])
        tr = rest[ihl:]
        family = 4
    elif etype == 0x86DD:
        if len(rest) < 40:
            return None
        proto = rest[6]
        src, dst = rest[8:24].hex(), rest[24:40].hex()
        tr = rest[40:]
        family = 6
    else:
        return None

    if proto == 6 and len(tr) >= 20:
        doff = (tr[12] >> 4) * 4
        sport, dport = struct.unpack(">HH", tr[:4])
        return ("tcp", family, src, dst, sport, dport, tr[doff:])
    if proto == 17 and len(tr) >= 8:
        sport, dport = struct.unpack(">HH", tr[:4])
        return ("udp", family, src, dst, sport, dport, tr[8:])
    return None


def load(path):
    out = []
    for linktype, frame in packets(path):
        dec = decode(frame, linktype)
        if dec:
            out.append(dec)
    return out


# ------------------------------------------------------------------ assertions


def has_plaintext_handshake(pkts):
    return any(b"BitTorrent protocol" in p[6] for p in pkts)


def handshake_reserved_bits(pkts):
    """Collect reserved bytes from every plaintext BitTorrent handshake."""
    out = []
    for p in pkts:
        pl = p[6]
        idx = pl.find(b"\x13BitTorrent protocol")
        if idx >= 0 and len(pl) >= idx + 28:
            out.append(pl[idx + 20 : idx + 28])
    return out


def fast_negotiated(pkts):
    # BEP 6: reserved byte 7, bit 0x04.
    return any(r[7] & 0x04 for r in handshake_reserved_bits(pkts))


def extension_negotiated(pkts):
    # BEP 10: reserved byte 5, bit 0x10.
    return any(r[5] & 0x10 for r in handshake_reserved_bits(pkts))


def has_bytes(pkts, needle):
    return any(needle in p[6] for p in pkts)


def lsd_present(pkts):
    return any(
        p[0] == "udp" and p[5] == 6771 and b"BT-SEARCH" in p[6] for p in pkts
    )


def udp_tracker_present(pkts):
    want = struct.pack(">Q", TRACKER_PROTOCOL_ID)
    return any(p[0] == "udp" and p[6].startswith(want) for p in pkts)


def udp_tracker_announce(pkts):
    # action=1 (announce) response: action, txn, interval, leechers, seeders
    for p in pkts:
        if p[0] == "udp" and len(p[6]) >= 20:
            action = struct.unpack(">I", p[6][:4])[0]
            if action == 1:
                return True
    return False


def utp_present(pkts):
    """uTP header: byte0 high nibble = type (0..4), low nibble = version 1."""
    count = 0
    for p in pkts:
        if p[0] != "udp" or len(p[6]) < 20:
            continue
        b0 = p[6][0]
        if (b0 & 0x0F) == 1 and (b0 >> 4) <= 4:
            count += 1
    return count >= 10


def no_tcp_payload(pkts):
    return not any(p[0] == "tcp" and len(p[6]) > 0 for p in pkts)


def dht_query(pkts):
    return any(
        p[0] == "udp"
        and p[6].startswith(b"d1:")
        and (b"9:find_node" in p[6] or b"9:get_peers" in p[6] or b"4:ping" in p[6])
        for p in pkts
    )


def ipv6_peer_traffic(pkts):
    return sum(1 for p in pkts if p[1] == 6 and len(p[6]) > 0) >= 10


def dht_query_behind_socks5(pkts):
    """Same check as dht_query, but past the 10-byte SOCKS5 UDP header.

    Checking the raw payload would always fail here: after wrapping, every
    datagram starts with the SOCKS5 header, not with bencode. The point of this
    assertion is that the BitTorrent payload is still intact underneath, which
    is what the detector has to find once it unwraps.
    """
    header = 4 + 4 + 2  # RSV+FRAG+ATYP, IPv4 address, port
    stripped = [p[:6] + (p[6][header:],) for p in pkts if p[0] == "udp"]
    return dht_query(stripped)


def mse_flow_payloads(pkts):
    """Flow-first TCP payloads of at least 96 bytes with no plaintext marker."""
    seen = set()
    out = []
    for p in pkts:
        if p[0] != "tcp" or len(p[6]) < 96:
            continue
        key = (p[2], p[4], p[3], p[5])
        if key in seen:
            continue
        seen.add(key)
        if b"BitTorrent protocol" not in p[6]:
            out.append(p[6])
    return out


def many_mse_flows(pkts):
    return len(mse_flow_payloads(pkts)) >= 100


def no_plaintext_vc(pkts):
    """No payload carries the MSE Verification Constant in the clear.

    Documents the measured fact that CheckMSEEncryption's VC scan cannot
    succeed: MSE sends VC encrypted, so 8 plaintext zero bytes never appear.
    If this assertion ever fails, the premise changed and the detector is worth
    revisiting.
    """
    for pl in mse_flow_payloads(pkts):
        window = pl[96:628]
        if b"\x00" * 8 in window:
            return False
    return True


def socks5_udp_wrapped(pkts):
    """SOCKS5 UDP request header: RSV(2)=0, FRAG(1)=0, ATYP(1)=1."""
    return any(
        p[0] == "udp" and len(p[6]) > 10 and p[6][:4] == b"\x00\x00\x00\x01"
        for p in pkts
    )


# Minimum decoded packets per fixture. Not a global constant: a fixture can be
# legitimately tiny -- the LSD one is 2 IGMP joins plus 2 BT-SEARCH announces,
# and a blanket "at least 10" rejected it. The point of the floor is to catch a
# parser or capture that produced nothing, not to demand bulk.
MIN_PACKETS = {
    # Two BT-SEARCH announces, one per peer. The IGMP joins alongside them are
    # not counted: decode() only handles TCP and UDP, and IGMP is protocol 2.
    "own_lsd_bep14.pcap": 2,
    "own_udp_tracker_bep15.pcap": 4,
    "own_dht_bep5.pcap": 4,
    "own_socks5_wrapped_synthetic.pcap": 4,
    "own_mse_many_flows.pcap": 250,
}
DEFAULT_MIN_PACKETS = 50

CHECKS = {
    "own_mse_handshake.pcap": [
        ("no plaintext handshake (MSE really was required)",
         lambda p: not has_plaintext_handshake(p)),
        ("carries TCP payload", lambda p: any(x[0] == "tcp" and x[6] for x in p)),
    ],
    "own_mid_transfer.pcap": [
        ("no plaintext handshake", lambda p: not has_plaintext_handshake(p)),
        ("carries TCP payload", lambda p: any(x[0] == "tcp" and x[6] for x in p)),
    ],
    "own_plaintext_bep6_bep10.pcap": [
        ("plaintext BitTorrent handshake", has_plaintext_handshake),
        ("FAST extension negotiated (BEP 6)", fast_negotiated),
        ("extension protocol negotiated (BEP 10)", extension_negotiated),
        ("ut_metadata offered (BEP 9)", lambda p: has_bytes(p, b"ut_metadata")),
    ],
    "own_lsd_bep14.pcap": [
        ("BT-SEARCH multicast to port 6771 (BEP 14)", lsd_present),
    ],
    "own_udp_tracker_bep15.pcap": [
        ("connect request with protocol id 0x41727101980", udp_tracker_present),
        ("announce response present", udp_tracker_announce),
    ],
    "own_utp_bep29.pcap": [
        ("uTP headers present (BEP 29)", utp_present),
        ("no TCP payload, so the transfer really used uTP", no_tcp_payload),
    ],
    "own_dht_bep5.pcap": [
        ("bencoded DHT query (BEP 5)", dht_query),
    ],
    "own_ipv6_peer.pcap": [
        ("IPv6 peer traffic", ipv6_peer_traffic),
    ],
    "own_pex_bep11.pcap": [
        ("ut_pex offered (BEP 11)", lambda p: has_bytes(p, b"ut_pex")),
    ],
    "own_mse_many_flows.pcap": [
        ("at least 100 MSE flows (sample size for threshold work)", many_mse_flows),
        ("no plaintext Verification Constant anywhere", no_plaintext_vc),
    ],
    "own_socks5_wrapped_synthetic.pcap": [
        ("SOCKS5 UDP request headers", socks5_udp_wrapped),
        ("inner DHT query survives unwrapping", dht_query_behind_socks5),
    ],
}


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    failures = 0
    checked = 0
    for name, checks in sorted(CHECKS.items()):
        path = os.path.join(root, name)
        if not os.path.exists(path):
            print(f"MISSING  {name}")
            failures += 1
            continue
        pkts = load(path)

        # Guard against vacuous passes. Several assertions below are negative
        # ("no plaintext handshake"), and those are trivially true of an empty
        # packet list -- so a parser bug would read as a clean bill of health.
        # This actually happened: an inverted pcap endianness check made the
        # loader return zero packets. Assert decodability first.
        minimum = MIN_PACKETS.get(name, DEFAULT_MIN_PACKETS)
        checked += 1
        if len(pkts) < minimum:
            print(
                f"FAIL     {name}: decoded only {len(pkts)} packets, "
                f"expected at least {minimum} (parser or capture broken)"
            )
            failures += 1
            continue
        print(f"ok       {name}: decoded {len(pkts)} packets (min {minimum})")

        for label, fn in checks:
            checked += 1
            try:
                ok = bool(fn(pkts))
            except Exception as exc:  # a malformed fixture must fail loudly
                ok = False
                label += f" [raised {exc!r}]"
            print(f"{'ok      ' if ok else 'FAIL    '} {name}: {label}")
            if not ok:
                failures += 1
    print(f"\n{checked} assertions, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
