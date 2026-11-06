#!/usr/bin/env python3
"""Keep only the first N payload-bearing packets of each TCP flow.

For handshake analysis the interesting bytes are all at the start of a flow;
everything after is bulk transfer that multiplies the fixture size without
adding a single handshake. A capture of 25 concurrent torrents is ~100 MB, of
which the handshakes are a few hundred packets.

Flows are keyed by (src, sport, dst, dport), so the two directions are
separate flows -- deliberately, because MSE's initiator and responder messages
differ and both are worth keeping.

Usage: extract-flow-starts.py <in.pcap> <out.pcap> [packets-per-flow]
"""

import struct
import sys

GLOBAL_HEADER_LEN = 24
DEFAULT_PER_FLOW = 4


def flow_key(frame):
    """Return (src, sport, dst, dport) for a TCP frame with payload, else None."""
    if len(frame) < 14:
        return None
    etype = struct.unpack(">H", frame[12:14])[0]
    if etype == 0x0800:
        ip = frame[14:]
        if len(ip) < 20 or ip[9] != 6:
            return None
        src, dst = bytes(ip[12:16]), bytes(ip[16:20])
        tr = ip[(ip[0] & 0xF) * 4 :]
    elif etype == 0x86DD:
        ip = frame[14:]
        if len(ip) < 40 or ip[6] != 6:
            return None
        src, dst = bytes(ip[8:24]), bytes(ip[24:40])
        tr = ip[40:]
    else:
        return None
    if len(tr) < 20:
        return None
    sport, dport = struct.unpack(">HH", tr[:4])
    if len(tr[(tr[12] >> 4) * 4 :]) == 0:
        return None
    return (src, sport, dst, dport)


def main():
    if len(sys.argv) not in (3, 4):
        raise SystemExit(
            "usage: extract-flow-starts.py <in.pcap> <out.pcap> [packets-per-flow]"
        )
    src, dst = sys.argv[1], sys.argv[2]
    per_flow = int(sys.argv[3]) if len(sys.argv) == 4 else DEFAULT_PER_FLOW

    data = open(src, "rb").read()
    header = data[:GLOBAL_HEADER_LEN]
    magic = struct.unpack("<I", header[:4])[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        raise SystemExit(f"{src}: not a classic pcap (magic {magic:#x})")

    counts = {}
    out = bytearray(header)
    kept = 0
    off = GLOBAL_HEADER_LEN
    while off + 16 <= len(data):
        incl = struct.unpack(endian + "I", data[off + 8 : off + 12])[0]
        if incl > 262144:
            break
        rec = data[off : off + 16 + incl]
        frame = data[off + 16 : off + 16 + incl]
        off += 16 + incl

        key = flow_key(frame)
        if key is None:
            continue
        seen = counts.get(key, 0)
        if seen >= per_flow:
            continue
        counts[key] = seen + 1
        out += rec
        kept += 1

    if not counts:
        raise SystemExit(f"{src}: no TCP flows with payload found")

    open(dst, "wb").write(out)
    print(f"   kept {kept} packets from {len(counts)} flows (<= {per_flow} each)")


if __name__ == "__main__":
    main()
