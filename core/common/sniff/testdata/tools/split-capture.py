#!/usr/bin/env python3
"""Split a lab capture into a handshake fixture and a mid-transfer fixture.

Part of gen-own-captures.sh. Kept separate because slicing pcap by packet
index is fiddly enough to deserve its own tests-by-inspection, and because
tshark is not installed on the capture host.

Fixture 1 (handshake): packets from the start, which is where the MSE key
exchange and the encrypted handshake live.

Fixture 2 (mid-transfer): a window from the middle of the session, chosen to
contain steady-state piece traffic and deliberately *not* the handshake, so
the two fixtures test different things rather than overlapping.
"""

import struct
import sys

GLOBAL_HEADER_LEN = 24
HANDSHAKE_PACKETS = 400
MID_PACKETS = 1200


def read_packets(path):
    data = open(path, "rb").read()
    header = data[:GLOBAL_HEADER_LEN]
    magic = struct.unpack("<I", header[:4])[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        raise SystemExit(f"{path}: not a classic pcap (magic {magic:#x})")

    packets = []
    off = GLOBAL_HEADER_LEN
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, orig = struct.unpack(endian + "IIII", data[off : off + 16])
        if incl > 262144:
            break
        packets.append(data[off : off + 16 + incl])
        off += 16 + incl
    return header, packets


def write(path, header, packets):
    with open(path, "wb") as fh:
        fh.write(header)
        for pkt in packets:
            fh.write(pkt)


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: split-capture.py <in.pcap> <handshake.pcap> <mid.pcap>")
    src, hs_out, mid_out = sys.argv[1:4]
    header, packets = read_packets(src)
    total = len(packets)
    if total < HANDSHAKE_PACKETS + MID_PACKETS:
        raise SystemExit(
            f"{src}: only {total} packets, need at least "
            f"{HANDSHAKE_PACKETS + MID_PACKETS}; raise CONTENT_MB and re-run"
        )

    handshake = packets[:HANDSHAKE_PACKETS]

    # Centre the mid-transfer window on the middle of the capture.
    start = max(HANDSHAKE_PACKETS, (total - MID_PACKETS) // 2)
    mid = packets[start : start + MID_PACKETS]

    write(hs_out, header, handshake)
    write(mid_out, header, mid)
    print(
        f"   split: {total} packets -> handshake[0:{HANDSHAKE_PACKETS}] "
        f"+ mid[{start}:{start + len(mid)}]"
    )


if __name__ == "__main__":
    main()
