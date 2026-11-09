#!/usr/bin/env python3
"""Trim a pcap to its first N packets, preserving the global header.

Used by gen-protocol-captures.sh to keep bulk-transfer fixtures small: once a
scenario has demonstrated its protocol, the remaining thousands of piece
packets add megabytes without adding a check.
"""

import struct
import sys

GLOBAL_HEADER_LEN = 24


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: trim-capture.py <in.pcap> <out.pcap> <max-packets>")
    src, dst, limit = sys.argv[1], sys.argv[2], int(sys.argv[3])

    data = open(src, "rb").read()
    header = data[:GLOBAL_HEADER_LEN]
    magic = struct.unpack("<I", header[:4])[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        raise SystemExit(f"{src}: not a classic pcap (magic {magic:#x})")

    out = bytearray(header)
    off = GLOBAL_HEADER_LEN
    kept = 0
    while off + 16 <= len(data) and kept < limit:
        incl = struct.unpack(endian + "I", data[off + 8 : off + 12])[0]
        if incl > 262144:
            break
        out += data[off : off + 16 + incl]
        off += 16 + incl
        kept += 1

    open(dst, "wb").write(out)
    print(f"   trimmed to {kept} packets")


if __name__ == "__main__":
    main()
