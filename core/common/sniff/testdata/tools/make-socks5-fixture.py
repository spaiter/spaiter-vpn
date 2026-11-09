#!/usr/bin/env python3
"""Build a synthetic SOCKS5-wrapped fixture from an owned UDP capture.

WHY THIS IS SYNTHETIC
---------------------
BitTorrent clients do not tunnel peer or DHT traffic through SOCKS5. Neither
Transmission nor aria2 offers it: their proxy settings cover tracker HTTP only.
So unlike every other owned fixture, this one cannot be captured from real
clients in the lab -- there is no configuration of real software that would
produce it.

It is therefore built by transformation: the UDP payloads of an owned capture
are prefixed with a SOCKS5 UDP request header, which is exactly what a client
behind a SOCKS5 UDP-associate proxy would emit. That exercises UnwrapSOCKS5
and the detection path behind it, which otherwise has no fixture at all.

The output is named *_synthetic.pcap and recorded as synthetic in NOTICE.md,
because a fixture that looks like a capture but is not one would mislead the
next person who reads a detection rate off it.

SOCKS5 UDP request header (RFC 1928 section 7):

    +-----+------+------+----------+----------+----------+
    | RSV | RSV  | FRAG |   ATYP   | DST.ADDR | DST.PORT |
    +-----+------+------+----------+----------+----------+
    |  0  |  0   |  0   |    1     |  4 bytes |  2 bytes |
    +-----+------+------+----------+----------+----------+

Usage: make-socks5-fixture.py <in.pcap> <out.pcap>
"""

import struct
import sys

GLOBAL_HEADER_LEN = 24


def ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def wrap_udp_payload(frame: bytes) -> bytes | None:
    """Return the frame with its UDP payload SOCKS5-wrapped, or None."""
    if len(frame) < 14 or struct.unpack(">H", frame[12:14])[0] != 0x0800:
        return None
    eth, ip = frame[:14], bytearray(frame[14:])
    if len(ip) < 20 or ip[9] != 17:
        return None
    ihl = (ip[0] & 0xF) * 4
    udp = bytearray(ip[ihl:])
    if len(udp) < 8:
        return None

    payload = bytes(udp[8:])
    if not payload:
        return None

    dst_ip = bytes(ip[16:20])
    dst_port = udp[2:4]
    wrapped = b"\x00\x00\x00\x01" + dst_ip + bytes(dst_port) + payload

    # Rebuild UDP: new length, and zero the checksum. Zero is legal for IPv4
    # UDP (RFC 768) and means "not computed", which is honest here -- the
    # payload has been rewritten, so the original checksum is meaningless and
    # faking a new one would imply a fidelity this file does not have.
    udp[4:6] = struct.pack(">H", 8 + len(wrapped))
    udp[6:8] = b"\x00\x00"
    new_udp = bytes(udp[:8]) + wrapped

    # Rebuild IPv4: new total length, recomputed header checksum.
    ip = ip[:ihl]
    ip[2:4] = struct.pack(">H", ihl + len(new_udp))
    ip[10:12] = b"\x00\x00"
    ip[10:12] = struct.pack(">H", ip_checksum(bytes(ip)))

    return eth + bytes(ip) + new_udp


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: make-socks5-fixture.py <in.pcap> <out.pcap>")
    src, dst = sys.argv[1], sys.argv[2]

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
    wrapped = skipped = 0
    off = GLOBAL_HEADER_LEN
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, orig = struct.unpack(
            endian + "IIII", data[off : off + 16]
        )
        if incl > 262144:
            break
        frame = data[off + 16 : off + 16 + incl]
        off += 16 + incl

        new_frame = wrap_udp_payload(frame)
        if new_frame is None:
            skipped += 1
            continue
        out += struct.pack(
            endian + "IIII", ts_sec, ts_usec, len(new_frame), len(new_frame)
        )
        out += new_frame
        wrapped += 1

    if wrapped == 0:
        raise SystemExit(f"{src}: no UDP payloads to wrap; wrong input capture?")

    open(dst, "wb").write(out)
    print(f"   wrapped {wrapped} UDP packets, skipped {skipped} non-UDP")


if __name__ == "__main__":
    main()
