import os
import socket
import struct
from typing import Dict, Tuple
from src.core.checksum_utils import ipv4_header_checksum

UDP_PROTO = 17
IPV4_HEADER_LEN = 20

# Note: ipv4_checksum was previously defined here inline.
# Replaced with ipv4_header_checksum from checksum_utils.py
# to centralize all checksum logic in one place.

def build_ipv4_header(
    src_ip: str,
    dst_ip: str,
    total_len: int,
    ident: int | None = None,
    ttl: int = 64,
    proto: int = UDP_PROTO,
    tos: int = 0,
    flags_frag: int = 0,
) -> bytes:
    """
    Build a minimal IPv4 header (20 bytes, no options).
    total_len must include IP header + L4 header + payload.
    """
    version = 4
    ihl = 5  # 5 * 4 = 20 bytes
    ver_ihl = (version << 4) | ihl

    if ident is None:
        ident = os.getpid() & 0xFFFF

    checksum = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    header_wo_sum = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        tos,
        total_len,
        ident,
        flags_frag,
        ttl,
        proto,
        checksum,
        src,
        dst,
    )

    checksum = ipv4_header_checksum(header_wo_sum) # changed from ipv4_checksum

    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        tos,
        total_len,
        ident,
        flags_frag,
        ttl,
        proto,
        checksum,
        src,
        dst,
    )
    return header


def parse_ipv4_header(packet: bytes) -> Tuple[Dict, int]:
    if len(packet) < 20:
        raise ValueError("Packet too short for IPv4 header")

    v_ihl = packet[0]
    version = v_ihl >> 4
    ihl = v_ihl & 0x0F
    if version != 4:
        raise ValueError(f"Not IPv4 (version={version})")

    ip_hlen = ihl * 4
    if ip_hlen < 20 or len(packet) < ip_hlen:
        raise ValueError("Invalid IPv4 IHL / packet too short")

    # Base header fields are in first 20 bytes
    (v_ihl, tos, total_len, ident, flags_frag, ttl, proto, hdr_csum, src_i, dst_i) = struct.unpack(
        "!BBHHHBBHII", packet[:20]
    )

    info = {
        "version": version,
        "ihl": ihl,
        "ip_header_len": ip_hlen,
        "tos": tos,
        "total_len": total_len,
        "id": ident,
        "flags_frag": flags_frag,
        "ttl": ttl,
        "proto": proto,
        "checksum": hdr_csum,
        "src": socket.inet_ntoa(struct.pack("!I", src_i)),
        "dst": socket.inet_ntoa(struct.pack("!I", dst_i)),
    }
    return info, ip_hlen
