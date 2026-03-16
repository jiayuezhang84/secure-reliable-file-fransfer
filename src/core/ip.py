import os
import socket
import struct
import sys
from typing import Dict, Optional, Tuple

UDP_PROTO = 17
IPV4_HEADER_LEN = 20
RECEIVE_TIMEOUT = 0.3

""" header keys """
IP_SRC = "src"
IP_DST = "dst"

""" darwin is the sys.platform value for mac """ 
ON_MAC_PLATFORM = sys.platform == "darwin"
SEND_PROTOCOL = socket.IPPROTO_UDP if ON_MAC_PLATFORM else socket.IPPROTO_RAW

def ipv4_checksum(header: bytes) -> int:
    if len(header) % 2 == 1:
        header += b"\x00"

    s = 0
    for i in range(0, len(header), 2):
        word = (header[i] << 8) + header[i + 1]
        s += word
        s = (s & 0xFFFF) + (s >> 16)

    return (~s) & 0xFFFF


"""
inits and returns a send socket based on platform/os
"""
def init_send_socket() -> socket.socket:
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, SEND_PROTOCOL)
    send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return send_socket

"""
packs and returns an ipv4 header based on platform/os
"""
def pack_ipv4_header(
    ver_ihl: int,
    tos: int,
    total_len: int,
    ident: int,
    flags_frag: int,
    ttl: int,
    proto: int,
    checksum: int,
    src: bytes,
    dst: bytes,
) -> bytes:
    if ON_MAC_PLATFORM:
        return (
            struct.pack("!BB", ver_ihl, tos)
            + struct.pack("=H", total_len)
            + struct.pack("!H", ident)
            + struct.pack("=H", flags_frag)
            + struct.pack("!BBH4s4s", ttl, proto, checksum, src, dst)
        )

    return struct.pack(
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


def build_ipv4_header(
    src_ip: str,
    dst_ip: str,
    total_len: int,
    ident: Optional[int] = None,
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

    header_wo_sum = pack_ipv4_header(
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

    checksum = ipv4_checksum(header_wo_sum)

    header = pack_ipv4_header(
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
        IP_SRC: socket.inet_ntoa(struct.pack("!I", src_i)),
        IP_DST: socket.inet_ntoa(struct.pack("!I", dst_i)),
    }
    return info, ip_hlen