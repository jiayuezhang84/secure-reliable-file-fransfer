import struct
from typing import Dict, Tuple

UDP_HEADER_LEN = 8

def build_udp_header(src_port: int, dst_port: int, payload_len: int, checksum: int = 0) -> bytes:
    """
    UDP header (8 bytes)
    """
    length = UDP_HEADER_LEN + payload_len
    checksum = 0
    return struct.pack("!HHHH", src_port, dst_port, length, checksum)


def parse_udp_header(packet: bytes, ip_header_len: int) -> Tuple[Dict, int]:
    start = ip_header_len
    end = ip_header_len + UDP_HEADER_LEN 

    if len(packet) < end:
        raise ValueError("Packet too short for UDP header")

    src_port, dst_port, length, checksum = struct.unpack("!HHHH", packet[start : end])

    info = {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": checksum,
    }
    return info, end