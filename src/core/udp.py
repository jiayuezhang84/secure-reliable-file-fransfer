import struct
from typing import Dict, Tuple
from src.core.checksum_utils import udp_checksum_ipv4

UDP_HEADER_LEN = 8

def build_udp_header(src_port: int, dst_port: int, payload: bytes, src_ip: str, dst_ip: str) -> bytes:
    length = UDP_HEADER_LEN + len(payload)
    
    # First build with checksum = 0
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    
    # Compute real checksum using pseudo-header
    checksum = udp_checksum_ipv4(src_ip, dst_ip, header, payload)
    
    # Rebuild with correct checksum
    return struct.pack("!HHHH", src_port, dst_port, length, checksum)

def parse_udp_header(packet: bytes, ip_header_len: int) -> Tuple[Dict, int]:
    start = ip_header_len
    end = ip_header_len + UDP_HEADER_LEN
    if len(packet) < end:
        raise ValueError("Packet too short for UDP header")
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", packet[start:end])
    info = {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": checksum,
    }
    return info, end
