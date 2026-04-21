from __future__ import annotations # fixes python version errors

import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def pad_if_odd_length(data):
    """
    If the number of bytes is odd, add one 0 byte at the end.
    Why? Because checksum adds 16-bit words (2 bytes at a time).
    """
    if len(data) % 2 == 1:
        return data + b"\x00"
    return data


def add_16bit_words(data):
    """
    Add the data as 16-bit words (2 bytes each) using one's-complement addition.
    This returns the SUM (not flipped yet).
    """
    data = pad_if_odd_length(data)

    total = 0
    index = 0

    while index < len(data):
        high_byte = data[index]
        low_byte = data[index + 1]

        word = (high_byte << 8) + low_byte

        total = total + word

        # Wrap-around carry
        total = (total & 0xFFFF) + (total >> 16)

        index = index + 2

    return total


def internet_checksum(data):
    """
    Full Internet checksum:
    1) Add all 16-bit words with wrap-around carry.
    2) Flip all bits (one's complement).
    """
    sum_16 = add_16bit_words(data)
    checksum = (~sum_16) & 0xFFFF
    return checksum


def ipv4_header_checksum(ip_header_bytes):
    """
    IPv4 header checksum is computed ONLY over the IPv4 header.
    The checksum field inside the header must be 0 when computing.
    """
    return internet_checksum(ip_header_bytes)


def ipv4_string_to_bytes(ip_str):
    """
    Convert '192.168.1.10' to 4 bytes.
    """
    parts = ip_str.split(".")
    return bytes([
        int(parts[0]),
        int(parts[1]),
        int(parts[2]),
        int(parts[3])
    ])


def udp_checksum_ipv4(src_ip_str, dst_ip_str, udp_header_bytes, udp_payload_bytes):
    """
    UDP checksum for IPv4 is computed over:
    (pseudo-header) + (UDP header) + (UDP payload)

    The pseudo-header is NOT actually sent as part of UDP,
    but it is included in checksum calculation to protect:
    - source IP
    - destination IP
    - protocol number
    - UDP length

    IMPORTANT RULE:
    - The UDP checksum field must be 0 when computing.
    """

    src_ip = ipv4_string_to_bytes(src_ip_str)
    dst_ip = ipv4_string_to_bytes(dst_ip_str)

    udp_length = len(udp_header_bytes) + len(udp_payload_bytes)

    # Pseudo-header:
    # src IP (4), dst IP (4), zero (1), protocol (1), UDP length (2)
    pseudo_header = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, 17, udp_length)

    data_to_check = pseudo_header + udp_header_bytes + udp_payload_bytes
    return internet_checksum(data_to_check)

MAX_SEQ = 2**32
aead_failures = 0

# aad init
# ===== BUILD AAD (IMPORTANT FOR SECURITY) =====
def build_add(session_id: bytes, seq: int, ack:int, flags:int) -> bytes:
    # AAD = Additional Authenticated Data
    # These values are NOT encrypted, but are protected.
    # If attacker modifies seq/ack/session → decryption fails.

    return(
        session_id +                           # identifies connection
        struct.pack("!I", seq % MAX_SEQ) +     # sequence number (4 bytes)
        struct.pack("!I", ack % MAX_SEQ) +     # acknowledgment number (4 bytes)
        struct.pack("!B", flags & 0xFF)        # flags (1 byte)
    )
    
# ===== ENCRYPT PACKET =====
def encrypt_packet(plaintext: bytes, enc_key: bytes, nonce: bytes, aad: bytes) -> bytes:
    # Encrypts the data so:
    # - attackers cannot read it (confidentiality)
    # - any modification is detected (integrity via AES-GCM)
    # AAD is included → protects metadata (seq, ack, session_id)

    return AESGCM(enc_key).encrypt(nonce, plaintext, aad)

# ===== DECRYPT PACKET =====
def decrypt_packet(ciphertext: bytes, enc_key: bytes, nonce: bytes, aad: bytes) -> bytes | None:
    # Decrypts the data AND verifies integrity.
    #
    # If ANYTHING was modified:
    # - ciphertext
    # - nonce
    # - AAD (seq, ack, session_id)
    #
    # → decryption fails

    global aead_failures

    try:
        return AESGCM(enc_key).decrypt(nonce, ciphertext, aad)

    except Exception:
        # failure = tampering / wrong key / replay attack
        aead_failures += 1
        return None
