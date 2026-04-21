from __future__ import annotations  # allows forward type hints (ignore for now)

import struct

# ===== BASIC PROTOCOL INFO =====
MAGIC = b"SRFT"   # identifies this as OUR protocol packet
VERSION = 1       # protocol version (in case we upgrade later)

# ===== PACKET TYPES =====
TYPE_REQ  = 1     # start transfer
TYPE_DATA = 2     # send file data
TYPE_ACK  = 3     # acknowledge received data
TYPE_FIN  = 4     # transfer complete
TYPE_ERR  = 5     # error occurred

# ===== HEADER STRUCTURE =====
HEADER_FORMAT = "!4sBBHIIHHHH"  # defines how header is packed into bytes
HEADER_LEN = struct.calcsize(HEADER_FORMAT)  # total header size

# ===== HEADER KEYS (for dictionary access) =====
SEQ = "seq"          # sequence number (order of packets)
TYPE = "type"        # packet type
PAYLOAD = "payload"  # actual data
SENT_AT = "sent_at"  # timestamp (used for retransmission)
ACK = "ack"          # acknowledgment number

# ===== SECURITY (PHASE 2) =====
SESSION_ID_LEN = 8   # identifies connection
NONCE_LEN = 12       # used for encryption uniqueness
SEC_PREFIX_LEN = SESSION_ID_LEN + NONCE_LEN  # total prefix before ciphertext

TYPE_HELLO_CLIENT = 6   # client starts secure handshake
TYPE_HELLO_SERVER = 7   # server responds
TYPE_FIN_DIGEST = 8     # final file hash verification


# ===== CHECKSUM FUNCTION =====
def checksum16(data: bytes) -> int:
    # To detect if data was corrupted during transmission.

    if len(data) % 2 == 1:
        data += b"\x00"

    s = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        s += word
        s = (s & 0xFFFF) + (s >> 16)

    return (~s) & 0xFFFF


# ===== BUILD SRFT PACKET =====
def pack_packet(msg_type: int, seq: int, ack: int,
                payload: bytes, window: int = 0, flags: int = 0) -> bytes:

    # convert our data into a structured packet
    # so it can be sent over the network.
    # This function builds the SRFT header + attaches the payload.

    payload_len = len(payload)
    checksum = 0
    reserved = 0

    header_wo_checksum = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        VERSION,
        msg_type,
        flags,
        seq,
        ack,
        payload_len,
        window,
        checksum,
        reserved
    )

    # checksum must include BOTH header and data
    checksum = checksum16(header_wo_checksum + payload)

    # rebuild header so checksum field is correct
    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        VERSION,
        msg_type,
        flags,
        seq,
        ack,
        payload_len,
        window,
        checksum,
        reserved
    )

    # final packet = header + actual data
    return header + payload


# ===== PARSE RECEIVED PACKET =====
def unpack_packet(packet: bytes):
    # extract the SRFT header and verify it before using the data.
    if len(packet) < HEADER_LEN:
        raise ValueError("Packet too short")

    # extract header fields
    fields = struct.unpack(HEADER_FORMAT, packet[:HEADER_LEN])

    magic, version, msg_type, flags, seq, ack, payload_len, window, checksum, _ = fields

    # check if packet belongs to our protocol
    if magic != MAGIC:
        raise ValueError("Invalid magic")

    # extract actual data
    payload = packet[HEADER_LEN:HEADER_LEN + payload_len]

    # rebuild header with checksum = 0 (for verification)
    header_wo_checksum = struct.pack(
        HEADER_FORMAT,
        magic,
        version,
        msg_type,
        flags,
        seq,
        ack,
        payload_len,
        window,
        0,
        0
    )

    # verify checksum (detect corruption/tampering)
    if checksum16(header_wo_checksum + payload) != checksum:
        raise ValueError("Checksum mismatch")

    # return structured data so program can use it easily
    return {
        TYPE: msg_type,
        SEQ: seq,
        ACK: ack,
        "payload_len": payload_len,
        "window": window
    }, payload


# ===== SECURITY PAYLOAD =====
def pack_secure_payload(session_id: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    # to send encrypted data along with required info
    # (session_id + nonce) so the receiver can decrypt it correctly.
    assert len(session_id) == SESSION_ID_LEN
    assert len(nonce) == NONCE_LEN

    # combine into one payload
    return session_id + nonce + ciphertext


def unpack_secure_payload(payload: bytes) -> tuple[bytes, bytes, bytes]:
    # ensure payload is large enough
    if len(payload) < SEC_PREFIX_LEN:
        raise ValueError("Payload too short")

    # split into components
    session_id = payload[:SESSION_ID_LEN]
    nonce = payload[SESSION_ID_LEN : SESSION_ID_LEN + NONCE_LEN]
    ciphertext = payload[SEC_PREFIX_LEN:]

    return session_id, nonce, ciphertext


# ===== BUILD SECURE PACKET =====
def pack_secure_packet(msg_type: int, seq: int, ack: int,
                       session_id: bytes, nonce: bytes, ciphertext: bytes,
                       window: int = 0, flags: int = 0) -> bytes:

    # build secure payload first
    payload = pack_secure_payload(session_id, nonce, ciphertext)

    # then wrap into normal SRFT packet
    return pack_packet(msg_type, seq, ack, payload, window, flags)


# ===== PARSE SECURE PACKET =====
def unpack_secure_packet(packet: bytes) -> tuple[dict, bytes, bytes, bytes]:
    header, payload = unpack_packet(packet)

    # split secure fields
    session_id, nonce, ciphertext = unpack_secure_payload(payload)

    return header, session_id, nonce, ciphertext
