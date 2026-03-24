import struct

MAGIC = b"SRFT"
VERSION = 1

TYPE_REQ  = 1
TYPE_DATA = 2
TYPE_ACK  = 3
TYPE_FIN  = 4
TYPE_ERR  = 5

HEADER_FORMAT = "!4sBBHIIHHHH"
HEADER_LEN = struct.calcsize(HEADER_FORMAT)

""" header keys """
SEQ = "seq"
TYPE = "type"
PAYLOAD = "payload"
SENT_AT = "sent_at"
ACK = "ack"

# security header filed
SESSION_ID_LEN = 8
NONCE_LEN = 12
SEC_PREFIX_LEN = SESSION_ID_LEN + NONCE_LEN

TYPE_HELLO_CLIENT = 6
TYPE_HELLO_SERVER = 7
TYPE_FIN_DIGEST = 8

def checksum16(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"

    s = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        s += word
        s = (s & 0xFFFF) + (s >> 16)

    return (~s) & 0xFFFF


def pack_packet(msg_type: int, seq: int, ack: int,
                payload: bytes, window: int = 0, flags: int = 0) -> bytes:

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

    checksum = checksum16(header_wo_checksum + payload)

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

    return header + payload


def unpack_packet(packet: bytes):
    if len(packet) < HEADER_LEN:
        raise ValueError("Packet too short")

    fields = struct.unpack(HEADER_FORMAT, packet[:HEADER_LEN])

    magic, version, msg_type, flags, seq, ack, payload_len, window, checksum, _ = fields

    if magic != MAGIC:
        raise ValueError("Invalid magic")

    payload = packet[HEADER_LEN:HEADER_LEN + payload_len]

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

    if checksum16(header_wo_checksum + payload) != checksum:
        raise ValueError("Checksum mismatch")

    return {
        TYPE: msg_type,
        SEQ: seq,
        ACK: ack,
        "payload_len": payload_len,
        "window": window
    }, payload
    
# pack security fields into payload
def pack_secure_payload(session_id: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    assert len(session_id) == SESSION_ID_LEN, "session id must be 8 bytes"
    assert len(nonce) == NONCE_LEN, "nonce must be 12 bytes"
    return session_id + nonce + ciphertext

def unpack_secure_payload(payload: bytes) -> tuple[bytes, bytes, bytes]:
    if len(payload) < SEC_PREFIX_LEN:
        raise ValueError(f"Payload too short for security field: {len(payload)} bytes")
    session_id = payload[:SESSION_ID_LEN]
    nonce = payload[SESSION_ID_LEN : SESSION_ID_LEN + NONCE_LEN]
    ciphertext = payload[SEC_PREFIX_LEN:]
    return session_id, nonce, ciphertext

def pack_secure_packet(msg_type: int, seq: int, ack: int,
                       session_id: bytes, nonce: bytes, ciphertext: bytes,
                       window: int = 0, flags: int = 0) -> bytes:
    payload = pack_secure_packet(session_id, nonce, ciphertext)
    return pack_packet(msg_type, seq, ack, payload, window, flags)

def unpack_secure_packet(packet: bytes) -> tuple[dict, bytes, bytes, bytes]:
    header, payload = unpack_packet(packet)
    session_id, nonce, ciphertext = unpack_secure_payload(payload)
    return header, session_id, nonce, ciphertext