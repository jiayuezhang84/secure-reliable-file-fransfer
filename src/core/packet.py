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
        "type": msg_type,
        "seq": seq,
        "ack": ack,
        "payload_len": payload_len,
        "window": window
    }, payload