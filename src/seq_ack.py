from __future__ import annotations  # fixes python version errors

WINDOW_SIZE = 16    # max un-ACKd packets allowed at once
CUMACK_INTERVAL = 4 # send 1 ACK for every N packets received
SEQ_BYTES = 4       # bytes reserved for sequence number field
ACK_BYTES = 4       # bytes reserved for acknowledgement number field
MAX_SEQ = 2**32     # sequence numbers wrap around after this value

import struct


def pack_seq_ack(seq: int, ack: int) -> bytes:
    # Pack seq and ack numbers into 8 bytes (4 each), big-endian
    return struct.pack("!II", seq % MAX_SEQ, ack % MAX_SEQ)


def unpack_seq_ack(raw: bytes, offset: int = 0) -> tuple[int, int]:
    # Unpack seq and ack numbers from raw bytes starting at offset
    seq, ack = struct.unpack_from("!II", raw, offset)
    return seq, ack


# Tracks sequence numbers on the SENDER side.
# Keeps track of: which packets are waiting for an ACK (base),
# and what sequence number to use next (next_seq).
#
# Window picture:
#   [base ---- unacked packets ---- next_seq] [not sent yet ...]
class SenderSeqTracker:
    def __init__(self):
        self.base     = 0  # oldest packet still waiting for an ACK
        self.next_seq = 0  # sequence number to assign to the next packet

    def next(self) -> int:
        # Return the next sequence number to use, then advance the counter
        seq = self.next_seq
        self.next_seq = (self.next_seq + 1) % MAX_SEQ
        return seq

    def window_open(self) -> bool:
        # Flow control: don't send if too many packets are still unACKed
        # in_flight = how many packets are sent but not yet acknowledged
        in_flight = (self.next_seq - self.base) % MAX_SEQ
        return in_flight < WINDOW_SIZE

    def advance_base(self, ack_num: int):
        # When a cumulative ACK arrives, slide the window forward.
        # ack_num means "I received everything up to but not including ack_num"
        ahead = (ack_num - self.base) % MAX_SEQ
        if ahead <= WINDOW_SIZE:
            self.base = ack_num

    def __repr__(self):
        return f"SenderSeqTracker(base={self.base}, next={self.next_seq})"


# Tracks sequence numbers and ACKs on the RECEIVER side.
# Handles three tricky cases:
#   1. Out-of-order packets  -> buffer them until the missing one arrives
#   2. Duplicate packets     -> detect and drop them
#   3. Cumulative ACKs       -> don't send an ACK for every single packet
class ReceiverACKTracker:

    def __init__(self):
        self.expected   = 0   # the sequence number we are waiting for next
        self.ooo_buffer = {}  # out-of-order buffer: {seq_num: payload}
        self._since_ack = 0   # counts packets since last ACK was sent

        self.received_set = set()  # set of seq numbers already delivered
        self.replay_drops = 0      # count of duplicate/replayed packets dropped

    def receive(self, seq: int, payload: bytes) -> tuple[list[bytes], int | None]:
        """
        Process an incoming packet.

        Returns:
            (delivered, ack_to_send)
            - delivered: list of payloads that are now in-order and ready to write
            - ack_to_send: the cumulative ACK number to send back, or None if
                           we should wait a bit longer before sending an ACK
        """
        # Case 1: Already received this sequence number before — drop it
        if seq in self.received_set:
            self.replay_drops += 1
            return [], self.expected

        # Case 2: Sequence number is way behind — it already passed, drop it
        already_passed = (seq - self.expected) % MAX_SEQ > MAX_SEQ // 2
        if already_passed:
            return [], self.expected

        # Case 3: This is exactly the packet we were waiting for — deliver it
        if seq == self.expected:
            delivered = [payload]
            self.expected = (self.expected + 1) % MAX_SEQ
            self.received_set.add(seq)

            # Check if any buffered out-of-order packets can now be delivered too
            delivered.extend(self._drain_buffer())
            self._since_ack += len(delivered)

        else:
            # Case 4: Out-of-order packet — buffer it for later
            if seq not in self.ooo_buffer:
                self.ooo_buffer[seq] = payload
            delivered = []
            self._since_ack += 1

        # Cumulative ACK: only send an ACK every CUMACK_INTERVAL packets
        # This reduces ACK traffic on the network
        if self._since_ack >= CUMACK_INTERVAL:
            self._since_ack = 0
            return delivered, self.expected  # tell caller to send an ACK now

        return delivered, None  # not time to ACK yet

    def force_ack(self) -> int:
        # Force an ACK right now regardless of the interval counter.
        # Used when a FIN arrives or we need to flush.
        self._since_ack = 0
        return self.expected

    def _drain_buffer(self) -> list[bytes]:
        # After delivering an in-order packet, check if the out-of-order buffer
        # has the next packets too. Keep delivering until there is a gap again.
        #
        # Example: expected=3, buffer has {3: ..., 4: ..., 6: ...}
        #   -> delivers seq 3 and 4, stops at 6 (gap), expected becomes 5
        drained = []
        while self.expected in self.ooo_buffer:
            drained.append(self.ooo_buffer.pop(self.expected))
            self.expected = (self.expected + 1) % MAX_SEQ
        return drained

    def __repr__(self):
        return (
            f"ReceiverACKTracker(expected={self.expected}, "
            f"buffered={sorted(self.ooo_buffer.keys())})"
        )


def generate_nonce(seq: int, session_id: bytes) -> bytes:
    # Build a 12-byte nonce for AES-GCM using session_id + seq number.
    # This ensures every packet gets a unique nonce (required by AES-GCM).
    return session_id[:8] + struct.pack("!I", seq % MAX_SEQ)