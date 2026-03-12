WINDOW_SIZE = 16 # max un-ACKd packets allowed
CUMACK_INTERVAL = 4 # 1 ACK every N packets
SEQ_BYTES = 4 # bytes reserved for seq num
ACK_BYTES = 4
MAX_SEQ = 2**32

import struct

def pack_seq_ack(seq: int, ack: int) -> bytes:
	return struct.pack("!II", seq % MAX_SEQ, ack % MAX_SEQ)

def unpack_seq_ack(raw: bytes, offset: int = 0) -> tuple[int, int]:
	seq, ack = struct.unpack_from("!II", raw, offset)
	return seq, ack

# sender seq tracker, increment packet number, tracks next seq num to assign to sender
# ACKed (sent) - base -(sent, waiting for ACK)- next_seq (not sent)
class SenderSeqTracker:
	def __init__(self):
		self.base     = 0   # oldest un Acked packet
		self.next_seq = 0   # next seq# 

	def next(self) -> int:
    # return seq# for next packet
		seq = self.next_seq
		self.next_seq = (self.next_seq + 1) % MAX_SEQ
		return seq
  
  # flow control, if too many unAcked, stop
  # check if we can send another packet if within window size
	def window_open(self) -> bool:
		in_flight = (self.next_seq - self.base) % MAX_SEQ
		return in_flight < WINDOW_SIZE
  
	def advance_base(self, ack_num: int):
    # slide window forward on cumulative ACK
		ahead = (ack_num - self.base) % MAX_SEQ
		if ahead <= WINDOW_SIZE:
			self.base = ack_num

	def __repr__(self):
		return f"SenderSeqTracker(base={self.base}, next={self.next_seq})"

# receiver ACK
# handles: packets out of order; duplicated packets; prevent sending ACK for every packet
class ReceiverACKTracker:
  # track next expected seq#

	def __init__(self):
		self.expected    = 0 # next seq#
		self.ooo_buffer  = {} # early arrivals: {seq_num: payload} 
		self._since_ack  = 0 # counter for cumulative ACK
   
  # public api 
	def receive(self, seq: int, payload: bytes) -> tuple[list[bytes], int | None]:
    # delivered: list of in-order payload
    # ack_to_send: cumulative ACK to send back
	  
    # duplicate detection
		already_passed = (seq - self.expected) % MAX_SEQ > MAX_SEQ // 2
		if already_passed:
			return [], self.expected

		# in order packet
		if seq == self.expected:
			delivered = [payload]
			self.expected = (self.expected + 1) % MAX_SEQ
			
			delivered.extend(self._drain_buffer())
			self._since_ack += len(delivered)
		else:
			# out of order packet
			if seq not in self.ooo_buffer:
					self.ooo_buffer[seq] = payload
			delivered = []
			self._since_ack += 1

		# cumulative ack 
		if self._since_ack >= CUMACK_INTERVAL:
			self._since_ack = 0
			return delivered, self.expected   

		return delivered, None                

	def force_ack(self) -> int:
    # return curr cumulative ACK
		self._since_ack = 0
		return self.expected

	def __repr__(self):
		return (f"ReceiverACKTracker(expected={self.expected}, "
			f"buffered={sorted(self.ooo_buffer.keys())})")
  
# private helper 
def _drain_buffer(self) -> list[bytes]:
	drained = []
	while self.expected in self.ooo_buffer:
		drained.append(self.ooo_buffer.pop(self.expected))
		self.expected = (self.expected + 1) % MAX_SEQ
	return drained