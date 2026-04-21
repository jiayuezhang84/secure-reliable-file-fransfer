import socket
import threading
import time
import os
import hashlib

from config import get_psk
from src.core.ip import IPV4_HEADER_LEN, RECEIVE_TIMEOUT, IP_SRC, IP_DST
from src.core.ip import init_send_socket, build_ipv4_header, parse_ipv4_header
from src.core.udp import build_udp_header, parse_udp_header, UDP_SRC, UDP_DST
from src.core.packet import (
    pack_packet,
    unpack_packet,
    pack_secure_packet,
    unpack_secure_packet,
    TYPE_REQ,
    TYPE_DATA,
    TYPE_ACK,
    TYPE_FIN,
    TYPE_ERR,
    TYPE_HELLO_CLIENT,
    TYPE_HELLO_SERVER,
    TYPE_FIN_DIGEST,
    SEQ,
    TYPE,
    PAYLOAD,
    SENT_AT,
    ACK,
    extract_rec_at_client_bit_map
)
from src.core.checksum_utils import encrypt_packet, decrypt_packet, build_add
from src.core.security import (
    handle_client_hello,
    build_server_hello,
    derive_keys
)

EMPTY_BYTES = b""
"""
maximum number of bitmap based retransmissions that can be triggered
per ack received from client at server
"""
BIT_MAP_RETRANSMIT_LIMIT = 8


def compute_sha256(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.digest()


def compute_md5(path: str) -> str:
    """
    Compute MD5 hash of a file, returned as a hex string.
    Required by the assignment to verify file integrity (md5sum on both sides).
    """
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


class SRFTServer:
    def __init__(self, cfg, attack_mode=None):
        self.cfg = cfg

        self.server_ip = cfg.network.server_ip
        self.server_port = cfg.network.server_port

        self.chunk_size = cfg.transfer.chunk_size
        self.window_size = cfg.transfer.send_window_packets

        self.rto = cfg.timers.rto_ms / 1000

        self.security_enabled = getattr(cfg.security, "enabled", False)
        self.verbose_logs_enabled = getattr(cfg.debug, "verbose_logs", False)
        self.psk = b""
        if self.security_enabled:
            self.psk = get_psk(cfg)

        self.send_socket = init_send_socket()

        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

        """ binding receive socket at server to server IP, with a timeout """
        self.recv_socket.bind((self.server_ip, 0))
        self.recv_socket.settimeout(RECEIVE_TIMEOUT)

        # sliding window state
        self.base = 0 # base is the first packet in the sliding window of packets to send
        self.next_seq = 0
        self.unacked = {}

        # for large file transfer: multi threading
        self.lock = threading.Lock()

        """ using file handle and eof flag to read file chunks per window """
        self.file_handle = None
        self.eof_reached = False
        self.fin_sent = False
        self.transmission_active = False
        """ transmission_id is unique identifier / counter for identifying current file transfer session """
        self.transmission_id = 0
        self.retransmission_thread = None

        self.packets_sent = 0
        self.retransmissions = 0
        self.packets_from_client = 0

        self.client_ip = None
        self.client_port = None

        self.running = True

        self.client_nonce = None
        self.server_nonce = None
        self.session_id = None

        self.enc_key = None
        self.ack_key = None

        self.handshake_done = False

        self.original_digest = None

        self.aead_failures = 0
        self.replay_drops = 0
        self.sha256_match = False

        # For the transfer report file
        self.current_filename    = None   # name of the file being transferred
        self.file_size_bytes     = 0      # size of the file in bytes
        self.transfer_start_time = None   # when the transfer started
        self.original_md5        = None   # MD5 of the original file (for report)

        # ------------------------------------------------------------------
        # Attack mode state
        # attack_mode is None (normal), "tamper", "replay", or "inject"
        # ------------------------------------------------------------------
        self.attack_mode = attack_mode

        # For tamper: have we already tampered with the first packet?
        self._tamper_done = False

        # For replay: store the first DATA packet bytes so we can resend later
        self._replay_packet = None
        self._replay_sent = False

        # For inject: have we already injected the garbage packet?
        self._inject_done = False

        if attack_mode:
            print(f"[SERVER][ATTACK] Attack mode enabled: --attack {attack_mode}")

    def log_verbose(self, message):
        if self.verbose_logs_enabled:
            print(message)

    # ------------------------------------------------------------------
    # Attack helpers
    # ------------------------------------------------------------------

    def _apply_tamper(self, packet: bytes) -> bytes:
        """
        Flip 2 bits inside the CIPHERTEXT portion of the packet.
        The packet layout (SRFT payload only, no IP/UDP headers here) is:
          - SRFT header : 24 bytes
          - session_id  :  8 bytes
          - nonce       : 12 bytes
          - ciphertext  : remaining bytes  <-- we corrupt here

        We recalculate the SRFT checksum after tampering so the packet
        passes the outer checksum check and reaches AES-GCM decryption,
        where it will fail and increment aead_failures.
        """
        from src.core.packet import checksum16, HEADER_FORMAT
        import struct

        SRFT_HEADER_LEN  = 24
        SESSION_ID_LEN   = 8
        NONCE_LEN        = 12
        CIPHERTEXT_START = SRFT_HEADER_LEN + SESSION_ID_LEN + NONCE_LEN  # = 44

        if len(packet) < CIPHERTEXT_START + 10:
            return packet

        packet_as_list = bytearray(packet)

        # Corrupt two bytes inside the ciphertext
        target1 = CIPHERTEXT_START + 2
        target2 = CIPHERTEXT_START + 5
        packet_as_list[target1] ^= 0b00000011
        packet_as_list[target2] ^= 0b11000000

        # Recalculate SRFT checksum so outer check still passes
        fields = struct.unpack(HEADER_FORMAT, bytes(packet_as_list[:SRFT_HEADER_LEN]))
        magic, version, msg_type, flags, seq, ack, payload_len, window, _, reserved = fields
        header_no_checksum = struct.pack(
            HEADER_FORMAT, magic, version, msg_type, flags,
            seq, ack, payload_len, window, 0, reserved
        )
        new_checksum = checksum16(header_no_checksum + bytes(packet_as_list[SRFT_HEADER_LEN:]))
        fixed_header = struct.pack(
            HEADER_FORMAT, magic, version, msg_type, flags,
            seq, ack, payload_len, window, new_checksum, reserved
        )
        packet_as_list[:SRFT_HEADER_LEN] = fixed_header

        print(f"[SERVER][ATTACK] tamper: corrupted ciphertext at bytes {target1} and {target2}")
        return bytes(packet_as_list)

    def _send_inject(self):
        """
        Send a completely random garbage packet to the client.
        This simulates an attacker injecting forged packets.
        The client's AES-GCM will reject it -> AEAD failure increments.
        """
        # Build a random payload that looks like it could be a packet
        # but has no valid AEAD tag -- the client will drop it immediately
        fake_nonce      = os.urandom(12)
        fake_ciphertext = os.urandom(60)
        forged_packet = pack_secure_packet(
            TYPE_DATA,
            seq=99,
            ack=0,
            session_id=self.session_id,
            nonce=fake_nonce,
            ciphertext=fake_ciphertext
        )

        print("[SERVER][ATTACK] inject: sending forged packet with random ciphertext")
        self.send_udp_packet(self.client_ip, self.server_port, self.client_port, forged_packet)

    def _schedule_replay(self, packet: bytes):
        """
        After a short delay, resend an old valid DATA packet.
        This simulates a replay attack -- sending a previously captured packet.
        The client has already seen this seq number -> replay drop increments.
        """
        saved_client_ip   = self.client_ip
        saved_client_port = self.client_port

        def _do_replay():
            # Wait until the transfer is likely done, then replay the old packet
            time.sleep(0.5)
            print("[SERVER][ATTACK] replay: resending captured DATA packet")
            self.send_udp_packet(
                saved_client_ip,
                self.server_port,
                saved_client_port,
                packet
            )

        replay_thread = threading.Thread(target=_do_replay, daemon=True)
        replay_thread.start()

    # ------------------------------------------------------------------
    # Core send functions
    # ------------------------------------------------------------------

    def send_udp_packet(self, dst_ip, src_port, dst_port, payload):
        udp_header = build_udp_header(src_port, dst_port, payload, self.server_ip, dst_ip)
        ip_header = build_ipv4_header(
            self.server_ip,
            dst_ip,
            IPV4_HEADER_LEN + len(udp_header) + len(payload)
        )

        packet = ip_header + udp_header + payload
        self.send_socket.sendto(packet, (dst_ip, 0))
        self.packets_sent += 1

    """ this function sends packet from server to client, and adds entry into unacked buffer
    using sequence number as key to track sent packets which have not been acked by client.
    since it updates unacked shared buffer, this function should always be called from code
    holding lock to avoid race conditions.
    """
    def send_packet_and_track_ack(self, msg_type, seq, payload):
        if self.security_enabled and self.handshake_done:
            nonce = os.urandom(12)

            aad = build_add(self.session_id, seq, 0, msg_type)

            ciphertext = encrypt_packet(
                payload,
                self.enc_key,
                nonce,
                aad
            )

            packet = pack_secure_packet(
                msg_type,
                seq,
                0,
                self.session_id,
                nonce,
                ciphertext
            )
        else:
            packet = pack_packet(msg_type, seq, 0, payload)

        # ------------------------------------------------------------------
        # Attack mode hooks -- only trigger on DATA packets, only once each
        # ------------------------------------------------------------------
        if msg_type == TYPE_DATA:

            # TAMPER: corrupt the first DATA packet before sending
            if self.attack_mode == "tamper" and not self._tamper_done:
                self._tamper_done = True
                tampered = self._apply_tamper(packet)
                self.send_udp_packet(self.client_ip, self.server_port, self.client_port, tampered)

            # REPLAY: save the first DATA packet to resend later
            if self.attack_mode == "replay" and self._replay_packet is None:
                self._replay_packet = packet
                print(f"[SERVER][ATTACK] replay: captured DATA seq={seq} for later replay")
                # Schedule the replay to fire after transfer completes
                self._schedule_replay(packet)

            # INJECT: send a garbage packet right after the first real packet
            if self.attack_mode == "inject" and not self._inject_done:
                self._inject_done = True
                # Send the real packet first, then inject garbage right after
                self.send_udp_packet(self.client_ip, self.server_port, self.client_port, packet)
                self.unacked[seq] = {
                    PAYLOAD: packet,
                    SENT_AT: time.time(),
                    TYPE: msg_type,
                }
                self._send_inject()
                return  # already tracked, skip the normal send below

        self.send_udp_packet(self.client_ip, self.server_port, self.client_port, packet)

        self.unacked[seq] = {
            PAYLOAD: packet,
            SENT_AT: time.time(),
            TYPE: msg_type,
        }

    def _read_next_file_chunk(self):
        if self.file_handle is None:
            self.eof_reached = True
            return None

        chunk = self.file_handle.read(self.chunk_size)
        if chunk == EMPTY_BYTES:
            self.eof_reached = True
            return None

        return chunk

    """ get the packet data to do the retransmission  """
    def _get_retransmission_packet_data(self, seq):
        """ first get the packet data reference for unacked packet """
        packet_data = self.unacked.get(seq)
        if packet_data is None or self.client_ip is None or self.client_port is None:
            return None

        """ mark send at time now, because we are going to send it now,
        and we dont want server to repick this for retransmission now """
        packet_data[SENT_AT] = time.time()

        return (
            self.client_ip,
            self.client_port,
            packet_data[PAYLOAD],
            packet_data[TYPE],
        )

    """ send the retransmission via send_udp_packet,
    not send and track ack, because we want to resend
    an already tracked unacked packet """
    def _send_retransmission_packet(self, seq, retransmit_info):

        client_ip, client_port, payload, msg_type = retransmit_info
        self.send_udp_packet(client_ip, self.server_port, client_port, payload)
        self.retransmissions += 1

        if msg_type in (TYPE_FIN, TYPE_FIN_DIGEST):
            packet_type = "FIN"
        else:
            packet_type = "DATA"

        self.log_verbose(f"[SERVER] retransmitted {packet_type} seq {seq}")


    """ identify the oldest unacked packet,
    check if it should be retransmitted,
    then fetch its retransmit info,
    must be called with lock held """
    def _find_oldest_unacked_packet(self):

        """ pick the oldest unacked seq number  """
        if self.base in self.unacked:
            oldest_unacked_seq = self.base
        else:
            oldest_unacked_seq = min(self.unacked)

        packet_data = self.unacked.get(oldest_unacked_seq)

        """ nothing to transmit """
        if packet_data is None:
            return None

        """ too little time passed, dont retransmit retranmission """
        if self.rto > time.time() - packet_data[SENT_AT]:
            return None

        """ get all required data for the retransmission """
        retransmit_info = self._get_retransmission_packet_data(oldest_unacked_seq)
        if retransmit_info is None:
            return None

        """ return picked oldest packet to retransmit  """
        return oldest_unacked_seq, retransmit_info

    """ determines which packets actually need to be retransmitted,
    based on the cumulative ack from client, and known received at client seqs 
    after the cumulative ack"""
    def _fill_retransmissions(self, oldest_seq_needed_at_client, received_seqs):
        if not received_seqs:
            return []

        """ get the largest received seq number, oldest(cumulative acked) to largest received seq number at client
        to determine which packets to retransmit
        """
        largest_received_seq = max(received_seqs)
        retransmissions = []
        too_soon = self.rto / 4
        now = time.time()

        for seq in sorted(self.unacked):
            """ already received at client, no need to retransmit """
            if seq in received_seqs:
                continue

            """ dont care about these, we don't track them in bit map """
            if seq > largest_received_seq or seq < oldest_seq_needed_at_client:
                continue


            packet_data = self.unacked.get(seq)
            """ if the packet was sent too recently, then we don't want to send it again 
            """
            if now - packet_data[SENT_AT] < too_soon:
                continue

            retransmit_info = self._get_retransmission_packet_data(seq)
            if retransmit_info:
                retransmissions.append((seq, retransmit_info))

            """ stay within limit of how many retransmissions can be done per cumulative
            ack received from client at server """
            if len(retransmissions) >= BIT_MAP_RETRANSMIT_LIMIT:
                break

        return retransmissions

    """
    determine which packets actually need to be resent between packets which 
    were sent after the base cumulative ack,
    and update base cumulative ack to new value if all packets received beyond current base cumulative ack
    till new value,
    needs to be called when lock held
    """
    def _get_retransmissions(self, oldest_seq_needed_at_client, received_seqs):
        retransmissions = []

        """ base is oldest unacked seq num at server,
        if client is still waiting for base seq at server """

        """ we can remove all seqs that are older than the oldest unacked seq at client,
         because client already has them """
        sorted_unacked = sorted(list(self.unacked))
        for seq in sorted_unacked:
            if seq < oldest_seq_needed_at_client:
                self.unacked.pop(seq)

        """ update the knowledge of oldest seq needed at client at server """
        self.base = oldest_seq_needed_at_client

        """ update window with new packets after base updated, and send the new packets in window """
        self.send_sliding_window()

        """ determine which packets are not present at client, and add them to retransmissions """
        not_present_at_client = self._fill_retransmissions(oldest_seq_needed_at_client, received_seqs)
        retransmissions.extend(not_present_at_client)


        return retransmissions

    """ dedup the list of retransmissions before sending them"""
    def _send_retransmissions(self, retransmissions):

        seen_retransmit_seqs = set()

        for seq, retransmit_info in retransmissions:
            if seq in seen_retransmit_seqs:
                continue

            seen_retransmit_seqs.add(seq)
            self._send_retransmission_packet(seq, retransmit_info)

    """ this function sends as many new data packets allowed using sliding window constraint, and
        sends FIN packet only after all the data is sent to client and acknowledged by client,
        since it calls send_packet_and_track_ack and sets next_seq this function should always be called from code
        holding lock to avoid race conditions.
        """
    def send_sliding_window(self):
        """ send new file chunks until the server's send window is full """
        while self.transmission_active and not self.eof_reached and self.next_seq < self.base + self.window_size:
            chunk = self._read_next_file_chunk()
            if chunk is None:
                break

            seq = self.next_seq
            self.send_packet_and_track_ack(TYPE_DATA, seq, chunk)
            self.next_seq += 1

        """ stopping condition, once all the data is sent and acked, send the FIN packet """
        if self.transmission_active and self.eof_reached and not self.fin_sent and not self.unacked:
            fin_seq = self.next_seq

            if self.security_enabled and self.original_digest is not None:
                self.send_packet_and_track_ack(TYPE_FIN_DIGEST, fin_seq, self.original_digest)
            else:
                self.send_packet_and_track_ack(TYPE_FIN, fin_seq, EMPTY_BYTES)

            self.fin_sent = True
            self.next_seq += 1

    """ reset the server state variables after transfers compelete, updates shared state variables,
    must be called after holding lock
    """
    def reset_transfer_variables(self):
        self.base = 0
        self.next_seq = 0
        self.unacked.clear()
        if self.file_handle is not None:
            self.file_handle.close()
            self.file_handle = None
        self.eof_reached = False
        self.fin_sent = False
        self.transmission_active = False
        self.client_ip = None
        self.client_port = None
        self.original_digest = None
        self.current_filename = None
        self.file_size_bytes = 0
        self.transfer_start_time = None
        self.original_md5 = None

    def handle_request(self, client_ip, client_port, filename):
        """ need to handle case when another transfer in progress and error out on new request """
        if self.transmission_active:
            err_packet = pack_packet(TYPE_ERR, 0, 0, b"Another transfer already in progress")
            self.send_udp_packet(client_ip, self.server_port, client_port, err_packet)
            return

        """ need to error out when the request file is not found, use name to check this  """
        if not os.path.isfile(filename):
            err_packet = pack_packet(TYPE_ERR, 0, 0, f"File not found: {filename}".encode())
            self.send_udp_packet(client_ip, self.server_port, client_port, err_packet)
            return

        """ prepare metadata and handle of the file to send  """
        file_size_bytes = os.path.getsize(filename)
        original_digest = compute_sha256(filename)
        file_handle = open(filename, "rb")

        """ set server state variables, need to acquire lock to update shared variables  """
        with self.lock:
            self.transmission_active = True
            self.transmission_id += 1
            self.base = 0
            self.next_seq = 0
            self.unacked.clear()
            self.client_ip = client_ip
            self.client_port = client_port
            self.file_handle = file_handle
            self.eof_reached = False
            self.fin_sent = False
            self.original_digest     = original_digest
            self.original_md5        = compute_md5(filename)
            self.current_filename    = filename
            self.file_size_bytes     = file_size_bytes
            self.transfer_start_time = time.time()
            self.packets_sent = 0
            self.retransmissions = 0
            self.packets_from_client = 0
            self.aead_failures = 0
            self.sha256_match = False

            current_transmission_id = self.transmission_id

            """ actually fill and send packet payload/chunks for the first time """
            self.send_sliding_window()

        """ init the background thread to check for and trigger retransmission """
        self.retransmission_thread = threading.Thread(
            target=self.check_retransmission,
            args=(current_transmission_id,),
            daemon=True,
        )
        self.retransmission_thread.start()

    def check_retransmission(self, transmission_id):
        while self.running:
            """ sleep before trying retransmission """
            time.sleep(self.rto)

            """ need to iterate over all unacknowledged packets and determine which have timed out
            and need to be resent """
            retransmissions = []
            """ need to acquire lock before reading transmission_id and unacked """
            with self.lock:
                """ transmission id has to be the currently active transmission id and transfer has to be active for this
                transmission to continue """
                if transmission_id != self.transmission_id or not self.transmission_active:
                    return

                retransmit_info = self._find_oldest_unacked_packet()
                if retransmit_info:
                    retransmissions.append(retransmit_info)

            self._send_retransmissions(retransmissions)

    def process_ack(self, oldest_seq_needed_at_client, sack_payload=b""):
        received_seqs = extract_rec_at_client_bit_map(oldest_seq_needed_at_client, sack_payload)
        retransmissions = []
        transfer_finished = False
        duration_seconds = 0.0
        """ acquire lock before reading/writing unacked map and transmission_active """
        with self.lock:
            """ only need to process acks when there is active transmission """
            if not self.transmission_active:
                return

            if oldest_seq_needed_at_client < self.base or oldest_seq_needed_at_client > self.next_seq:
                return

            retransmissions = self._get_retransmissions(oldest_seq_needed_at_client, received_seqs)

            if self.fin_sent and oldest_seq_needed_at_client >= self.next_seq and not self.unacked:
                self.sha256_match = True

                if self.transfer_start_time is not None:
                    duration_seconds = time.time() - self.transfer_start_time
                # if transfer_finished:
                self.write_report(duration_seconds)
                transfer_finished = True
                self.reset_transfer_variables()
                return

        self._send_retransmissions(retransmissions)

    # Receive loop
    def receive_loop(self):
        """ run while server is running """
        while self.running:
            try:
                packet, _ = self.recv_socket.recvfrom(65535)
            except socket.timeout:
                """ just keep listening if socket timed out trying to receive a message """
                continue

            self.log_verbose(f"[SERVER][DEBUG] raw packet len={len(packet)}")

            """ unpack the ip and udp data, and get the offset where SRFT payload content starts """
            try:
                ip_header_data, ip_header_len = parse_ipv4_header(packet)
                udp_header_data, content_start_index = parse_udp_header(packet, ip_header_len)
            except ValueError as exc:
                self.log_verbose(f"[SERVER][DEBUG] dropped before SRFT parse: {exc}")
                continue

            """ early exit further processing for packets not coming to intended dst """
            if ip_header_data[IP_DST] != self.server_ip:
                continue
            if udp_header_data[UDP_DST] != self.server_port:
                continue

            """ parse the SRFT data """
            try:
                header, payload = unpack_packet(packet[content_start_index:])
            except ValueError as exc:
                self.log_verbose(f"[SERVER][DEBUG] dropped SRFT packet: {exc}")
                continue

            if header[TYPE] == TYPE_HELLO_CLIENT:
                self.packets_from_client += 1

                ok, client_nonce = handle_client_hello(self.psk, payload)
                if not ok:
                    print("[SERVER] Handshake failed: bad ClientHello")
                    continue

                self.client_nonce = client_nonce
                self.server_nonce, self.session_id, hello_reply_payload = build_server_hello(
                    self.psk,
                    self.client_nonce
                )

                hello_reply_packet = pack_packet(TYPE_HELLO_SERVER, 0, 0, hello_reply_payload)
                self.send_udp_packet(
                    ip_header_data[IP_SRC],
                    self.server_port,
                    udp_header_data[UDP_SRC],
                    hello_reply_packet
                )

                self.enc_key, self.ack_key = derive_keys(
                    self.psk,
                    self.client_nonce,
                    self.server_nonce
                )

                self.client_ip = ip_header_data[IP_SRC]
                self.client_port = udp_header_data[UDP_SRC]
                self.handshake_done = True

                print("[SERVER] Handshake complete")
                continue

            if header[TYPE] == TYPE_REQ:
                self.packets_from_client += 1

                if self.security_enabled and not self.handshake_done:
                    self.log_verbose("[SERVER][DEBUG] ignored REQ before handshake")
                    continue

                filename = payload.decode().strip()
                print(f"[SERVER][DEBUG] accepted REQ for {filename!r}")
                self.handle_request(ip_header_data[IP_SRC], udp_header_data[UDP_SRC], filename)

            elif header[TYPE] == TYPE_ACK:
                if ip_header_data[IP_SRC] != self.client_ip or udp_header_data[UDP_SRC] != self.client_port:
                    self.log_verbose(
                        "[SERVER][DEBUG] ignored ACK from unexpected peer "
                        f"{ip_header_data[IP_SRC]}:{udp_header_data[UDP_SRC]}"
                    )
                    continue

                self.packets_from_client += 1

                if self.security_enabled and self.handshake_done:
                    try:
                        secure_header, session_id, nonce, ciphertext = unpack_secure_packet(
                            packet[content_start_index:]
                        )
                    except ValueError as exc:
                        self.log_verbose(f"[SERVER][DEBUG] dropped secure ACK: {exc}")
                        continue

                    if session_id != self.session_id:
                        continue

                    aad = build_add(session_id, secure_header[SEQ], secure_header[ACK], TYPE_ACK)

                    plaintext = decrypt_packet(
                        ciphertext,
                        self.enc_key,
                        nonce,
                        aad
                    )

                    if plaintext is None:
                        self.aead_failures += 1
                        continue

                    self.log_verbose(f"[SERVER][DEBUG] accepted secure ACK {secure_header[ACK]}")
                    self.process_ack(secure_header[ACK], plaintext)
                else:
                    self.log_verbose(f"[SERVER][DEBUG] accepted ACK {header[ACK]}")
                    self.process_ack(header[ACK], payload)

    def write_report(self, duration_seconds: float):
        """
        Saved to transfer_report.txt and printed to terminal.
        """
        hours        = int(duration_seconds // 3600)
        minutes      = int((duration_seconds % 3600) // 60)
        seconds      = int(duration_seconds % 60)
        duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        filename   = self.current_filename or "N/A"
        size_bytes = self.file_size_bytes or 0
        md5_hash   = self.original_md5 or "N/A"

        border = "=" * 50

        lines = [
            border,
            "SERVER REPORT",
            border,
            f"Name of the transferred file:             {filename}",
            f"Size of the transferred file:             {size_bytes} bytes",
            f"Number of packets sent from the server:   {self.packets_sent}",
            f"Number of retransmitted packets:          {self.retransmissions}",
            f"Number of packets received from client:   {self.packets_from_client}",
            f"Time duration of the file transfer:       {duration_str}",
            f"Original file MD5:                        {md5_hash}",
            f"Security enabled (PSK + AEAD):            {'Yes' if self.security_enabled else 'No'}",
            f"Handshake status:                         {'Success' if self.handshake_done else 'Fail'}",
            f"AEAD authentication failures:             {self.aead_failures}",
            border,
        ]

        report_text = "\n".join(lines)
        print("\n" + report_text + "\n")

        report_path = "transfer_report.txt"
        with open(report_path, "w") as f:
            f.write(report_text + "\n")
        print(f"[SERVER] Report saved to {report_path}")

    def start(self):
        print(f"[SERVER] Listening on {self.server_ip}:{self.server_port}")
        if self.attack_mode:
            print(f"[SERVER] *** ATTACK MODE: {self.attack_mode} ***")

        """ receive loop in try except, so that 
        when we ^C out of server, the report still gets written """
        try:
            self.receive_loop()
        except KeyboardInterrupt:
            self.running = False
            print("\n[SERVER] Shutting down")


def run_server(cfg, attack_mode=None):
    server = SRFTServer(cfg, attack_mode=attack_mode)
    server.start()