import os
import socket
import threading
import time
import hashlib

from config import get_psk
from src.core.ip import IPV4_HEADER_LEN, RECEIVE_TIMEOUT, IP_SRC, IP_DST
from src.core.ip import build_ipv4_header, init_send_socket, parse_ipv4_header
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
    ACK
)

from src.core.checksum_utils import decrypt_packet, encrypt_packet, build_add

from src.core.security import (
    build_client_hello,
    handle_server_hello,
    derive_keys
)


def compute_sha256(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.digest()


class SRFTClient:
    def __init__(self, cfg, filename):
        self.cfg = cfg
        self.filename = filename

        self.client_ip = cfg.network.client_ip
        self.client_port = cfg.network.client_port
        self.server_ip = cfg.network.server_ip
        self.server_port = cfg.network.server_port

        self.chunk_size = cfg.transfer.chunk_size
        self.ack_interval = cfg.timers.ack_interval_ms / 1000

        self.security_enabled = getattr(cfg.security, "enabled", False)
        self.psk = b""
        if self.security_enabled:
            self.psk = get_psk(cfg)

        # raw sockets
        self.send_socket = init_send_socket()

        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        
        """ binding receive socket at client IP, with a timeout """
        self.recv_socket.bind((self.client_ip, 0))
        self.recv_socket.settimeout(RECEIVE_TIMEOUT)

        # receive state
        self.expected_seq = 0
        self.buffer = {}
        self.lock = threading.Lock()

        self.running = True
        self.finished = False
        self.server_error = None

        self.output_file = f"received_{os.path.basename(filename)}"
        self.output_fp = open(self.output_file, "wb")

        self.last_ack_sent = 0.0
        """ initialize ack_needed from client to false, 
            this tracks if an ack still needs to be sent from client to server after 
            receiving payload 
        """
        self.ack_needed = False

        # phase 2 security state
        self.client_nonce = None
        self.server_nonce = None
        self.session_id = None

        self.enc_key = None
        self.ack_key = None

        self.handshake_done = False

        # reporting / counters
        self.aead_failures = 0
        self.replay_drops = 0
        self.sha256_match = False

        # replay tracking
        self.seen_secure_seqs = set()

    def send_udp_packet(self, dst_ip, src_port, dst_port, payload):
        udp_header = build_udp_header(src_port, dst_port, payload, self.client_ip, dst_ip)
        ip_header = build_ipv4_header(
            self.client_ip,
            dst_ip,
            IPV4_HEADER_LEN + len(udp_header) + len(payload)
        )
        packet = ip_header + udp_header + payload
        self.send_socket.sendto(packet, (dst_ip, 0))

    def send_client_hello(self):
        self.client_nonce, payload = build_client_hello(self.psk)
        pkt = pack_packet(TYPE_HELLO_CLIENT, 0, 0, payload)
        self.send_udp_packet(self.server_ip, self.client_port, self.server_port, pkt)
        print("[CLIENT] sent ClientHello")

    def send_request(self):
        req_payload = self.filename.encode()
        req_packet = pack_packet(TYPE_REQ, 0, 0, req_payload)
        self.send_udp_packet(self.server_ip, self.client_port, self.server_port, req_packet)
        print(f"[CLIENT] requested file: {self.filename}")

    def send_ack(self, ack_number):
        if self.security_enabled and self.handshake_done:
            seq_num = 0
            nonce = os.urandom(12)
            aad = build_add(self.session_id, seq_num, ack_number, TYPE_ACK)

            ciphertext = encrypt_packet(
                b"",
                self.enc_key,
                nonce,
                aad
            )

            ack_packet = pack_secure_packet(
                TYPE_ACK,
                seq_num,
                ack_number,
                self.session_id,
                nonce,
                ciphertext
            )
        else:
            ack_packet = pack_packet(TYPE_ACK, 0, ack_number, b"")

        self.send_udp_packet(self.server_ip, self.client_port, self.server_port, ack_packet)
        self.last_ack_sent = time.time()
        print(f"[CLIENT] sent ACK {ack_number}")

    def handle_data(self, received_seq, payload):
        with self.lock:
            """ if the received seq number is lower than expected(OLD PACKET), then need to ack again """
            if received_seq < self.expected_seq:
                self.ack_needed = True
                self.replay_drops += 1
                return

            """ if received seq number is equal to expected, then need to write output and increment expected """
            if received_seq == self.expected_seq:
                self.output_fp.write(payload)
                self.expected_seq += 1

                """ handle out of order receival """
                """ check for next consecutive payloads already received in buffer and write them out """
                while self.expected_seq in self.buffer:
                    self.output_fp.write(self.buffer.pop(self.expected_seq))
                    self.expected_seq += 1

            elif received_seq not in self.buffer:
                """ sequence number greater than expected, receiving later packets earlier out of order, add to buffer """
                self.buffer[received_seq] = payload
            else:
                self.replay_drops += 1

            """ after processing packet based on received_seq, need to acknowledge processed """
            self.ack_needed = True

    def receive_loop(self):
        while self.running:
            try:
                packet, _ = self.recv_socket.recvfrom(65535)
            except socket.timeout:
                """ just keep listening if socket timed out trying to receive a message """
                continue

            try:
                """ unpack the ip and udp data, and get the offset where SRFT payload content starts """
                ip_header_data, ip_header_len = parse_ipv4_header(packet)
                udp_header_data, content_start_index = parse_udp_header(packet, ip_header_len)
            except ValueError:
                """ just keep listening if bad packets received """
                continue

            """ early exit further processing for packets not coming from intended src to intended dst """
            if ip_header_data[IP_SRC] != self.server_ip or ip_header_data[IP_DST] != self.client_ip:
                continue
            if udp_header_data[UDP_SRC] != self.server_port or udp_header_data[UDP_DST] != self.client_port:
                continue


            """ parse the SRFT data """
            try:
                header, payload = unpack_packet(packet[content_start_index:])
            except ValueError:
                """ keep listening for the next packet parsing SRFT fails """
                continue

            if header[TYPE] == TYPE_HELLO_SERVER:
                ok, server_nonce, session_id = handle_server_hello(
                    self.psk,
                    self.client_nonce,
                    payload
                )

                if not ok:
                    self.server_error = "Handshake failed"
                    self.running = False
                    continue

                self.server_nonce = server_nonce
                self.session_id = session_id

                self.enc_key, self.ack_key = derive_keys(
                    self.psk,
                    self.client_nonce,
                    self.server_nonce
                )

                self.handshake_done = True
                print("[CLIENT] Handshake complete")
                continue

            if header[TYPE] == TYPE_DATA and self.security_enabled and self.handshake_done:
                try:
                    secure_header, session_id, nonce, ciphertext = unpack_secure_packet(
                        packet[content_start_index:]
                    )
                except ValueError:
                    continue

                if session_id != self.session_id:
                    continue

                if secure_header[SEQ] in self.seen_secure_seqs:
                    self.replay_drops += 1
                    continue

                aad = build_add(session_id, secure_header[SEQ], secure_header[ACK], TYPE_DATA)

                plaintext = decrypt_packet(
                    ciphertext,
                    self.enc_key,
                    nonce,
                    aad
                )

                if plaintext is None:
                    self.aead_failures += 1
                    continue

                self.seen_secure_seqs.add(secure_header[SEQ])
                self.handle_data(secure_header[SEQ], plaintext)

            elif header[TYPE] == TYPE_DATA:
                self.handle_data(header[SEQ], payload)

            elif header[TYPE] == TYPE_FIN_DIGEST and self.security_enabled and self.handshake_done:
                try:
                    secure_header, session_id, nonce, ciphertext = unpack_secure_packet(
                        packet[content_start_index:]
                    )
                except ValueError:
                    continue

                if session_id != self.session_id:
                    continue

                aad = build_add(session_id, secure_header[SEQ], secure_header[ACK], TYPE_FIN_DIGEST)

                sender_digest = decrypt_packet(
                    ciphertext,
                    self.enc_key,
                    nonce,
                    aad
                )

                if sender_digest is None:
                    self.aead_failures += 1
                    continue

                transfer_complete = False
                with self.lock:
                    if secure_header[SEQ] == self.expected_seq:
                        self.expected_seq += 1
                        ack_number = self.expected_seq
                        transfer_complete = True
                    else:
                        ack_number = self.expected_seq

                self.send_ack(ack_number)

                self.output_fp.flush()
                local_digest = compute_sha256(self.output_file)
                self.sha256_match = (local_digest == sender_digest)

                print(f"[CLIENT] SHA-256 match: {self.sha256_match}")

                if transfer_complete and self.sha256_match:
                    self.finished = True
                    def stop_after_delay():
                        time.sleep(2.0)
                        self.running = False
                    threading.Thread(target=stop_after_delay, daemon=True).start()
                elif not self.sha256_match:
                    self.server_error = "SHA-256 mismatch"
                    self.running = False

            elif header[TYPE] == TYPE_FIN:
                """ if a FIN type packet received from server, we must finish the file transfer """
                transfer_complete = False

                """ lock to protect expected_seq and ack_number from race conditions """
                with self.lock:
                    """ if received sequence for FIN is expected sequence, then we can complete, """
                    if header[SEQ] == self.expected_seq:
                        self.expected_seq += 1
                        ack_number = self.expected_seq
                        transfer_complete = True
                    else:
                        """ we cant complete yet, packets missing between fin seq and expected seq
                        becasue fin came too early """
                        ack_number = self.expected_seq

                """ send the current cumulative ack """
                self.send_ack(ack_number)

                if transfer_complete:
                    self.finished = True
                    self.running = False

            elif header[TYPE] == TYPE_ERR:
                """ error case header handling """
                self.server_error = payload.decode()
                self.running = False

    # ACK loop
    def ack_loop(self):
        """ run while client is running """
        while self.running:
            """ wait a little to ack  """
            time.sleep(self.ack_interval)

            """ lock to protect expected_seq and ack_number from race conditions """
            with self.lock:
                if not self.ack_needed:
                    continue

                ack_number = self.expected_seq

            """ sends cumulative ack """
            self.send_ack(ack_number)

            with self.lock:
                self.ack_needed = ack_number != self.expected_seq

    # Start client
    def start(self):
        print(f"[CLIENT] running on {self.client_ip}:{self.client_port}")
        print(f"[CLIENT] talking to server {self.server_ip}:{self.server_port}")

        recv_thread = threading.Thread(target=self.receive_loop, daemon=True)
        ack_thread = threading.Thread(target=self.ack_loop, daemon=True)

        recv_thread.start()
        ack_thread.start()

        if self.security_enabled:
            self.send_client_hello()

            while self.running and not self.handshake_done:
                time.sleep(0.1)

        if self.running:
            self.send_request()

        while self.running:
            time.sleep(0.1)
        
        time.sleep(2.0)  # wait for delayed attack packets

        self.output_fp.close()

        print(f"[CLIENT] Security enabled: {'Yes' if self.security_enabled else 'No'}")
        print(f"[CLIENT] Handshake status: {'Success' if self.handshake_done else 'Fail'}")
        print(f"[CLIENT] AEAD authentication failures: {self.aead_failures}")
        print(f"[CLIENT] Replay drops: {self.replay_drops}")
        print(f"[CLIENT] SHA-256 match: {'Yes' if self.sha256_match else 'No'}")

        if self.finished:
            print(f"[CLIENT] file saved as {self.output_file}")
        elif self.server_error:
            print(f"[CLIENT] server error: {self.server_error}")
        else:
            print("[CLIENT] transfer did not complete cleanly")


def run_client(cfg, filename):
    client = SRFTClient(cfg, filename)
    client.start()