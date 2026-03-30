import socket
import threading
import time
import os
import hashlib

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
    ACK
)
from src.core.checksum_utils import encrypt_packet, decrypt_packet, build_add
from src.core.security import (
    load_psk,
    handle_client_hello,
    build_server_hello,
    derive_keys
)

EMPTY_BYTES = b""


def compute_sha256(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.digest()


class SRFTServer:
    def __init__(self, cfg):
        self.cfg = cfg

        self.server_ip = cfg.network.server_ip
        self.server_port = cfg.network.server_port

        self.chunk_size = cfg.transfer.chunk_size
        self.window_size = cfg.transfer.send_window_packets

        self.rto = cfg.timers.rto_ms / 1000

        self.security_enabled = getattr(cfg.security, "enabled", False)
        self.psk = load_psk() if self.security_enabled else b""

        self.send_socket = init_send_socket()

        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.recv_socket.bind((self.server_ip, 0))
        self.recv_socket.settimeout(RECEIVE_TIMEOUT)

        self.base = 0
        self.next_seq = 0
        self.unacked = {}

        self.lock = threading.Lock()
        self.file_chunks = []
        self.fin_sent = False
        self.transmission_active = False
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

        self.seen_acks = set()

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

        self.send_udp_packet(self.client_ip, self.server_port, self.client_port, packet)

        self.unacked[seq] = {
            PAYLOAD: packet,
            SENT_AT: time.time(),
            TYPE: msg_type,
        }

    def send_sliding_window(self):
        while self.next_seq < len(self.file_chunks) and self.next_seq < self.base + self.window_size:
            seq = self.next_seq
            self.send_packet_and_track_ack(TYPE_DATA, seq, self.file_chunks[seq])
            self.next_seq += 1

        if self.transmission_active and not self.fin_sent and self.next_seq >= len(self.file_chunks) and not self.unacked:
            fin_seq = self.next_seq

            if self.security_enabled and self.original_digest is not None:
                self.send_packet_and_track_ack(TYPE_FIN_DIGEST, fin_seq, self.original_digest)
            else:
                self.send_packet_and_track_ack(TYPE_FIN, fin_seq, EMPTY_BYTES)

            self.fin_sent = True
            self.next_seq += 1

    def reset_transfer_variables(self):
        self.base = 0
        self.next_seq = 0
        self.unacked.clear()
        self.file_chunks = []
        self.fin_sent = False
        self.transmission_active = False
        self.client_ip = None
        self.client_port = None
        self.original_digest = None
        self.seen_acks.clear()

    def handle_request(self, client_ip, client_port, filename):
        if self.transmission_active:
            err_packet = pack_packet(TYPE_ERR, 0, 0, b"Another transfer already in progress")
            self.send_udp_packet(client_ip, self.server_port, client_port, err_packet)
            return

        if not os.path.isfile(filename):
            err_packet = pack_packet(TYPE_ERR, 0, 0, f"File not found: {filename}".encode())
            self.send_udp_packet(client_ip, self.server_port, client_port, err_packet)
            return

        file_chunks = []
        with open(filename, "rb") as file_obj:
            while True:
                chunk = file_obj.read(self.chunk_size)
                if chunk == EMPTY_BYTES:
                    break
                file_chunks.append(chunk)

        with self.lock:
            self.transmission_active = True
            self.transmission_id += 1
            self.base = 0
            self.next_seq = 0
            self.unacked.clear()
            self.client_ip = client_ip
            self.client_port = client_port
            self.file_chunks = file_chunks
            self.fin_sent = False
            self.original_digest = compute_sha256(filename)

            current_transmission_id = self.transmission_id
            self.send_sliding_window()

        self.retransmission_thread = threading.Thread(
            target=self.check_retransmission,
            args=(current_transmission_id,),
            daemon=True,
        )
        self.retransmission_thread.start()

    def check_retransmission(self, transmission_id):
        while self.running:
            time.sleep(self.rto)

            timed_out = []
            with self.lock:
                if transmission_id != self.transmission_id or not self.transmission_active:
                    return

                now = time.time()
                client_ip = self.client_ip
                client_port = self.client_port

                for seq, packet_data in self.unacked.items():
                    if now - packet_data[SENT_AT] >= self.rto:
                        packet_data[SENT_AT] = now
                        timed_out.append((seq, packet_data[PAYLOAD], packet_data[TYPE]))

            for seq, payload, msg_type in timed_out:
                self.send_udp_packet(client_ip, self.server_port, client_port, payload)
                self.retransmissions += 1
                packet_type = "FIN" if msg_type in (TYPE_FIN, TYPE_FIN_DIGEST) else "DATA"
                print(f"[SERVER] retransmitted {packet_type} seq {seq}")

    def process_ack(self, ack):
        with self.lock:
            if not self.transmission_active:
                return

            if ack in self.seen_acks:
                self.replay_drops += 1
                return
            self.seen_acks.add(ack)

            if ack <= self.base or ack > self.next_seq:
                return

            for seq in sorted(list(self.unacked)):
                if seq < ack:
                    self.unacked.pop(seq)

            self.base = ack
            self.send_sliding_window()

            if self.fin_sent and ack >= self.next_seq and not self.unacked:
                self.sha256_match = True
                self.reset_transfer_variables()

    def receive_loop(self):
        while self.running:
            try:
                packet, _ = self.recv_socket.recvfrom(65535)
            except socket.timeout:
                continue

            print(f"[SERVER][DEBUG] raw packet len={len(packet)}")

            try:
                ip_header_data, ip_header_len = parse_ipv4_header(packet)
                udp_header_data, content_start_index = parse_udp_header(packet, ip_header_len)
            except ValueError as exc:
                print(f"[SERVER][DEBUG] dropped before SRFT parse: {exc}")
                continue

            if ip_header_data[IP_DST] != self.server_ip:
                continue
            if udp_header_data[UDP_DST] != self.server_port:
                continue

            try:
                header, payload = unpack_packet(packet[content_start_index:])
            except ValueError as exc:
                print(f"[SERVER][DEBUG] dropped SRFT packet: {exc}")
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
                    print("[SERVER][DEBUG] ignored REQ before handshake")
                    continue

                filename = payload.decode().strip()
                print(f"[SERVER][DEBUG] accepted REQ for {filename!r}")
                self.handle_request(ip_header_data[IP_SRC], udp_header_data[UDP_SRC], filename)

            elif header[TYPE] == TYPE_ACK:
                if ip_header_data[IP_SRC] != self.client_ip or udp_header_data[UDP_SRC] != self.client_port:
                    print(
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
                        print(f"[SERVER][DEBUG] dropped secure ACK: {exc}")
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

                    print(f"[SERVER][DEBUG] accepted secure ACK {secure_header[ACK]}")
                    self.process_ack(secure_header[ACK])
                else:
                    print(f"[SERVER][DEBUG] accepted ACK {header[ACK]}")
                    self.process_ack(header[ACK])

    def start(self):
        print(f"[SERVER] Listening on {self.server_ip}:{self.server_port}")
        self.receive_loop()

        print(f"[SERVER] Security enabled (PSK + AEAD): {'Yes' if self.security_enabled else 'No'}")
        print(f"[SERVER] Handshake status: {'Success' if self.handshake_done else 'Fail'}")
        print(f"[SERVER] AEAD authentication failures (invalid packets dropped): {self.aead_failures}")
        print(f"[SERVER] Replay drops (duplicate/out-of-window packets): {self.replay_drops}")
        print(f"[SERVER] SHA-256 match: {'Yes' if self.sha256_match else 'No'}")


def run_server(cfg):
    server = SRFTServer(cfg)
    server.start()