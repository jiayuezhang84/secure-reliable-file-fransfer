# Open raw socket + send packets
import socket
import threading
import time
import os

from src.core.ip import IPV4_HEADER_LEN, RECEIVE_TIMEOUT, IP_SRC, IP_DST
from src.core.ip import init_send_socket, build_ipv4_header, parse_ipv4_header
from src.core.udp import build_udp_header, parse_udp_header, UDP_SRC, UDP_DST
from src.core.packet import (
    pack_packet,
    unpack_packet,
    TYPE_REQ,
    TYPE_DATA,
    TYPE_ACK,
    TYPE_FIN,
    TYPE_ERR,
    TYPE_HELLO_CLIENT,
    TYPE_HELLO_SERVER,
    SEQ,
    TYPE,
    PAYLOAD,
    SENT_AT,
    ACK,
    pack_secure_packet
)
from src.core.checksum_utils import encrypt_packet, build_add
from src.core.security import (
    load_psk,
    handle_client_hello,
    build_server_hello,
    derive_keys
)

EMPTY_BYTES = b""


class SRFTServer:
    def __init__(self, cfg):
        self.cfg = cfg

        self.server_ip = cfg.network.server_ip
        self.server_port = cfg.network.server_port

        self.chunk_size = cfg.transfer.chunk_size
        self.window_size = cfg.transfer.send_window_packets

        self.rto = cfg.timers.rto_ms / 1000

        # raw sockets
        self.send_socket = init_send_socket()

        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

        """ binding receive socket at server to server IP, with a timeout """
        self.recv_socket.bind((self.server_ip, 0))
        self.recv_socket.settimeout(RECEIVE_TIMEOUT)

        # sliding window state
        self.base = 0
        self.next_seq = 0
        self.unacked = {}

        # for large file transfer: multi threading
        self.lock = threading.Lock()
        self.file_chunks = []
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

        # PHASE 2 SECURITY STATE
        self.psk = load_psk()

        self.client_nonce = None
        self.server_nonce = None
        self.session_id = None

        self.enc_key = None
        self.ack_key = None

        self.handshake_done = False

    # Raw packet send
    def send_udp_packet(self, dst_ip, src_port, dst_port, payload):
        udp_header = build_udp_header(src_port, dst_port, payload, self.server_ip, dst_ip)
        ip_header = build_ipv4_header(self.server_ip, dst_ip, IPV4_HEADER_LEN + len(udp_header) + len(payload))

        packet = ip_header + udp_header + payload
        self.send_socket.sendto(packet, (dst_ip, 0))

        self.packets_sent += 1

    """
    this function sends packet from server to client, and adds entry into unacked buffer
    using sequence number as key to track sent packets which have not been acked by client.
    since it updates unacked shared buffer, this function should always be called from code
    holding lock to avoid race conditions.
    """
    def send_packet_and_track_ack(self, msg_type, seq, payload):
        if self.handshake_done:
            nonce = os.urandom(12)

            aad = build_add(self.session_id, seq, 0, 0)

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

    """
    this function sends as many new data packets allowed using sliding window constraint, and
    sends FIN packet only after all the data is sent to client and acknowledged by client,
    since it calls send_packet_and_track_ack and sets next_seq this function should always be called from code
    holding lock to avoid race conditions.
    """
    def send_sliding_window(self):
        """ send new file chunks until the server's send window is full """
        while self.next_seq < len(self.file_chunks) and self.next_seq < self.base + self.window_size:
            seq = self.next_seq
            self.send_packet_and_track_ack(TYPE_DATA, seq, self.file_chunks[seq])
            self.next_seq += 1

        """ stopping condition, once all the data is sent and acked, send the FIN packet """
        if self.transmission_active and not self.fin_sent and self.next_seq >= len(self.file_chunks) and not self.unacked:
            fin_seq = self.next_seq
            self.send_packet_and_track_ack(TYPE_FIN, fin_seq, EMPTY_BYTES)
            self.fin_sent = True
            self.next_seq += 1

    """
    reset the server state variables after transfers complete, updates shared state variables,
    must be called after holding lock
    """
    def reset_transfer_variables(self):
        self.base = 0
        self.next_seq = 0
        self.unacked.clear()
        self.file_chunks = []
        self.fin_sent = False
        self.transmission_active = False
        self.client_ip = None
        self.client_port = None

    # Handle filename
    def handle_request(self, client_ip, client_port, filename):
        """ need to handle case when another transfer in progress and error out on new request """
        if self.transmission_active:
            err_packet = pack_packet(TYPE_ERR, 0, 0, b"Another transfer already in progress")
            self.send_udp_packet(client_ip, self.server_port, client_port, err_packet)
            return

        """ need to error out when the requested file is not found """
        if not os.path.isfile(filename):
            err_packet = pack_packet(TYPE_ERR, 0, 0, f"File not found: {filename}".encode())
            self.send_udp_packet(client_ip, self.server_port, client_port, err_packet)
            return

        """ chunkify the file, and each chunk will be sent as a packet payload """
        file_chunks = []
        with open(filename, "rb") as file_obj:
            while True:
                chunk = file_obj.read(self.chunk_size)
                if chunk == EMPTY_BYTES:
                    break
                file_chunks.append(chunk)

        """ set server state variables """
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

    # Retransmission: guarantee safe transfer
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
                packet_type = "FIN" if msg_type == TYPE_FIN else "DATA"
                print(f"[SERVER] retransmitted {packet_type} seq {seq}")

    # ACK processing
    def process_ack(self, ack):
        with self.lock:
            if not self.transmission_active:
                return

            if ack <= self.base or ack > self.next_seq:
                return

            for seq in sorted(list(self.unacked)):
                if seq < ack:
                    self.unacked.pop(seq)

            self.base = ack
            self.send_sliding_window()

            if self.fin_sent and ack >= self.next_seq and not self.unacked:
                self.reset_transfer_variables()

    # Receive loop
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

            # HANDLE CLIENT HELLO
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

                if not self.handshake_done:
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
                print(f"[SERVER][DEBUG] accepted ACK {header[ACK]}")
                self.process_ack(header[ACK])

    # Start
    def start(self):
        print(f"[SERVER] Listening on {self.server_ip}:{self.server_port}")
        self.receive_loop()


def run_server(cfg):
    server = SRFTServer(cfg)
    server.start()