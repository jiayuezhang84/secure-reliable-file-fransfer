import os
import socket
import threading
import time

from src.core.ip import build_ipv4_header, init_send_socket, parse_ipv4_header, IPV4_HEADER_LEN
from src.core.udp import build_udp_header, parse_udp_header
from src.core.packet import (
    pack_packet,
    unpack_packet,
    TYPE_REQ,
    TYPE_DATA,
    TYPE_ACK,
    TYPE_FIN,
    TYPE_ERR,
)


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

        # raw sockets
        self.send_socket = init_send_socket()

        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

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

    # Raw packet send
    def send_udp_packet(self, dst_ip, src_port, dst_port, payload):
        udp_header = build_udp_header(src_port, dst_port, len(payload))
        ip_header = build_ipv4_header(self.client_ip, dst_ip, IPV4_HEADER_LEN + len(udp_header) + len(payload))

        packet = ip_header + udp_header + payload
        self.send_socket.sendto(packet, (dst_ip, 0))

    # Send REQ
    def send_request(self):
        req_payload = self.filename.encode()
        req_packet = pack_packet(TYPE_REQ, 0, 0, req_payload)
        self.send_udp_packet(self.server_ip, self.client_port, self.server_port, req_packet)

        print(f"[CLIENT] requested file: {self.filename}")

    # Send ACK
    def send_ack(self, ack_number):
        ack_packet = pack_packet(TYPE_ACK, 0, ack_number, b"")
        self.send_udp_packet(self.server_ip, self.client_port, self.server_port, ack_packet)
        self.last_ack_sent = time.time()

        print(f"[CLIENT] sent ACK {ack_number}")

    # Handle packet
    def handle_data(self):
       pass

    # Receive loop
    def receive_loop(self):
        pass

    # ACK loop
    def ack_loop(self):
        pass

    # Start client
    def start(self):
        print(f"[CLIENT] running on {self.client_ip}:{self.client_port}")
        print(f"[CLIENT] talking to server {self.server_ip}:{self.server_port}")

        recv_thread = threading.Thread(target=self.receive_loop, daemon=True)
        ack_thread = threading.Thread(target=self.ack_loop, daemon=True)

        recv_thread.start()
        ack_thread.start()

        self.send_request()

        while self.running:
            time.sleep(0.1)

        self.output_fp.close()

        if self.finished:
            print(f"[CLIENT] file saved as {self.output_file}")
        else:
            print("[CLIENT] transfer did not complete cleanly")


def run_client(cfg, filename):
    client = SRFTClient(cfg, filename)
    client.start()