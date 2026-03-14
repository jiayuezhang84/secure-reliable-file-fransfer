# Open raw socket + send packets
import socket

import socket
import threading
import time
import os

from src.core.ip import init_send_socket, build_ipv4_header, parse_ipv4_header, IPV4_HEADER_LEN
from src.core.udp import build_udp_header, parse_udp_header
from src.core.packet import (
    pack_packet,
    unpack_packet,
    TYPE_REQ,
    TYPE_DATA,
    TYPE_ACK,
    TYPE_FIN,
    TYPE_ERR
)


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

        # sliding window state
        self.base = 0
        self.next_seq = 0
        self.unacked = {}

        # for large file transfer: multi threading 
        self.lock = threading.Lock()
        ############ TODO ############

        self.packets_sent = 0
        self.retransmissions = 0
        self.packets_from_client = 0

        self.client_ip = None
        self.client_port = None

        self.running = True

    # Raw packet send
    def send_udp_packet(self, dst_ip, src_port, dst_port, payload):

        udp_header = build_udp_header(src_port, dst_port, len(payload))
        ip_header = build_ipv4_header(self.server_ip, dst_ip, IPV4_HEADER_LEN + len(udp_header) + len(payload))

        packet = ip_header + udp_header + payload

        self.send_socket.sendto(packet, (dst_ip, 0))

        self.packets_sent += 1

    # Handle filename
    def handle_request(self, client_ip, client_port, filename):
        pass

    # Retransmission: guarantee safe transfer
    def check_retransmission(self, client_ip, client_port):
        pass

    # ACK processing
    def process_ack(self, ack):
        pass

    # Receive loop
    def receive_loop(self):
        pass

    # Start
    def start(self):
        print(f"[SERVER] Listening on {self.server_ip}:{self.server_port}")
        self.receive_loop()


def run_server(cfg):
    server = SRFTServer(cfg)
    server.start()