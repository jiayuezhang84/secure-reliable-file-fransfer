import os
import socket
import threading
import time

from src.core.ip import IPV4_HEADER_LEN, RECEIVE_TIMEOUT, IP_SRC, IP_DST
from src.core.ip import build_ipv4_header, init_send_socket, parse_ipv4_header
from src.core.udp import build_udp_header, parse_udp_header, UDP_SRC, UDP_DST
from src.core.packet import (
    pack_packet,
    unpack_packet,
    TYPE_REQ,
    TYPE_DATA,
    TYPE_ACK,
    TYPE_FIN,
    TYPE_ERR,
    SEQ,
    TYPE
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
    def handle_data(self, received_seq, payload):
        """ lock to protect expected_seq and buffer from race conditions """
        with self.lock:
            """ if the received seq number is lower than expected(OLD PACKET), then need to ack again """
            if received_seq < self.expected_seq:
                self.ack_needed = True
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

            """ after processing packet based on received_seq, need to acknowledge processed """
            self.ack_needed = True

    # Receive loop
    def receive_loop(self):
        """ run while client is running """
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

            if header[TYPE] == TYPE_DATA:
                """ process data packet into buffer or writing it out """
                self.handle_data(header[SEQ], payload)
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

        self.send_request()

        while self.running:
            time.sleep(0.1)

        self.output_fp.close()

        if self.finished:
            print(f"[CLIENT] file saved as {self.output_file}")
        elif self.server_error:
            print(f"[CLIENT] server error: {self.server_error}")
        else:
            print("[CLIENT] transfer did not complete cleanly")


def run_client(cfg, filename):
    client = SRFTClient(cfg, filename)
    client.start()