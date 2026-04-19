# Secure Reliable File Transfer (SRFT)

A UDP-based file transfer application that combines reliable delivery with strong cryptographic security. Built from scratch using raw IPv4/UDP sockets with manual header construction and AES-256-GCM encryption.

---

## Table of Contents

1. [How to Run](#how-to-run)
2. [How It Works](#how-it-works)
3. [Features Implemented](#features-implemented)
4. [Design Summary](#design-summary)
5. [Project Structure](#project-structure)
6. [Transfer Performance](#transfer-performance)
7. [Known Limitations and Errors](#known-limitations-and-errors)
8. [Lessons Learned](#lessons-learned)
9. [Possible Future Improvements](#possible-future-improvements)

---

## How to Run

### Requirements

- Python 3.8+
- `cryptography` library
- Root privileges (raw sockets require `sudo`)

```bash
pip install cryptography
```

### Running on AWS (Two EC2 Instances)

Edit `config.json` with the private IPs of your two EC2 instances:

```json
{
  "network": {
    "client_ip": "<CLIENT_PRIVATE_IP>",
    "server_ip": "<SERVER_PRIVATE_IP>",
    "client_port": 40000,
    "server_port": 50000
  },
  "transfer": {
    "chunk_size": 1200,
    "send_window_packets": 64
  },
  "timers": {
    "rto_ms": 300,
    "ack_interval_ms": 50
  },
  "security": {
    "enabled": true,
    "psk": "<hex string, minimum 32 characters>"
  }
}
```

**On the server EC2 instance** — run first:

```bash
sudo PYTHONPATH=. python3 main.py --mode server --config config.json
```

**On the client EC2 instance** — then run:

```bash
sudo PYTHONPATH=. python3 main.py --mode client --config config.json --file <filename>
```

The server writes `transfer_report.txt` after each transfer completes.

### Running Security Attack Simulation (server side)

These modes inject a deliberate security event to test client-side defenses:

```bash
# Flip bits in ciphertext → AEAD authentication failure on client
sudo PYTHONPATH=. python3 main.py --mode server --config config.json --attack tamper

# Resend a previously captured packet → replay detection triggers
sudo PYTHONPATH=. python3 main.py --mode server --config config.json --attack replay

# Send a forged garbage packet → rejected by AEAD tag check
sudo PYTHONPATH=. python3 main.py --mode server --config config.json --attack inject
```

### Running Local Integration Tests (Docker)

```bash
docker-compose up -d
./scripts/docker_retransmission_test.sh         # small file
./scripts/docker_retransmission_test_10mb.sh    # 10 MB file
```

Both scripts binary-compare sent and received files and fail if they differ.

---

## How It Works

### Protocol Flow (Security Enabled)

```
Client                              Server
  |                                   |
  |-- TYPE_HELLO_CLIENT -----------> |   nonce_c (16B) + HMAC-SHA256(psk, nonce_c)
  |<-- TYPE_HELLO_SERVER ----------- |   nonce_s (16B) + session_id (8B) + HMAC
  |    (both sides independently derive enc_key + ack_key via HKDF-SHA256)
  |                                   |
  |-- TYPE_REQ --------------------> |   filename (plaintext)
  |<-- TYPE_DATA seq=0 ------------- |   session_id | nonce | AES-GCM ciphertext
  |<-- TYPE_DATA seq=1 ------------- |
  |  ...                             |
  |-- TYPE_ACK (cumulative) -------> |   every 50 ms
  |<-- TYPE_FIN_DIGEST ------------- |   SHA-256 of entire plaintext file
  |-- TYPE_ACK --------------------> |
  |    (client verifies SHA-256)     |
```

**Without security,** the handshake is skipped, DATA packets carry raw plaintext, and `TYPE_FIN` is sent instead of `TYPE_FIN_DIGEST`.

### Reliable Delivery

- **Sliding window:** server sends up to 64 unACKed packets simultaneously (configurable via `send_window_packets`)
- **Retransmission:** a background thread checks every `rto_ms` (300 ms default) and resends any packet older than the RTO
- **Cumulative ACKs:** client sends one ACK every `ack_interval_ms` (50 ms) carrying the next expected sequence number; this slides the server's window forward
- **Out-of-order buffering:** client buffers early-arriving packets and flushes them in order once gaps are filled

### Security

- **Handshake auth:** HMAC-SHA256 over nonces using PSK — proves both sides know the key without transmitting it
- **Key derivation:** HKDF-SHA256 with `salt = client_nonce || server_nonce` and `info = "SRFT-session-keys"` produces a fresh 64-byte key material split into `enc_key` (32B) and `ack_key` (32B) per session
- **Per-packet encryption:** AES-256-GCM with a fresh random 12-byte nonce per packet
- **AAD:** `session_id || seq || ack || msg_type` (17 bytes) is bound to the GCM tag — any header modification fails authentication
- **Replay protection:** client tracks all seen sequence numbers in `seen_secure_seqs`; duplicates are dropped and counted
- **Integrity:** server sends SHA-256 of the full plaintext file in `TYPE_FIN_DIGEST`; client verifies after reassembly

### Packet Format

```
SRFT Header (24 bytes):
  MAGIC(4) | VERSION(1) | MSG_TYPE(1) | FLAGS(2) |
  SEQ(4)   | ACK(4)     | PAYLOAD_LEN(2) | WINDOW(2) |
  CHECKSUM(2) | RESERVED(2)

Secure packet payload:
  session_id (8) | nonce (12) | ciphertext (variable)
```

Packet types: `REQ(1)`, `DATA(2)`, `ACK(3)`, `FIN(4)`, `ERR(5)`, `HELLO_CLIENT(6)`, `HELLO_SERVER(7)`, `FIN_DIGEST(8)`

---

## Features Implemented

| Feature | Implemented |
|---------|-------------|
| Raw IPv4/UDP socket construction | Yes |
| Sliding window (configurable size) | Yes |
| RTO-based retransmission | Yes |
| Cumulative ACKs | Yes |
| Out-of-order packet buffering | Yes |
| PSK handshake (HMAC-SHA256) | Yes |
| Session key derivation (HKDF-SHA256) | Yes |
| Per-packet AES-256-GCM encryption | Yes |
| Authenticated header (AAD) | Yes |
| Replay attack detection | Yes |
| End-to-end SHA-256 integrity check | Yes |
| Attack simulation (tamper / replay / inject) | Yes |
| Transfer report (`transfer_report.txt`) | Yes |
| Docker integration tests | Yes |
| macOS + Linux platform support | Yes |

---

## Design Summary

The application is split into three layers:

**Transport layer** (`src/core/ip.py`, `src/core/udp.py`): manual construction and parsing of raw IPv4 and UDP headers using `struct.pack`. Requires `IP_HDRINCL` and `sudo`. Handles macOS vs. Linux byte-order differences.

**Protocol layer** (`src/core/packet.py`, `src/seq_ack.py`): defines the 24-byte SRFT header format, pack/unpack functions, Internet checksum, and sliding window / ACK tracking utilities.

**Security layer** (`src/core/security.py`, `src/core/checksum_utils.py`): HMAC-SHA256 handshake, HKDF-SHA256 key derivation, AES-256-GCM encrypt/decrypt, and AAD construction.

**Application layer** (`src/server.py`, `src/client.py`): `SRFTServer` (sender) manages the sliding window, retransmission thread, attack hooks, and report generation. `SRFTClient` (receiver) manages out-of-order buffering, decryption, replay detection, and SHA-256 verification. Both run receive and ACK loops as concurrent threads.

---

## Project Structure

```
.
├── main.py                     # CLI entry point (--mode, --config, --file, --attack)
├── config.py                   # Configuration loader and validator
├── config.json                 # Default configuration (security enabled)
├── config_retransmission.json  # Docker test config (no security, faster timeouts)
├── docker-compose.yml          # SEED Ubuntu containers for integration tests
├── src/
│   ├── client.py               # SRFTClient — receiver, reassembly, decryption
│   ├── server.py               # SRFTServer — sender, retransmission, attack modes
│   ├── seq_ack.py              # Sequence/ACK tracker utilities
│   └── core/
│       ├── packet.py           # Packet format, pack/unpack, checksum
│       ├── security.py         # PSK handshake, HKDF key derivation
│       ├── checksum_utils.py   # Checksums, AES-GCM encrypt/decrypt, AAD builder
│       ├── ip.py               # Raw IPv4 header construction and parsing
│       └── udp.py              # UDP header construction and parsing
└── scripts/
    ├── run_server.sh
    ├── run_client.sh
    ├── docker_retransmission_test.sh
    └── docker_retransmission_test_10mb.sh
```

---

## Transfer Performance

All tests run on AWS EC2 instances. Packet loss was simulated using `tc netem` on the network interface. Duration is wall-clock time reported in `transfer_report.txt`.

| File | File Size | No Packet Loss | 2% Packet Loss | 3% Packet Loss | 4% Packet Loss | Secure (No Packet Loss) |
|------|-----------|---------------|----------------|----------------|----------------|------------------------|
| small_test.bin | ~500 KB | | | | | |
| medium_test.bin | ~5 MB | | | | | |
| large_test.bin | ~10 MB | | | | | |


---

## Known Limitations and Errors

- **Single concurrent transfer:** the server supports only one active transfer at a time. A second `TYPE_REQ` while a transfer is in progress receives a `TYPE_ERR` response.
- **No dynamic congestion control:** the window size is fixed (default is 64). There is no slow-start or AIMD which can lead to higher latency.
- **Raw socket filtering:** both server and client use raw sockets and filter by IP/port in software. On hosts with busy background traffic, irrelevant packets are parsed and discarded, which causes CPU overhead.
- **No fragmentation handling:** packets larger than the path MTU may be silently dropped by the network. The default `chunk_size` of 1200 bytes is chosen to stay well under typical Ethernet MTU (1500 bytes) but this is not dynamically negotiated.
- **PSK is static:** the PSK is stored in `config.json` in plaintext. There is no key rotation or certificate-based authentication.

---

## Lessons Learned
- **AEAD matters in practice**: Before adding AAD, tampering with a packet's seq number and the receiver wouldn't be noticed. The outer SRFT checksum can be recalculated by the attacker. Only the GCM tag can prevent header manipulation.
- **Unique Nonce is critical**: If reusing a nonce with the same key, AES-GCM can be broken. Setting nonce as a fresh random 12 bytes per packet is a better design decision.
- **UDP can't guarantee delivery**: When simulating packet loss with tc netem, the out-of-order buffer becomes necessary.
- **Checksums are not security**: The SRFT header checksum detects accidental corruption but not intentional tampering. An attacker can flip bits and recompute a valid checksum. This reinforced that integrity and authenticity require cryptographic primitives, not just checksums.
- **Sliding window sizing matters**: A window that is too small underutilizes the network; too large fills buffers and causes avoidable drops. Tuning the default to 64 packets was a balance between throughput and memory use.

---

## Possible Future Improvements
- **Congestion control**: Replace the fixed window size with a dynamic congestion window. Implementing TCP-style slow start and AIMD would improve performance under packet loss.
- **Certificate-based authentication**: The PSK is a shared secret stored in plaintext config. An improved version could use asymmetric cryptography (e.g., DH key exchange) so no secret needs to be pre-distributed.
- **Selective ACK**: Currently the implementation uses cumulative ACKs, which causes the server to retransmit everything from base onward on loss. Selective ACK would let the client report exactly which packets it has buffered, so only truly missing packets are retransmitted.
- **Multi-client support**: The server currently handles one transfer at a time. A future version could use the session ID as a demultiplexer to support concurrent transfers from multiple clients.
- **Resumable transfers**: If a transfer is interrupted, the client must start over from scratch. Adding a resume mechanism (tracking which chunks were already received) would make large file transfers more robust.

---

## Transfer Report Format

After each transfer the server writes `transfer_report.txt`:

```
==================================================
SRFT Transfer Report
==================================================
Name of the transferred file:                           example.bin
Size of the transferred file:                           10485760 bytes (10240.00 KB)
The number of packets sent from the server:             8739
The number of retransmitted packets from the server:    12
The number of packets received from the client:         145
The time duration of the file transfer (hh:mm:ss):      00:00:04
Security enabled (PSK + AEAD):                          Yes
Handshake status:                                        Success
AEAD authentication failures (invalid packets dropped): 0
Replay drops (duplicate/out-of-window packets):         0
SHA-256 match:                                           Yes
==================================================
```
## Contributors
Arunit Baidya, Yun Ma, Kole Agava, Jiayue Zhang