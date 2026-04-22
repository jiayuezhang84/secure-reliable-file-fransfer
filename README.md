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
10. [Meeting Notes](#meeting-notes)
11. [AI Disclosure](#ai-disclosure)
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

Edit a relevant `config json file` with the private IPs of your two EC2 instances:

`config_phase1.json` used for phase 1 and is performance tuned.

`config_phase2.json` same as phase 1 with security enabled.
SAMPLE CONFIG
```json
{
  "network": {
    "client_ip": "172.31.64.201",
    "server_ip": "172.31.77.14",
    "client_port": 50000,
    "server_port": 50000
  },
  "transfer": {
    "chunk_size": 1200,
    "send_window_packets": 64
  },
  "timers": {
    "rto_ms": 300,
    "ack_interval_ms": 50,
    "handshake_timeout_ms": 3000
  },
  "security": {
    "enabled": true,
    "psk": "<hex string>"
  },
  "debug": {
    "verbose_packet_logs": true
  }
}
```

**On the server EC2 instance** — run first:

```bash
sudo PYTHONPATH=. python3 main.py --mode server --config config_phase1.json
```

**On the client EC2 instance** — then run:

```bash
sudo PYTHONPATH=. python3 main.py --mode client --config config_phase1.json --file <file requested at server name>
```

The server writes `transfer_report.txt` at server instance after each transfer completes.

The client writes `client_report.txt` at client instance after each transfer completes.

### Running Security Attack Simulation (server side)

These modes inject a deliberate security event to test client-side defenses:

```bash
# Flip bits in ciphertext → AEAD authentication failure on client
sudo PYTHONPATH=. python3 main.py --mode server --config config_phase2.json --attack tamper

# Resend a previously captured packet → replay detection triggers
sudo PYTHONPATH=. python3 main.py --mode server --config config_phase2.json --attack replay

# Send a forged garbage packet → rejected by AEAD tag check
sudo PYTHONPATH=. python3 main.py --mode server --config config_phase2.json --attack inject
```

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

- **Sliding window(SERVER):** server sends up to 64 unACKed packets simultaneously (configurable via `send_window_packets`)
- **Retransmission:** a background retransmission thread checks every `rto_ms` (300 ms default) and resends any packet older than the RTO
- **Cumulative ACKs + Bitmap Driven Retransmissions:** client sends one ACK every `ack_interval_ms` (50 ms) carrying the next expected sequence number plus a bitmap(64 packets) of out-of-order packets already received/buffered ahead of base/cumulative acked. The server then selectively retransmits the packets that are not present in client bitmap ahead of cumulative ack(up to 8 per ACK via `BIT_MAP_RETRANSMIT_LIMIT`) or are unacked and timed out at server.
- **Out-of-order buffering(CLIENT):** client buffers early-arriving packets and writes them to disk in order once gaps are filled

### Security

- **Handshake auth:** HMAC-SHA256 over nonces using PSK — proves both sides know the key without transmitting it. If the PSK is wrong the HMAC won't match and the handshake fails immediately — no file data is ever sent.

- **Key derivation:** HKDF-SHA256 with `salt = client_nonce || server_nonce` and `info = "SRFT-session-keys"` produces a fresh 64-byte key material split into `enc_key` (32B) and `ack_key` (32B) per session. Neither key is ever transmitted — both sides derive the same keys independently.

- **Per-packet encryption:** AES-256-GCM with a fresh random 12-byte nonce per packet. AES-GCM provides both confidentiality and integrity in one operation — if any bit of the ciphertext is modified, decryption returns `None` and the packet is dropped without writing corrupted data to disk. A fresh nonce per packet is required because reusing a nonce with the same key breaks GCM security.

- **AAD:** `session_id || seq || ack || msg_type` (17 bytes) is bound to the GCM tag — any header modification fails authentication.

- **Replay protection:** client tracks all seen sequence numbers in `seen_secure_seqs`; duplicates are dropped and counted.

- **Integrity:** server sends SHA-256 of the full plaintext file in `TYPE_FIN_DIGEST`; client verifies after reassembly. This provides end-to-end file integrity — any corruption of the reassembled file is detected even if individual packets passed AES-GCM verification.

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
| Bitmap-based Selective ACK (SACK) | Yes |
| MD5 integrity check (client report) | Yes |
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

**Transport layer** (`src/core/ip.py`, `src/core/udp.py`): manual construction and parsing of raw IPv4 and UDP headers using `struct.pack`. Requires `IP_HDRINCL` and `sudo`.

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
    └── run_client.sh
```

---

## Transfer Performance

All tests run on AWS EC2 instances. Packet loss was simulated using `tc netem` on the network interface. Duration is wall-clock time reported in `transfer_report.txt`.

## 0% Packet Loss

| File Size | Time for Transfer (min:sec) |
|-----------|------------------------------|
| 10 MB     | 00:02                        |
| 100 MB    | 00:28                        |
| 500 MB    | 02:26                        |
| 800 MB    | 04:25                        |
| 1 GB      | 05:02                        |

## 2% Packet Loss

| File Size | Time for Transfer (min:sec) |
|-----------|------------------------------|
| 10 MB     | 00:03                        |
| 100 MB    | 00:34                        |
| 500 MB    | 02:48                        |
| 800 MB    | 05:01                        |
| 1 GB      | 05:45                        |

## 3% Packet Loss

| File Size | Time for Transfer (min:sec) |
|-----------|------------------------------|
| 10 MB     | 00:03                        |
| 100 MB    | 00:34                        |
| 500 MB    | 02:54                        |
| 800 MB    | 05:16                        |
| 1 GB      | 06:02                        |

## 4% Packet Loss

| File Size | Time for Transfer (min:sec) |
|-----------|------------------------------|
| 10 MB     | 00:03                        |
| 100 MB    | 00:38                        |
| 500 MB    | 03:02                        |
| 800 MB    | 05:20                        |
| 1 GB      | 06:16                        |


---

## Known Limitations and Errors

- **Single concurrent transfer:** the server supports only one active transfer at a time. Any additional concurrent file transfer is not supported, is rejected and results in error packet at client. 
- **No dynamic congestion control:** the window size is fixed (default is 64). There is no slow-start or AIMD which can lead to higher latency.
- **PSK is static and visible:** the PSK is stored in `config.json` in plaintext. There is no mechanism for key-rotation, and it is visible in codebase in config.

---

## Lessons Learned
- **AEAD matters in practice**: Before adding AAD, tampering with a packet's seq number and the receiver wouldn't be noticed. The outer SRFT checksum can be recalculated by the attacker. Only the GCM tag can prevent header manipulation.
- **Unique Nonce is critical**: If reusing a nonce with the same key, AES-GCM can be broken. Setting nonce as a fresh random 12 bytes per packet is a better design decision.
- **Buffered receival at client crucial**: When simulating packet loss with tc netem, the out-of-order buffer + retransmissions becomes necessary to keep packets we receive out of order, and try again for packets not received and acked.
- **Checksums cannot reveal intention**: The SRFT header checksum detects accidental corruption but not intentional tampering. An attacker can flip bits and recompute a valid checksum. Matching cryptographic hashes help with this.
- **Bit Map**: Using bit map to track packets beyond cumulative ack but still received early at client, and passing this bitmap to server helps server to selectively retransmit packets which are needed at client, drastically reducing retransmissions.   
---

## Possible Future Improvements
- **Congestion control**: Replace the fixed window size with a dynamic congestion window. Implementing TCP-style slow start and AIMD would improve performance under packet loss.
- **Certificate-based authentication**: The PSK is a shared secret stored in plaintext config. An improved version could use asymmetric cryptography (e.g., DH key exchange) so no secret needs to be pre-distributed.
- **Full congestion control with AIMD**: The bitmap SACK is implemented, but the window size remains fixed. Adding slow-start and AIMD on top of the existing SACK would further reduce unnecessary retransmissions under heavy loss.
- **Multi-client support**: The server currently handles one transfer at a time. A future version could use the session ID as a demultiplexer to support concurrent transfers from multiple clients.
- **Resumable transfers**: If a transfer is interrupted, the client must start over from scratch. Adding a resume mechanism (tracking which chunks were already received) would make large file transfers more robust.
- **Web application interface**: Currently the system is operated entirely through the command line. A future version could add a web frontend allowing users to upload files, monitor transfer progress in real time, and view transfer reports through a browser.

---

## Transfer Report Format

After each transfer the server writes `transfer_report.txt` and the client writes `client_report.txt`.

### Server Report (`transfer_report.txt`)

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

### Client Report (`client_report.txt`)

```
==================================================
CLIENT REPORT
==================================================
Security enabled (PSK + AEAD):            Yes
Handshake status:                         Success
Size of the transferred file:             10485760 bytes
Number of packets received from server:   8739
Number of duplicate packets:              0
Replay drops:                             0
Number of out-of-order packets:           3
Number of packets with checksum errors:   0
Time duration of the file transfer:       00:00:04
Received file MD5:                        d41d8cd98f00b204e9800998ecf8427e
AEAD authentication failures:             0
SHA-256 match:                            Yes
==================================================
```

---

## Meeting Notes
### Link: [Meeting notes and project management tools Google Doc](https://docs.google.com/document/d/1pn3BFcJAlB4Dd3i4K-3ii5pTBZ-inJ_5vCT1wfeDVrU/edit?tab=t.0)
---

## AI Disclosure
AI was helpful in
   - setting up the EC2 instances => had not done this before, so AI helped tell and learn the setup steps and verify correct setup
   - generate commands to do testing of server and client => helped to identify and learn the packet loss commands in EC2 ubuntu instance and generate repetitive commands for creating different output files for different runs
   - Initially we were facing 5x performance loss when doing packet loss of 4%. We brainstormed ideas of how to tackle this, and AI suggested BIT_MAP, so that we only retransmit the missing packets to client in our cumulative ACK setup. Then we learned and implemented the bitmap concept, which caused retransmission of packets to reduce drastically and performance under packet loss improved as well.

## Contributors
Arunit Baidya, Yun Ma, Kole Agava, Jiayue Zhang