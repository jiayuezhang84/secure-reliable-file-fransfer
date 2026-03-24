"""
Handle handshakes, session key derivation
"""
import os
import hmac
import json
import struct
import hashlib
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_SIZE = 16
SESSION_ID_SIZE = 8
KEY_SIZE = 32
HMAC_SIZE = 32

# psk loading


def load_psk(config_path: str = "config.json") -> bytes:
    """_summary_

    Args:
                    config_path (str, optional): _description_. Defaults to "config.json".

    Returns:
                    bytes: _description_
    """
    with open(config_path, 'r') as f:
        cfg = json.loads(f)
    psk = cfg["PSK"]
    if isinstance(psk, str):
        return psk.encode()
    return bytes(psk)

# hmac helper functions


def _make_hmac(psk: bytes, data: bytes) -> bytes:
    """compute hmac"""
    return hmac.new(psk, data, hashlib.sha256).digest()


def _verify_hmac(psk: bytes, data: bytes, received: bytes) -> bool:
    return hmac.compare_digest(_make_hmac(psk, data), received)


def build_client_hello(psk: bytes) -> tuple[bytes, bytes]:
    client_nonce = os.urandom(NONCE_SIZE)
    mac = _make_hmac(psk, client_nonce)
    return client_nonce, client_nonce + mac

# verify hmac


def handle_client_hello(psk: bytes, message: bytes) -> tuple[bool, bytes]:
    if len(message) < NONCE_SIZE + HMAC_SIZE:
        return False, b""
    client_nonce = message[:NONCE_SIZE]
    received_mac = message[NONCE_SIZE:NONCE_SIZE+HMAC_SIZE]
    if not _verify_hmac(psk, client_nonce, received_mac):
        return False, b""
    return True, client_nonce


def build_server_hello(psk: bytes, client_nonce: bytes) -> tuple[bytes, bytes, bytes]:
    server_nonce = os.urandom(NONCE_SIZE)
    session_id = os.urandom(SESSION_ID_SIZE)
    mac = _make_hmac(psk, server_nonce + session_id + client_nonce)
    return server_nonce, session_id, server_nonce + session_id + mac


def handle_server_hello(psk: bytes, client_nonce: bytes, message: bytes) -> tuple[bool, bytes, bytes]:
    expected = NONCE_SIZE + SESSION_ID_SIZE + HMAC_SIZE
    if len(message) < expected:
        return False, b"", b""
    server_nonce = message[:NONCE_SIZE]
    session_id = message[NONCE_SIZE:NONCE_SIZE+SESSION_ID_SIZE]
    received_mac = message[NONCE_SIZE + SESSION_ID_SIZE:]
    if not _verify_hmac(psk, server_nonce + session_id + client_nonce, received_mac):
      return False, b"", b""
    return True, server_nonce, session_id

def derive_keys(psk: bytes, client_nonce: bytes, server_nonce: bytes) -> tuple[bytes, bytes]:
    hkdf = HKDF(algorithm=SHA256(), 
                length=KEY_SIZE * 2,
                salt=client_nonce + server_nonce,
                info=b"SRFT-session-keys")
    key_material = hkdf.derive(psk)
    return key_material[:KEY_SIZE], key_material[KEY_SIZE:]