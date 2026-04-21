"""
1. Verify client identity (ClientHello)
2. Verify server identity (ServerHello)
3. Generate shared encryption keys (HKDF)
"""

from __future__ import annotations  # allows modern type hints (not networking related)

import os
import hmac
import hashlib
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ===== CONSTANTS =====

NONCE_SIZE = 16        # random value size (used once per session)
SESSION_ID_SIZE = 8    # identifies a connection/session
KEY_SIZE = 32          # size of encryption keys (256 bits)
HMAC_SIZE = 32         # size of HMAC-SHA256 output


# ===== HMAC HELPERS =====

def _make_hmac(psk: bytes, data: bytes) -> bytes:
    # Create a secure "signature" using the shared secret (PSK)
    # Used to prove both sides know the same secret
    return hmac.new(psk, data, hashlib.sha256).digest()


def _verify_hmac(psk: bytes, data: bytes, received: bytes) -> bool:
    # Verify the received HMAC matches what we expect
    # If not → message was tampered or sender is not trusted
    return hmac.compare_digest(_make_hmac(psk, data), received)


# ===== CLIENT HELLO =====

def build_client_hello(psk: bytes) -> tuple[bytes, bytes]:
    """
    Build first handshake message from client

    Format:
    [client_nonce][HMAC(psk, client_nonce)]
    """

    # Generate random value → prevents replay attacks
    client_nonce = os.urandom(NONCE_SIZE)

    # prove client knows PSK
    mac = _make_hmac(psk, client_nonce)

    # send both
    return client_nonce, client_nonce + mac


def handle_client_hello(psk: bytes, message: bytes) -> tuple[bool, bytes]:
    """
    Server receives and verifies ClientHello
    """

    # check message size
    if len(message) < NONCE_SIZE + HMAC_SIZE:
        return False, b""

    # extract values
    client_nonce = message[:NONCE_SIZE]
    received_mac = message[NONCE_SIZE:NONCE_SIZE + HMAC_SIZE]

    # verify authenticity
    if not _verify_hmac(psk, client_nonce, received_mac):
        return False, b""

    # valid client
    return True, client_nonce


# ===== SERVER HELLO =====

def build_server_hello(psk: bytes, client_nonce: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Build response from server

    Format:
    [server_nonce][session_id][HMAC(psk, server_nonce + session_id + client_nonce)]
    """

    # generate fresh random values
    server_nonce = os.urandom(NONCE_SIZE)
    session_id = os.urandom(SESSION_ID_SIZE)

    # prove server knows PSK and bind to client_nonce
    mac = _make_hmac(psk, server_nonce + session_id + client_nonce)

    return server_nonce, session_id, server_nonce + session_id + mac


def handle_server_hello(psk: bytes, client_nonce: bytes, message: bytes) -> tuple[bool, bytes, bytes]:
    """
    Client verifies ServerHello
    """

    expected = NONCE_SIZE + SESSION_ID_SIZE + HMAC_SIZE
    if len(message) < expected:
        return False, b"", b""

    # extract values
    server_nonce = message[:NONCE_SIZE]
    session_id = message[NONCE_SIZE:NONCE_SIZE + SESSION_ID_SIZE]
    received_mac = message[NONCE_SIZE + SESSION_ID_SIZE:]

    # verify server authenticity
    if not _verify_hmac(psk, server_nonce + session_id + client_nonce, received_mac):
        return False, b"", b""

    return True, server_nonce, session_id


# ===== KEY DERIVATION =====

def derive_keys(psk: bytes, client_nonce: bytes, server_nonce: bytes) -> tuple[bytes, bytes]:
    """
    Generate session keys after handshake

    - PSK alone is not enough
    - we mix in random nonces to create unique session keys
    """

    hkdf = HKDF(
        algorithm=SHA256(),
        length=KEY_SIZE * 2,             # generate 2 keys
        salt=client_nonce + server_nonce, # randomness from both sides
        info=b"SRFT-session-keys"        # context label
    )

    key_material = hkdf.derive(psk)

    # split into two keys
    return key_material[:KEY_SIZE], key_material[KEY_SIZE:]
