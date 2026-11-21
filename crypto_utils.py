"""
crypto_utils.py
===============
Core cryptographic primitives for the Searchable Encryption system.

Provides:
  - AES-256-GCM encryption / decryption (authenticated encryption)
  - HMAC-SHA256 based pseudorandom function (PRF) for trapdoor generation
  - Secure random key generation
"""

import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_key(length: int = 32) -> bytes:
    """Generate a cryptographically secure random key.

    Args:
        length: Key length in bytes (default 32 = 256 bits).

    Returns:
        Random bytes of the specified length.
    """
    return os.urandom(length)


# ---------------------------------------------------------------------------
# AES-256-GCM encryption / decryption
# ---------------------------------------------------------------------------

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt *plaintext* with AES-256-GCM.

    The 12-byte nonce is prepended to the ciphertext so that the same key
    can be used for many messages without the caller tracking nonces.

    Args:
        key: 32-byte AES key.
        plaintext: Data to encrypt.

    Returns:
        nonce (12 B) || ciphertext || tag (16 B)
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext  # 12 + len(plaintext) + 16


def aes_decrypt(key: bytes, ciphertext_blob: bytes) -> bytes:
    """Decrypt a blob produced by :func:`aes_encrypt`.

    Args:
        key: 32-byte AES key (same key used for encryption).
        ciphertext_blob: nonce || ciphertext || tag as returned by aes_encrypt.

    Returns:
        Original plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If the ciphertext was tampered with.
    """
    nonce = ciphertext_blob[:12]
    ciphertext = ciphertext_blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ---------------------------------------------------------------------------
# HMAC-SHA256 pseudorandom function (PRF) — used for trapdoor generation
# ---------------------------------------------------------------------------

def hmac_prf(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256(key, data).

    Used as a pseudorandom function (PRF) so that the cloud server
    receives a *trapdoor* value instead of the plaintext keyword.

    Args:
        key: Secret HMAC key.
        data: Input data (e.g. keyword encoded to bytes).

    Returns:
        32-byte HMAC digest.
    """
    return hmac.new(key, data, hashlib.sha256).digest()


def hmac_prf_hex(key: bytes, data: bytes) -> str:
    """Same as :func:`hmac_prf` but returns a hex string (for use as dict key)."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()
