"""
sse_scheme.py
=============
Searchable Symmetric Encryption (SSE) scheme.

Implements a single-keyword SSE scheme inspired by Curtmola et al. (2006):

1. **BuildIndex** — creates an encrypted inverted index mapping
   HMAC(K_s, keyword) → AES-GCM(K_e, list-of-document-IDs).
2. **Trapdoor**  — given a keyword, the client computes HMAC(K_s, keyword)
   and sends the result (the *trapdoor*) to the server.
3. **Search**    — the server looks up the trapdoor in the encrypted index,
   returns the encrypted posting list; the client decrypts it.

The server never sees the plaintext keyword or the plaintext document IDs
during the search phase.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Set, Tuple

from crypto_utils import (
    generate_key,
    aes_encrypt,
    aes_decrypt,
    hmac_prf_hex,
)


# ---------------------------------------------------------------------------
# Text processing helpers
# ---------------------------------------------------------------------------

_STOP_WORDS: Set[str] = {
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "shall",
    "should", "may", "might", "must", "can", "could", "of", "in", "to",
    "for", "with", "on", "at", "by", "from", "as", "into", "about",
    "and", "but", "or", "not", "no", "it", "its", "this", "that",
    "these", "those", "i", "we", "you", "he", "she", "they", "me",
    "him", "her", "us", "them", "my", "our", "your", "his", "their",
}


def extract_keywords(text: str) -> List[str]:
    """Extract meaningful lowercase keywords from *text*.

    Removes punctuation, filters stop words, and returns unique tokens.
    """
    tokens = re.findall(r"[a-zA-Z0-9]+", text.lower())
    seen: Set[str] = set()
    keywords: List[str] = []
    for t in tokens:
        if t not in _STOP_WORDS and t not in seen:
            seen.add(t)
            keywords.append(t)
    return keywords


# ---------------------------------------------------------------------------
# SSE key bundle
# ---------------------------------------------------------------------------

class SSEKeys:
    """Holds the two secret keys used by the SSE scheme.

    Attributes:
        k_search: HMAC key for trapdoor / address computation.
        k_enc:    AES key for encrypting posting lists & documents.
    """

    def __init__(self, k_search: bytes | None = None, k_enc: bytes | None = None):
        self.k_search = k_search or generate_key(32)
        self.k_enc = k_enc or generate_key(32)


# ---------------------------------------------------------------------------
# Index building (client side)
# ---------------------------------------------------------------------------

def build_plaintext_index(documents: Dict[str, str]) -> Dict[str, List[str]]:
    """Build a plaintext inverted index: keyword → [doc_id, …].

    Args:
        documents: Mapping of doc_id → plaintext content.

    Returns:
        Inverted index as a dict.
    """
    index: Dict[str, List[str]] = {}
    for doc_id, content in documents.items():
        for kw in extract_keywords(content):
            index.setdefault(kw, []).append(doc_id)
    return index


def build_encrypted_index(
    keys: SSEKeys,
    plaintext_index: Dict[str, List[str]],
) -> Dict[str, bytes]:
    """Encrypt the inverted index.

    For every keyword *w*:
      address = HMAC(K_search, w)          — the lookup key
      value   = AES-GCM(K_enc, [doc_ids]) — the encrypted posting list

    Args:
        keys: SSE key bundle.
        plaintext_index: keyword → [doc_id, …].

    Returns:
        Encrypted index: hex(address) → ciphertext_blob.
    """
    encrypted_index: Dict[str, bytes] = {}
    for keyword, doc_ids in plaintext_index.items():
        addr = hmac_prf_hex(keys.k_search, keyword.encode())
        plaintext = json.dumps(doc_ids).encode()
        ciphertext = aes_encrypt(keys.k_enc, plaintext)
        encrypted_index[addr] = ciphertext
    return encrypted_index


# ---------------------------------------------------------------------------
# Trapdoor generation (client side)
# ---------------------------------------------------------------------------

def generate_trapdoor(keys: SSEKeys, keyword: str) -> str:
    """Generate a trapdoor token for *keyword*.

    The trapdoor is HMAC(K_search, keyword).  It reveals nothing about
    the keyword to the server because HMAC is a PRF under a secret key.

    Args:
        keys: SSE key bundle.
        keyword: The search keyword (plaintext).

    Returns:
        Hex-encoded trapdoor string.
    """
    return hmac_prf_hex(keys.k_search, keyword.lower().encode())


# ---------------------------------------------------------------------------
# Search (server side returns ciphertext; client decrypts)
# ---------------------------------------------------------------------------

def server_search(encrypted_index: Dict[str, bytes], trapdoor: str) -> bytes | None:
    """Server-side search: look up the trapdoor in the encrypted index.

    The server only sees the trapdoor (a random-looking hash) and returns
    the corresponding ciphertext.  It learns nothing about the keyword or
    the matching document IDs.

    Returns:
        Encrypted posting list, or ``None`` if no match.
    """
    return encrypted_index.get(trapdoor)


def client_decrypt_results(keys: SSEKeys, ciphertext: bytes) -> List[str]:
    """Client-side decryption of the posting list returned by the server.

    Args:
        keys: SSE key bundle.
        ciphertext: Encrypted posting list blob.

    Returns:
        List of matching document IDs.
    """
    plaintext = aes_decrypt(keys.k_enc, ciphertext)
    return json.loads(plaintext.decode())


# ---------------------------------------------------------------------------
# Document encryption / decryption
# ---------------------------------------------------------------------------

def encrypt_document(keys: SSEKeys, plaintext: str) -> bytes:
    """Encrypt a document for cloud storage."""
    return aes_encrypt(keys.k_enc, plaintext.encode())


def decrypt_document(keys: SSEKeys, ciphertext: bytes) -> str:
    """Decrypt a document retrieved from the cloud."""
    return aes_decrypt(keys.k_enc, ciphertext).decode()
