"""
client.py
=========
Client-side operations for the Searchable Encryption system.

The client holds the secret keys and performs:
  - Document encryption & upload
  - Encrypted index building & upload
  - Trapdoor generation for search queries
  - Decryption of search results and retrieved documents
"""

from __future__ import annotations

from typing import Dict, List, Optional

from crypto_utils import generate_key
from sse_scheme import (
    SSEKeys,
    build_plaintext_index,
    build_encrypted_index,
    encrypt_document,
    decrypt_document,
    generate_trapdoor,
    client_decrypt_results,
)
from cloud_server import CloudServer


class Client:
    """Represents a trusted client that owns the secret keys.

    Args:
        server: The (untrusted) cloud server to interact with.
        keys:   Optional pre-existing key bundle; generated if ``None``.
    """

    def __init__(self, server: CloudServer, keys: SSEKeys | None = None) -> None:
        self.server = server
        self.keys = keys or SSEKeys()
        self._local_docs: Dict[str, str] = {}  # plaintext copies (client-side only)

    # ------------------------------------------------------------------
    # Upload workflow
    # ------------------------------------------------------------------

    def add_document(self, doc_id: str, content: str) -> None:
        """Register a plaintext document locally (before uploading)."""
        self._local_docs[doc_id] = content

    def upload_all(self) -> None:
        """Encrypt and upload all local documents + build & upload the index."""
        # 1. Encrypt each document
        for doc_id, content in self._local_docs.items():
            enc_doc = encrypt_document(self.keys, content)
            self.server.upload_document(doc_id, enc_doc)

        # 2. Build & upload encrypted index
        pt_index = build_plaintext_index(self._local_docs)
        enc_index = build_encrypted_index(self.keys, pt_index)
        self.server.upload_index(enc_index)

    # ------------------------------------------------------------------
    # Search workflow
    # ------------------------------------------------------------------

    def search(self, keyword: str) -> List[str]:
        """Search for *keyword* across all encrypted documents.

        1. Generate a trapdoor (client-side, using secret key).
        2. Send the trapdoor to the server (server never sees keyword).
        3. Receive encrypted posting list from the server.
        4. Decrypt the posting list (client-side).

        Args:
            keyword: Plaintext search keyword.

        Returns:
            List of matching document IDs (empty if no match).
        """
        trapdoor = generate_trapdoor(self.keys, keyword)
        encrypted_result = self.server.search(trapdoor)
        if encrypted_result is None:
            return []
        return client_decrypt_results(self.keys, encrypted_result)

    def retrieve_and_decrypt(self, doc_id: str) -> Optional[str]:
        """Retrieve and decrypt a document from the server.

        Args:
            doc_id: Identifier of the document to retrieve.

        Returns:
            Plaintext content, or ``None`` if not found.
        """
        enc_doc = self.server.retrieve_document(doc_id)
        if enc_doc is None:
            return None
        return decrypt_document(self.keys, enc_doc)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @property
    def local_document_count(self) -> int:
        return len(self._local_docs)

    def get_trapdoor(self, keyword: str) -> str:
        """Return the trapdoor for a keyword (for testing / inspection)."""
        return generate_trapdoor(self.keys, keyword)
