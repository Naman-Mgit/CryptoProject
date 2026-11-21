"""
cloud_server.py
===============
Simulated cloud server for storing encrypted documents and the encrypted index.

The server **never** has access to:
  - The plaintext documents
  - The plaintext keywords
  - The secret keys

It can only:
  - Store encrypted blobs
  - Look up an entry in the encrypted index given a trapdoor token
  - Return encrypted results to the client
"""

from __future__ import annotations

from typing import Dict, List, Optional


class CloudServer:
    """A simulated cloud storage server.

    Attributes:
        encrypted_docs:  doc_id → encrypted document bytes.
        encrypted_index: trapdoor_hex → encrypted posting-list bytes.
        search_log:      record of all trapdoor tokens received (for auditing).
    """

    def __init__(self) -> None:
        self.encrypted_docs: Dict[str, bytes] = {}
        self.encrypted_index: Dict[str, bytes] = {}
        self.search_log: List[str] = []

    # ------------------------------------------------------------------
    # Upload
    # ------------------------------------------------------------------

    def upload_document(self, doc_id: str, encrypted_content: bytes) -> None:
        """Store an encrypted document on the server."""
        self.encrypted_docs[doc_id] = encrypted_content

    def upload_index(self, encrypted_index: Dict[str, bytes]) -> None:
        """Replace the encrypted index on the server."""
        self.encrypted_index = dict(encrypted_index)

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(self, trapdoor: str) -> Optional[bytes]:
        """Look up a trapdoor in the encrypted index.

        The server logs the trapdoor token it receives (for later
        confidentiality analysis) but cannot determine the original keyword.

        Args:
            trapdoor: Hex-encoded trapdoor token from the client.

        Returns:
            Encrypted posting-list blob, or ``None`` if no match.
        """
        self.search_log.append(trapdoor)
        return self.encrypted_index.get(trapdoor)

    def retrieve_document(self, doc_id: str) -> Optional[bytes]:
        """Return the encrypted document for *doc_id*, or ``None``."""
        return self.encrypted_docs.get(doc_id)

    # ------------------------------------------------------------------
    # Inspection helpers (for confidentiality tests)
    # ------------------------------------------------------------------

    def get_all_index_keys(self) -> List[str]:
        """Return all trapdoor addresses stored in the index."""
        return list(self.encrypted_index.keys())

    def get_all_index_values(self) -> List[bytes]:
        """Return all encrypted posting lists stored in the index."""
        return list(self.encrypted_index.values())

    def get_search_log(self) -> List[str]:
        """Return the full search log (trapdoor tokens only)."""
        return list(self.search_log)

    @property
    def document_count(self) -> int:
        return len(self.encrypted_docs)

    @property
    def index_entry_count(self) -> int:
        return len(self.encrypted_index)
