"""
test_confidentiality.py
=======================
Confidentiality validation tests for the Searchable Encryption system.

Ensures that the cloud server cannot:
  - Learn the plaintext keywords from the encrypted index
  - Read the contents of stored documents
  - Determine search terms from observed trapdoors
  - Distinguish between different keywords from their trapdoors
  - Decrypt posting lists without the secret key
"""

import json
import sys
from crypto_utils import generate_key, aes_decrypt
from sse_scheme import SSEKeys, generate_trapdoor
from cloud_server import CloudServer
from client import Client


SAMPLE_DOCS = {
    "doc_a": "Encryption algorithms protect sensitive data in cloud storage systems.",
    "doc_b": "Machine learning models require large datasets for effective training.",
    "doc_c": "Blockchain provides decentralized security for financial transactions.",
    "doc_d": "Cloud computing enables on-demand access to encryption services.",
    "doc_e": "Network security relies on firewalls and intrusion detection systems.",
}

passed = 0
failed = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    status = "PASS" if condition else "FAIL"
    if not condition:
        failed += 1
    else:
        passed += 1
    suffix = f"  ({detail})" if detail else ""
    print(f"  [{status}] {name}{suffix}")


def setup():
    """Create a server & client, upload documents, return both."""
    server = CloudServer()
    client = Client(server)
    for doc_id, content in SAMPLE_DOCS.items():
        client.add_document(doc_id, content)
    client.upload_all()
    return server, client


def test_index_keys_not_plaintext() -> None:
    """Index keys must be hex-encoded HMAC digests, not plaintext keywords."""
    print("\n--- Test 1: Index keys are not plaintext keywords ---")
    server, client = setup()
    keys = server.get_all_index_keys()

    # None of the index keys should be a readable English word
    readable_words = set()
    for k in keys:
        try:
            decoded = bytes.fromhex(k).decode("utf-8", errors="strict")
            if decoded.isalpha():
                readable_words.add(decoded)
        except (ValueError, UnicodeDecodeError):
            pass

    check("No index key decodes to a readable word", len(readable_words) == 0,
          f"readable_words={readable_words}" if readable_words else "all opaque hex")

    # All keys should be exactly 64 hex characters (SHA-256)
    all_valid = all(len(k) == 64 and all(c in "0123456789abcdef" for c in k) for k in keys)
    check("All index keys are 64-char hex (SHA-256 output)", all_valid)


def test_index_values_encrypted() -> None:
    """Index values (posting lists) must not be readable without the key."""
    print("\n--- Test 2: Index values are encrypted ---")
    server, _ = setup()

    for i, val in enumerate(server.get_all_index_values()):
        try:
            decoded = json.loads(val)
            check(f"Index value {i} not readable as JSON", False, f"decoded={decoded}")
            return
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    check("No index value is readable as plaintext JSON", True)


def test_documents_encrypted() -> None:
    """Stored documents must not be readable without the key."""
    print("\n--- Test 3: Stored documents are encrypted ---")
    server, _ = setup()

    for doc_id in SAMPLE_DOCS:
        enc = server.retrieve_document(doc_id)
        try:
            text = enc.decode("utf-8")
            # Even if it decodes, it shouldn't match the original
            if text == SAMPLE_DOCS[doc_id]:
                check(f"{doc_id} not stored as plaintext", False)
                return
        except UnicodeDecodeError:
            pass  # expected — it's encrypted

    check("No document is stored as readable plaintext", True)


def test_trapdoor_hides_keyword() -> None:
    """Trapdoors must not reveal the original keyword."""
    print("\n--- Test 4: Trapdoors hide the keyword ---")
    _, client = setup()

    keywords = ["encryption", "machine", "cloud", "blockchain", "network"]
    for kw in keywords:
        td = client.get_trapdoor(kw)
        # The trapdoor should not contain the keyword
        check(f"Trapdoor for '{kw}' does not contain keyword",
              kw not in td and kw.upper() not in td)
        # It should be a 64-char hex string
        check(f"Trapdoor for '{kw}' is a 64-char hex string",
              len(td) == 64 and all(c in "0123456789abcdef" for c in td))


def test_different_keywords_different_trapdoors() -> None:
    """Different keywords must produce different trapdoors."""
    print("\n--- Test 5: Different keywords → different trapdoors ---")
    _, client = setup()

    keywords = ["encryption", "machine", "cloud", "blockchain", "network",
                "security", "data", "learning", "computing", "privacy"]
    trapdoors = {kw: client.get_trapdoor(kw) for kw in keywords}

    # All trapdoors should be unique
    unique = len(set(trapdoors.values()))
    check(f"All {len(keywords)} trapdoors are unique", unique == len(keywords),
          f"{unique} unique out of {len(keywords)}")


def test_same_keyword_same_trapdoor() -> None:
    """The same keyword must always produce the same trapdoor (deterministic)."""
    print("\n--- Test 6: Same keyword → same trapdoor (deterministic) ---")
    _, client = setup()

    for kw in ["encryption", "cloud", "data"]:
        t1 = client.get_trapdoor(kw)
        t2 = client.get_trapdoor(kw)
        check(f"'{kw}' trapdoor is deterministic", t1 == t2)


def test_different_keys_different_trapdoors() -> None:
    """Different users (different keys) produce different trapdoors for the same keyword."""
    print("\n--- Test 7: Different keys → different trapdoors for same keyword ---")

    keys_a = SSEKeys()
    keys_b = SSEKeys()

    for kw in ["encryption", "cloud", "data"]:
        ta = generate_trapdoor(keys_a, kw)
        tb = generate_trapdoor(keys_b, kw)
        check(f"'{kw}' trapdoor differs across key sets", ta != tb)


def test_server_cannot_decrypt_with_wrong_key() -> None:
    """The server cannot decrypt posting lists or documents with a random key."""
    print("\n--- Test 8: Decryption with wrong key fails ---")
    server, _ = setup()

    wrong_key = generate_key(32)

    # Try to decrypt an index value
    sample_ct = server.get_all_index_values()[0]
    try:
        aes_decrypt(wrong_key, sample_ct)
        check("Index value decryption with wrong key fails", False, "decrypted successfully!")
    except Exception:
        check("Index value decryption with wrong key fails", True, "InvalidTag raised")

    # Try to decrypt a document
    enc_doc = server.retrieve_document("doc_a")
    try:
        aes_decrypt(wrong_key, enc_doc)
        check("Document decryption with wrong key fails", False, "decrypted successfully!")
    except Exception:
        check("Document decryption with wrong key fails", True, "InvalidTag raised")


def test_server_search_log_contains_no_keywords() -> None:
    """The server's search log must contain only trapdoors, never keywords."""
    print("\n--- Test 9: Server search log contains no plaintext keywords ---")
    server, client = setup()

    search_terms = ["encryption", "machine", "cloud"]
    for kw in search_terms:
        client.search(kw)

    log = server.get_search_log()
    check("Search log has correct number of entries", len(log) == len(search_terms),
          f"{len(log)} entries")

    for entry in log:
        # Should be a hex string, not a keyword
        is_hex = len(entry) == 64 and all(c in "0123456789abcdef" for c in entry)
        # Should not contain any of the search terms
        no_keyword = not any(kw in entry for kw in search_terms)
        check("Log entry is hex, not a keyword", is_hex and no_keyword,
              f"{entry[:32]}...")


def main() -> None:
    global passed, failed
    print("=" * 70)
    print("  SEARCHABLE ENCRYPTION — CONFIDENTIALITY VALIDATION")
    print("=" * 70)

    test_index_keys_not_plaintext()
    test_index_values_encrypted()
    test_documents_encrypted()
    test_trapdoor_hides_keyword()
    test_different_keywords_different_trapdoors()
    test_same_keyword_same_trapdoor()
    test_different_keys_different_trapdoors()
    test_server_cannot_decrypt_with_wrong_key()
    test_server_search_log_contains_no_keywords()

    print(f"\n{'=' * 70}")
    print(f"  RESULTS: {passed} passed, {failed} failed, {passed + failed} total")
    print(f"{'=' * 70}")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
