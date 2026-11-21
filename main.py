"""
main.py
=======
End-to-end demonstration of the Searchable Encryption for Secure Cloud
Document Sharing system.

Demonstrates all five project tasks:
  1. Building an encrypted keyword index
  2. Trapdoor-based search (no plaintext keywords revealed)
  3. Query response time measurement
  4. Confidentiality validation
  5. Scalability with multiple documents
"""

import time
from cloud_server import CloudServer
from client import Client


# ======================================================================
# Sample research documents
# ======================================================================
SAMPLE_DOCUMENTS = {
    "doc1": (
        "Machine learning algorithms are increasingly used in cybersecurity "
        "to detect malware and intrusion attempts in network traffic."
    ),
    "doc2": (
        "Cloud computing provides scalable infrastructure for deploying "
        "machine learning models and big data analytics platforms."
    ),
    "doc3": (
        "Encryption techniques such as AES and RSA are fundamental to "
        "securing data in transit and at rest in cloud environments."
    ),
    "doc4": (
        "Blockchain technology enables decentralized and tamper-proof "
        "record keeping, with applications in finance and supply chain."
    ),
    "doc5": (
        "Natural language processing and deep learning have revolutionized "
        "search engines and recommendation systems."
    ),
    "doc6": (
        "Quantum computing poses a potential threat to current encryption "
        "standards, motivating research into post-quantum cryptography."
    ),
    "doc7": (
        "Data privacy regulations like GDPR require organizations to "
        "implement encryption and access controls to protect user data."
    ),
    "doc8": (
        "Federated learning allows machine learning models to be trained "
        "across multiple devices without sharing raw data."
    ),
}


def separator(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}\n")


def main() -> None:
    # ==================================================================
    # Setup
    # ==================================================================
    separator("SETUP — Creating Cloud Server and Client")
    server = CloudServer()
    client = Client(server)

    # Add documents locally
    for doc_id, content in SAMPLE_DOCUMENTS.items():
        client.add_document(doc_id, content)
    print(f"  → {client.local_document_count} documents loaded on the client.\n")

    # ==================================================================
    # TASK 1: Build encrypted keyword index
    # ==================================================================
    separator("TASK 1 — Building Encrypted Keyword Index")

    start = time.perf_counter()
    client.upload_all()
    index_time = time.perf_counter() - start

    print(f"  → {server.document_count} encrypted documents uploaded to the cloud.")
    print(f"  → {server.index_entry_count} entries in the encrypted index.")
    print(f"  → Index built in {index_time * 1000:.2f} ms.")
    print(f"\n  Sample index keys (trapdoor addresses — NOT keywords):")
    for key in list(server.get_all_index_keys())[:5]:
        print(f"    {key}")

    # ==================================================================
    # TASK 2: Trapdoor-based search
    # ==================================================================
    separator("TASK 2 — Trapdoor Mechanism: Searching Without Revealing Keywords")

    search_keywords = ["encryption", "machine", "cloud", "blockchain", "quantum"]

    for kw in search_keywords:
        trapdoor = client.get_trapdoor(kw)
        results = client.search(kw)
        print(f"  Keyword   : '{kw}'")
        print(f"  Trapdoor  : {trapdoor[:48]}...")
        print(f"  Matches   : {results}")
        print()

    # Demonstrate that the server log contains only trapdoors
    print("  Server search log (trapdoors only — no plaintext keywords):")
    for entry in server.get_search_log():
        print(f"    {entry[:48]}...")

    # ==================================================================
    # TASK 3: Measure query response times
    # ==================================================================
    separator("TASK 3 — Efficiency: Query Response Times")

    keywords_to_test = ["encryption", "data", "learning", "cloud", "network"]
    for kw in keywords_to_test:
        start = time.perf_counter()
        results = client.search(kw)
        elapsed = time.perf_counter() - start
        print(f"  '{kw:12s}'  → {len(results)} result(s)  |  {elapsed * 1_000_000:.1f} µs")

    # ==================================================================
    # TASK 4: Confidentiality validation
    # ==================================================================
    separator("TASK 4 — Confidentiality Validation")

    # 4a. Index keys are random-looking HMAC outputs
    print("  [CHECK 1] Index keys are HMAC outputs, not plaintext keywords.")
    all_keys = server.get_all_index_keys()
    all_look_random = all(len(k) == 64 and all(c in "0123456789abcdef" for c in k) for k in all_keys)
    print(f"    All {len(all_keys)} index keys are 256-bit hex strings: {all_look_random}")

    # 4b. Index values are encrypted (not decodable as JSON without key)
    print("\n  [CHECK 2] Index values are encrypted and cannot be read by the server.")
    sample_value = server.get_all_index_values()[0]
    try:
        import json
        json.loads(sample_value)
        print("    FAIL — server could read the posting list as plaintext!")
    except (json.JSONDecodeError, UnicodeDecodeError):
        print(f"    PASS — encrypted blob ({len(sample_value)} bytes), not readable as JSON.")

    # 4c. Same keyword always produces the same trapdoor (deterministic PRF)
    print("\n  [CHECK 3] Same keyword → same trapdoor (deterministic search).")
    t1 = client.get_trapdoor("encryption")
    t2 = client.get_trapdoor("encryption")
    print(f"    Trapdoor 1: {t1[:48]}...")
    print(f"    Trapdoor 2: {t2[:48]}...")
    print(f"    Match: {t1 == t2}")

    # 4d. Different keywords produce different trapdoors
    print("\n  [CHECK 4] Different keywords → different trapdoors.")
    ta = client.get_trapdoor("encryption")
    tb = client.get_trapdoor("blockchain")
    print(f"    'encryption' : {ta[:48]}...")
    print(f"    'blockchain' : {tb[:48]}...")
    print(f"    Different: {ta != tb}")

    # 4e. Encrypted documents are not readable
    print("\n  [CHECK 5] Stored documents are encrypted and unreadable by the server.")
    enc_doc = server.retrieve_document("doc1")
    try:
        readable = enc_doc.decode("utf-8")
        print(f"    FAIL — document is stored as plaintext: {readable[:60]}...")
    except UnicodeDecodeError:
        print(f"    PASS — encrypted blob ({len(enc_doc)} bytes), not readable as text.")

    # ==================================================================
    # TASK 5: Scalability test
    # ==================================================================
    separator("TASK 5 — Scalability with a Large Number of Documents")

    doc_counts = [100, 500, 1000, 2000]
    for n in doc_counts:
        # Create a fresh server & client
        s = CloudServer()
        c = Client(s)
        for i in range(n):
            c.add_document(
                f"doc_{i}",
                f"Research document number {i} about encryption security "
                f"cloud computing data privacy machine learning algorithms "
                f"network intrusion detection system keyword_{i}",
            )

        # Measure index build time
        t0 = time.perf_counter()
        c.upload_all()
        build_time = time.perf_counter() - t0

        # Measure search time
        t0 = time.perf_counter()
        results = c.search("encryption")
        search_time = time.perf_counter() - t0

        print(
            f"  {n:5d} docs  |  Index build: {build_time * 1000:8.2f} ms  "
            f"|  Search: {search_time * 1_000_000:8.1f} µs  "
            f"|  Results: {len(results)}"
        )

    separator("ALL TASKS COMPLETED SUCCESSFULLY")


if __name__ == "__main__":
    main()
