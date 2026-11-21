"""
test_performance.py
===================
Performance and scalability benchmarks for the Searchable Encryption system.

Tests:
  - Index build time vs. document count
  - Single search latency vs. index size
  - Throughput: searches per second
  - Document encryption / decryption throughput
"""

import time
import statistics
from cloud_server import CloudServer
from client import Client


def generate_documents(n: int, keywords_per_doc: int = 20) -> dict:
    """Generate *n* synthetic documents with *keywords_per_doc* unique keywords each."""
    docs = {}
    base_keywords = [
        "encryption", "security", "cloud", "computing", "data",
        "privacy", "machine", "learning", "network", "algorithm",
        "blockchain", "quantum", "federated", "cryptography", "protocol",
        "authentication", "firewall", "malware", "intrusion", "analytics",
    ]
    for i in range(n):
        words = " ".join(
            [base_keywords[j % len(base_keywords)] for j in range(keywords_per_doc)]
            + [f"unique_term_{i}"]
        )
        docs[f"doc_{i}"] = words
    return docs


def benchmark_index_build() -> None:
    print("=" * 70)
    print("  BENCHMARK 1 — Index Build Time vs. Document Count")
    print("=" * 70)
    for n in [50, 100, 250, 500, 1000, 2000, 5000]:
        docs = generate_documents(n)
        server = CloudServer()
        client = Client(server)
        for doc_id, content in docs.items():
            client.add_document(doc_id, content)

        t0 = time.perf_counter()
        client.upload_all()
        elapsed = time.perf_counter() - t0
        print(f"  {n:5d} docs  →  {elapsed * 1000:9.2f} ms  ({elapsed / n * 1_000_000:.1f} µs/doc)")
    print()


def benchmark_search_latency() -> None:
    print("=" * 70)
    print("  BENCHMARK 2 — Search Latency vs. Index Size")
    print("=" * 70)
    for n in [100, 500, 1000, 2000, 5000]:
        docs = generate_documents(n)
        server = CloudServer()
        client = Client(server)
        for doc_id, content in docs.items():
            client.add_document(doc_id, content)
        client.upload_all()

        # Measure multiple searches and report statistics
        times = []
        for _ in range(100):
            t0 = time.perf_counter()
            client.search("encryption")
            times.append(time.perf_counter() - t0)

        avg = statistics.mean(times) * 1_000_000
        med = statistics.median(times) * 1_000_000
        mn = min(times) * 1_000_000
        mx = max(times) * 1_000_000
        print(
            f"  {n:5d} docs  →  avg {avg:8.1f} µs  |  "
            f"median {med:8.1f} µs  |  min {mn:7.1f} µs  |  max {mx:8.1f} µs"
        )
    print()


def benchmark_search_throughput() -> None:
    print("=" * 70)
    print("  BENCHMARK 3 — Search Throughput (searches/sec)")
    print("=" * 70)
    docs = generate_documents(1000)
    server = CloudServer()
    client = Client(server)
    for doc_id, content in docs.items():
        client.add_document(doc_id, content)
    client.upload_all()

    keywords = ["encryption", "security", "cloud", "data", "privacy",
                "machine", "learning", "network", "algorithm", "blockchain"]

    duration = 2.0  # seconds
    count = 0
    end_time = time.perf_counter() + duration
    while time.perf_counter() < end_time:
        for kw in keywords:
            client.search(kw)
            count += 1
            if time.perf_counter() >= end_time:
                break

    throughput = count / duration
    print(f"  Completed {count} searches in {duration:.1f}s  →  {throughput:,.0f} searches/sec\n")


def benchmark_encryption_throughput() -> None:
    print("=" * 70)
    print("  BENCHMARK 4 — Document Encryption / Decryption Throughput")
    print("=" * 70)
    from sse_scheme import SSEKeys, encrypt_document, decrypt_document

    keys = SSEKeys()
    sizes = [1_000, 10_000, 100_000, 1_000_000]  # bytes

    for size in sizes:
        plaintext = "A" * size

        # Encryption
        t0 = time.perf_counter()
        for _ in range(100):
            ct = encrypt_document(keys, plaintext)
        enc_time = (time.perf_counter() - t0) / 100

        # Decryption
        t0 = time.perf_counter()
        for _ in range(100):
            decrypt_document(keys, ct)
        dec_time = (time.perf_counter() - t0) / 100

        enc_tp = size / enc_time / 1_000_000  # MB/s
        dec_tp = size / dec_time / 1_000_000  # MB/s
        label = f"{size:>10,d} B"
        print(
            f"  {label}  →  Encrypt: {enc_time * 1000:7.3f} ms ({enc_tp:7.1f} MB/s)  "
            f"|  Decrypt: {dec_time * 1000:7.3f} ms ({dec_tp:7.1f} MB/s)"
        )
    print()


def main() -> None:
    print("\n" + "=" * 70)
    print("  SEARCHABLE ENCRYPTION — PERFORMANCE BENCHMARKS")
    print("=" * 70 + "\n")

    benchmark_index_build()
    benchmark_search_latency()
    benchmark_search_throughput()
    benchmark_encryption_throughput()

    print("=" * 70)
    print("  ALL BENCHMARKS COMPLETED")
    print("=" * 70)


if __name__ == "__main__":
    main()
