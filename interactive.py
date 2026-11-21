"""
interactive.py
==============
Interactive command-line interface for the Searchable Encryption system.

Run:  python interactive.py

You can type keywords, add documents, see what the server sees vs what
the client sees, and verify that encryption is actually working.
"""

import os
import textwrap
from cloud_server import CloudServer
from client import Client


# ── Sample documents preloaded ──────────────────────────────────────
SAMPLE_DOCUMENTS = {
    "doc1": "Machine learning algorithms are increasingly used in cybersecurity to detect malware and intrusion attempts in network traffic.",
    "doc2": "Cloud computing provides scalable infrastructure for deploying machine learning models and big data analytics platforms.",
    "doc3": "Encryption techniques such as AES and RSA are fundamental to securing data in transit and at rest in cloud environments.",
    "doc4": "Blockchain technology enables decentralized and tamper-proof record keeping, with applications in finance and supply chain.",
    "doc5": "Natural language processing and deep learning have revolutionized search engines and recommendation systems.",
    "doc6": "Quantum computing poses a potential threat to current encryption standards, motivating research into post-quantum cryptography.",
    "doc7": "Data privacy regulations like GDPR require organizations to implement encryption and access controls to protect user data.",
    "doc8": "Federated learning allows machine learning models to be trained across multiple devices without sharing raw data.",
}


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def pause():
    input("\n  Press Enter to continue...")


def banner():
    print()
    print("  ╔════════════════════════════════════════════════════════════════╗")
    print("  ║      SEARCHABLE ENCRYPTION FOR SECURE CLOUD SHARING          ║")
    print("  ║                   Interactive Demo                           ║")
    print("  ╚════════════════════════════════════════════════════════════════╝")
    print()


def show_menu():
    print("  ┌────────────────────────── MENU ──────────────────────────────┐")
    print("  │                                                             │")
    print("  │   1.  Search for a keyword                                  │")
    print("  │   2.  View all documents (plaintext — client side)          │")
    print("  │   3.  View what the SERVER sees (encrypted data)            │")
    print("  │   4.  Add a new document                                    │")
    print("  │   5.  Compare: client view vs server view of a document     │")
    print("  │   6.  View server search log (proves keywords are hidden)   │")
    print("  │   7.  Show all keywords in the index                        │")
    print("  │   0.  Exit                                                  │")
    print("  │                                                             │")
    print("  └─────────────────────────────────────────────────────────────┘")
    print()


def option_search(client: Client, server: CloudServer):
    """Let the user search for a keyword and see the full pipeline."""
    print("\n  ── KEYWORD SEARCH ──────────────────────────────────────────\n")
    keyword = input("  Enter keyword to search: ").strip()
    if not keyword:
        print("  (empty keyword, skipping)")
        return

    # Step 1: Show the trapdoor
    trapdoor = client.get_trapdoor(keyword)
    print(f"\n  Step 1 — Trapdoor generated (what the SERVER receives):")
    print(f"           {trapdoor}")
    print(f"           ↑ The server sees THIS, not '{keyword}'")

    # Step 2: Server lookup
    encrypted_result = server.search(trapdoor)
    if encrypted_result is None:
        print(f"\n  Step 2 — Server found: NO MATCH for this trapdoor.")
        print(f"           Keyword '{keyword}' does not exist in any document.")
        return

    print(f"\n  Step 2 — Server found encrypted result:")
    print(f"           {encrypted_result[:60]}...")
    print(f"           ({len(encrypted_result)} bytes of encrypted data)")

    # Step 3: Client decrypts
    results = client.search(keyword)
    print(f"\n  Step 3 — Client decrypted the result → matching documents:")
    for doc_id in results:
        content = client.retrieve_and_decrypt(doc_id)
        print(f"\n    📄 {doc_id}:")
        print(f"       {content}")

    print(f"\n  ✅ Found {len(results)} document(s) containing '{keyword}'")


def option_view_documents(client: Client):
    """Show all plaintext documents (client-side view)."""
    print("\n  ── ALL DOCUMENTS (Client-Side — Plaintext) ─────────────────\n")
    for doc_id, content in SAMPLE_DOCUMENTS.items():
        print(f"    📄 {doc_id}: {content[:80]}...")
    print(f"\n  Total: {len(SAMPLE_DOCUMENTS)} documents")


def option_server_view(server: CloudServer):
    """Show what the server actually stores — encrypted blobs."""
    print("\n  ── SERVER VIEW (What the cloud server stores) ──────────────\n")

    print("  Encrypted Documents:")
    for doc_id in list(server.encrypted_docs.keys())[:5]:
        enc = server.encrypted_docs[doc_id]
        print(f"    🔒 {doc_id}: {enc[:50]}... ({len(enc)} bytes)")

    print(f"\n  Encrypted Index Entries (first 5 of {server.index_entry_count}):")
    for addr in list(server.encrypted_index.keys())[:5]:
        val = server.encrypted_index[addr]
        print(f"    🔑 {addr[:40]}... → {val[:30]}... ({len(val)} bytes)")

    print(f"\n  ⚠️  The server CANNOT read any of this without the secret keys!")


def option_add_document(client: Client, server: CloudServer):
    """Let the user add a new document and rebuild the index."""
    print("\n  ── ADD A NEW DOCUMENT ──────────────────────────────────────\n")
    doc_id = input("  Enter document ID (e.g. doc9): ").strip()
    if not doc_id:
        print("  (empty ID, skipping)")
        return
    content = input("  Enter document content: ").strip()
    if not content:
        print("  (empty content, skipping)")
        return

    SAMPLE_DOCUMENTS[doc_id] = content
    client.add_document(doc_id, content)
    client.upload_all()

    print(f"\n  ✅ Document '{doc_id}' added, encrypted, and uploaded!")
    print(f"     Index rebuilt with {server.index_entry_count} entries.")
    print(f"     You can now search for keywords from this document.")


def option_compare(client: Client, server: CloudServer):
    """Side-by-side comparison of client vs server view of a document."""
    print("\n  ── CLIENT vs SERVER VIEW ───────────────────────────────────\n")
    doc_ids = list(SAMPLE_DOCUMENTS.keys())
    print(f"  Available documents: {', '.join(doc_ids)}")
    doc_id = input("  Enter document ID to compare: ").strip()
    if doc_id not in SAMPLE_DOCUMENTS:
        print(f"  Document '{doc_id}' not found.")
        return

    # Client view (decrypted)
    decrypted = client.retrieve_and_decrypt(doc_id)
    print(f"\n  👤 CLIENT sees (decrypted):")
    print(f"     {decrypted}")

    # Server view (encrypted)
    encrypted = server.retrieve_document(doc_id)
    print(f"\n  🖥️  SERVER sees (encrypted):")
    print(f"     {encrypted[:80]}...")
    print(f"     ({len(encrypted)} bytes of unreadable encrypted data)")

    print(f"\n  ✅ Proof: the server stores ONLY encrypted data!")


def option_search_log(server: CloudServer):
    """Show the server's search log — only trapdoor hashes, no keywords."""
    print("\n  ── SERVER SEARCH LOG ──────────────────────────────────────\n")
    log = server.get_search_log()
    if not log:
        print("  (no searches performed yet)")
        return

    print(f"  The server has logged {len(log)} search(es).")
    print(f"  It stores ONLY the trapdoor tokens — never the keywords:\n")
    for i, entry in enumerate(log, 1):
        print(f"    {i}. {entry}")
    print(f"\n  ⚠️  None of these reveal what keyword was searched!")


def option_show_keywords(client: Client):
    """Show all keywords that exist in the index."""
    print("\n  ── INDEXED KEYWORDS ───────────────────────────────────────\n")
    from sse_scheme import build_plaintext_index
    pt_index = build_plaintext_index(SAMPLE_DOCUMENTS)
    keywords = sorted(pt_index.keys())
    # Print in columns
    cols = 4
    for i in range(0, len(keywords), cols):
        row = keywords[i:i + cols]
        print("    " + "  ".join(f"{kw:<18}" for kw in row))
    print(f"\n  Total: {len(keywords)} unique keywords")
    print(f"  Try searching for any of these!")


def main():
    # Setup
    server = CloudServer()
    client = Client(server)
    for doc_id, content in SAMPLE_DOCUMENTS.items():
        client.add_document(doc_id, content)
    client.upload_all()

    clear()
    banner()
    print("  System initialized with 8 encrypted research documents.\n")

    while True:
        show_menu()
        choice = input("  Enter your choice (0-7): ").strip()

        if choice == "1":
            option_search(client, server)
        elif choice == "2":
            option_view_documents(client)
        elif choice == "3":
            option_server_view(server)
        elif choice == "4":
            option_add_document(client, server)
        elif choice == "5":
            option_compare(client, server)
        elif choice == "6":
            option_search_log(server)
        elif choice == "7":
            option_show_keywords(client)
        elif choice == "0":
            print("\n  Goodbye! 👋\n")
            break
        else:
            print("\n  Invalid choice. Please enter 0-7.")

        pause()
        clear()
        banner()


if __name__ == "__main__":
    main()
