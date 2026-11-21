"""
web_app.py
==========
Web-based GUI for the Searchable Encryption system.

Run:  python web_app.py

Then open your browser at:  http://localhost:5000

No extra libraries needed — uses Python's built-in http.server.
"""

import json
import html
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from cloud_server import CloudServer
from client import Client
from sse_scheme import build_plaintext_index

# ── Setup ───────────────────────────────────────────────────────────
DOCUMENTS = {
    "doc1": "Machine learning algorithms are increasingly used in cybersecurity to detect malware and intrusion attempts in network traffic.",
    "doc2": "Cloud computing provides scalable infrastructure for deploying machine learning models and big data analytics platforms.",
    "doc3": "Encryption techniques such as AES and RSA are fundamental to securing data in transit and at rest in cloud environments.",
    "doc4": "Blockchain technology enables decentralized and tamper-proof record keeping, with applications in finance and supply chain.",
    "doc5": "Natural language processing and deep learning have revolutionized search engines and recommendation systems.",
    "doc6": "Quantum computing poses a potential threat to current encryption standards, motivating research into post-quantum cryptography.",
    "doc7": "Data privacy regulations like GDPR require organizations to implement encryption and access controls to protect user data.",
    "doc8": "Federated learning allows machine learning models to be trained across multiple devices without sharing raw data.",
}

server = CloudServer()
client = Client(server)
for doc_id, content in DOCUMENTS.items():
    client.add_document(doc_id, content)
client.upload_all()


# ── HTML Template ───────────────────────────────────────────────────
HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Searchable Encryption - Secure Cloud Search</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f1724; color: #e0e0e0; min-height: 100vh; }

  .header { background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 30px; text-align: center; border-bottom: 2px solid #0f3460; }
  .header h1 { font-size: 28px; color: #00d4ff; margin-bottom: 8px; }
  .header p { color: #8892b0; font-size: 14px; }

  .container { max-width: 1100px; margin: 0 auto; padding: 30px 20px; }

  /* Search Box */
  .search-box { background: #1a2332; border-radius: 12px; padding: 30px; margin-bottom: 25px; border: 1px solid #233554; }
  .search-box h2 { color: #00d4ff; margin-bottom: 15px; font-size: 18px; }
  .search-row { display: flex; gap: 10px; }
  .search-row input {
    flex: 1; padding: 14px 18px; border-radius: 8px; border: 1px solid #334155;
    background: #0f1724; color: #e0e0e0; font-size: 16px; outline: none;
  }
  .search-row input:focus { border-color: #00d4ff; box-shadow: 0 0 0 2px rgba(0,212,255,0.15); }
  .search-row button {
    padding: 14px 30px; border-radius: 8px; border: none; cursor: pointer;
    background: linear-gradient(135deg, #00d4ff, #0088cc); color: #000; font-weight: 700; font-size: 15px;
  }
  .search-row button:hover { background: linear-gradient(135deg, #00e5ff, #009de0); }
  .keyword-hints { margin-top: 12px; color: #64748b; font-size: 13px; }
  .keyword-hints span { background: #233554; padding: 3px 10px; border-radius: 4px; margin: 2px 4px; display: inline-block; cursor: pointer; color: #8892b0; }
  .keyword-hints span:hover { background: #0f3460; color: #00d4ff; }

  /* Results */
  .results { background: #1a2332; border-radius: 12px; padding: 25px; margin-bottom: 25px; border: 1px solid #233554; display: none; }
  .results.show { display: block; }
  .results h2 { color: #00d4ff; margin-bottom: 15px; font-size: 18px; }

  .pipeline { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px; margin-bottom: 20px; }
  .step { background: #0f1724; border-radius: 8px; padding: 15px; border: 1px solid #233554; }
  .step .label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #64748b; margin-bottom: 6px; }
  .step .value { font-family: 'Consolas', monospace; font-size: 12px; color: #ffd700; word-break: break-all; }
  .step .value.green { color: #00ff88; }

  .doc-result { background: #0f1724; border-radius: 8px; padding: 15px; margin-bottom: 10px; border-left: 3px solid #00d4ff; }
  .doc-result .doc-id { color: #00d4ff; font-weight: 700; margin-bottom: 5px; }
  .doc-result .doc-content { color: #b0b8c8; font-size: 14px; }
  .doc-result .highlight { background: #ffd70033; color: #ffd700; padding: 1px 4px; border-radius: 3px; }

  .no-results { text-align: center; padding: 30px; color: #64748b; }

  /* Two column layout */
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 25px; }
  .panel { background: #1a2332; border-radius: 12px; padding: 20px; border: 1px solid #233554; }
  .panel h2 { color: #00d4ff; margin-bottom: 15px; font-size: 16px; }
  .panel .item { background: #0f1724; border-radius: 6px; padding: 10px 12px; margin-bottom: 8px; font-size: 13px; }
  .panel .item .id { color: #00d4ff; font-weight: 600; }
  .panel .item .enc { font-family: monospace; color: #ff6b6b; font-size: 11px; word-break: break-all; }
  .panel .item .plain { color: #b0b8c8; }

  .tag-pass { background: #00ff8822; color: #00ff88; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
  .tag-encrypted { background: #ff6b6b22; color: #ff6b6b; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }

  /* Tabs */
  .tabs { display: flex; gap: 5px; margin-bottom: 20px; }
  .tab { padding: 10px 20px; border-radius: 8px 8px 0 0; border: 1px solid #233554; border-bottom: none;
         background: #0f1724; color: #64748b; cursor: pointer; font-size: 14px; }
  .tab.active { background: #1a2332; color: #00d4ff; border-color: #0f3460; }

  .tab-content { display: none; }
  .tab-content.active { display: block; }

  /* Add document */
  .add-form { display: flex; flex-direction: column; gap: 10px; }
  .add-form input, .add-form textarea {
    padding: 12px; border-radius: 8px; border: 1px solid #334155;
    background: #0f1724; color: #e0e0e0; font-size: 14px; outline: none; font-family: inherit;
  }
  .add-form textarea { resize: vertical; min-height: 80px; }
  .add-form button {
    padding: 12px; border-radius: 8px; border: none; cursor: pointer;
    background: #00ff88; color: #000; font-weight: 700; font-size: 14px; align-self: flex-start;
  }
  .msg { padding: 10px 15px; border-radius: 8px; margin-top: 10px; background: #00ff8822; color: #00ff88; font-size: 14px; display: none; }
  .msg.show { display: block; }

  @media (max-width: 768px) { .pipeline, .two-col { grid-template-columns: 1fr; } }
</style>
</head>
<body>
  <div class="header">
    <h1>🔐 Searchable Encryption for Secure Cloud Sharing</h1>
    <p>Project No: 20 — Search encrypted documents without revealing keywords to the cloud server</p>
  </div>

  <div class="container">
    <div class="tabs">
      <div class="tab active" onclick="switchTab('search')">🔍 Search</div>
      <div class="tab" onclick="switchTab('documents')">📄 Documents</div>
      <div class="tab" onclick="switchTab('server')">🖥️ Server View</div>
      <div class="tab" onclick="switchTab('add')">➕ Add Document</div>
    </div>

    <!-- SEARCH TAB -->
    <div class="tab-content active" id="tab-search">
      <div class="search-box">
        <h2>🔍 Search Encrypted Documents</h2>
        <div class="search-row">
          <input type="text" id="searchInput" placeholder="Type a keyword (e.g. encryption, cloud, machine)..." onkeydown="if(event.key==='Enter')doSearch()">
          <button onclick="doSearch()">Search</button>
        </div>
        <div class="keyword-hints">
          Try: KEYWORD_HINTS_PLACEHOLDER
        </div>
      </div>

      <div class="results" id="results">
        <h2>Search Pipeline</h2>
        <div class="pipeline">
          <div class="step">
            <div class="label">① Your Keyword</div>
            <div class="value green" id="res-keyword"></div>
          </div>
          <div class="step">
            <div class="label">② Trapdoor Sent to Server</div>
            <div class="value" id="res-trapdoor"></div>
          </div>
          <div class="step">
            <div class="label">③ Server Returns</div>
            <div class="value" id="res-encrypted" style="color:#ff6b6b"></div>
          </div>
        </div>
        <h2 id="res-heading"></h2>
        <div id="res-docs"></div>
      </div>
    </div>

    <!-- DOCUMENTS TAB -->
    <div class="tab-content" id="tab-documents">
      <div class="two-col">
        <div class="panel">
          <h2>👤 Client View <span class="tag-pass">DECRYPTED</span></h2>
          <div id="client-docs"></div>
        </div>
        <div class="panel">
          <h2>🖥️ Server View <span class="tag-encrypted">ENCRYPTED</span></h2>
          <div id="server-docs"></div>
        </div>
      </div>
    </div>

    <!-- SERVER TAB -->
    <div class="tab-content" id="tab-server">
      <div class="panel" style="margin-bottom:20px">
        <h2>🗂️ Encrypted Index (What the Server Stores)</h2>
        <p style="color:#64748b;margin-bottom:15px;font-size:13px">The server maps trapdoor hashes → encrypted posting lists. It cannot read either side.</p>
        <div id="server-index"></div>
      </div>
      <div class="panel">
        <h2>📋 Server Search Log</h2>
        <p style="color:#64748b;margin-bottom:15px;font-size:13px">Every search the server received — only trapdoor tokens, NEVER keywords.</p>
        <div id="server-log">No searches yet.</div>
      </div>
    </div>

    <!-- ADD DOC TAB -->
    <div class="tab-content" id="tab-add">
      <div class="panel">
        <h2>➕ Add a New Document</h2>
        <p style="color:#64748b;margin-bottom:15px;font-size:13px">Add your own document, then search for keywords from it.</p>
        <div class="add-form">
          <input type="text" id="newDocId" placeholder="Document ID (e.g. doc9)">
          <textarea id="newDocContent" placeholder="Document content..."></textarea>
          <button onclick="addDocument()">Encrypt & Upload</button>
        </div>
        <div class="msg" id="addMsg"></div>
      </div>
    </div>
  </div>

<script>
function switchTab(name) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
  if (name === 'documents') loadDocuments();
  if (name === 'server') loadServerView();
}

function doSearch() {
  const kw = document.getElementById('searchInput').value.trim();
  if (!kw) return;
  fetch('/api/search?keyword=' + encodeURIComponent(kw))
    .then(r => r.json())
    .then(data => {
      document.getElementById('results').classList.add('show');
      document.getElementById('res-keyword').textContent = kw;
      document.getElementById('res-trapdoor').textContent = data.trapdoor;
      document.getElementById('res-encrypted').textContent = data.encrypted_result || 'No match';
      const docsDiv = document.getElementById('res-docs');
      docsDiv.innerHTML = '';
      if (data.results.length === 0) {
        document.getElementById('res-heading').textContent = 'No documents found';
        docsDiv.innerHTML = '<div class="no-results">No documents contain the keyword "' + kw + '"</div>';
      } else {
        document.getElementById('res-heading').textContent = data.results.length + ' Document(s) Found (Client Decrypted)';
        data.results.forEach(r => {
          const highlighted = r.content.replace(new RegExp('(' + kw + ')', 'gi'), '<span class="highlight">$1</span>');
          docsDiv.innerHTML += '<div class="doc-result"><div class="doc-id">📄 ' + r.doc_id + '</div><div class="doc-content">' + highlighted + '</div></div>';
        });
      }
    });
}

function loadDocuments() {
  fetch('/api/documents').then(r => r.json()).then(data => {
    let clientHtml = '', serverHtml = '';
    data.forEach(d => {
      clientHtml += '<div class="item"><div class="id">📄 ' + d.doc_id + '</div><div class="plain">' + d.plaintext + '</div></div>';
      serverHtml += '<div class="item"><div class="id">🔒 ' + d.doc_id + '</div><div class="enc">' + d.encrypted + '</div></div>';
    });
    document.getElementById('client-docs').innerHTML = clientHtml;
    document.getElementById('server-docs').innerHTML = serverHtml;
  });
}

function loadServerView() {
  fetch('/api/server-view').then(r => r.json()).then(data => {
    let indexHtml = '';
    data.index.forEach(entry => {
      indexHtml += '<div class="item"><div class="enc">🔑 ' + entry.address + '</div><div class="enc" style="margin-top:4px">→ ' + entry.value + '</div></div>';
    });
    document.getElementById('server-index').innerHTML = indexHtml || 'Empty index';

    let logHtml = '';
    if (data.search_log.length === 0) {
      logHtml = '<div class="item" style="color:#64748b">No searches performed yet. Go search something!</div>';
    } else {
      data.search_log.forEach((entry, i) => {
        logHtml += '<div class="item"><div class="enc">Search #' + (i+1) + ': ' + entry + '</div></div>';
      });
    }
    document.getElementById('server-log').innerHTML = logHtml;
  });
}

function addDocument() {
  const docId = document.getElementById('newDocId').value.trim();
  const content = document.getElementById('newDocContent').value.trim();
  if (!docId || !content) { alert('Please fill in both fields'); return; }
  fetch('/api/add-document', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({doc_id: docId, content: content})})
    .then(r => r.json()).then(data => {
      const msg = document.getElementById('addMsg');
      msg.textContent = '✅ Document "' + docId + '" encrypted & uploaded! Index now has ' + data.index_entries + ' entries. Try searching for keywords from your document.';
      msg.classList.add('show');
      document.getElementById('newDocId').value = '';
      document.getElementById('newDocContent').value = '';
    });
}

// Click on keyword hints
document.addEventListener('click', function(e) {
  if (e.target.matches('.keyword-hints span')) {
    document.getElementById('searchInput').value = e.target.textContent;
    doSearch();
  }
});
</script>
</body>
</html>"""


# ── HTTP Handler ────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        # Clean log
        print(f"  {args[0]}")

    def _send(self, code, content, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(content.encode() if isinstance(content, str) else content)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/":
            # Build keyword hints
            pt_index = build_plaintext_index(DOCUMENTS)
            # Pick popular keywords
            popular = sorted(pt_index.keys(), key=lambda k: len(pt_index[k]), reverse=True)[:12]
            hints = " ".join(f"<span>{html.escape(kw)}</span>" for kw in popular)
            page = HTML_PAGE.replace("KEYWORD_HINTS_PLACEHOLDER", hints)
            self._send(200, page)

        elif path == "/api/search":
            kw = params.get("keyword", [""])[0].strip()
            if not kw:
                self._send(400, json.dumps({"error": "no keyword"}), "application/json")
                return

            trapdoor = client.get_trapdoor(kw)
            enc_result = server.search(trapdoor)
            results = client.search(kw)

            result_docs = []
            for doc_id in results:
                content = client.retrieve_and_decrypt(doc_id)
                result_docs.append({"doc_id": doc_id, "content": content})

            resp = {
                "keyword": kw,
                "trapdoor": trapdoor,
                "encrypted_result": enc_result.hex()[:80] + "..." if enc_result else None,
                "results": result_docs,
            }
            self._send(200, json.dumps(resp), "application/json")

        elif path == "/api/documents":
            docs = []
            for doc_id in DOCUMENTS:
                enc = server.retrieve_document(doc_id)
                docs.append({
                    "doc_id": doc_id,
                    "plaintext": DOCUMENTS[doc_id],
                    "encrypted": enc.hex()[:80] + "..." if enc else "N/A",
                })
            self._send(200, json.dumps(docs), "application/json")

        elif path == "/api/server-view":
            index_entries = []
            for addr, val in list(server.encrypted_index.items())[:10]:
                index_entries.append({
                    "address": addr,
                    "value": val.hex()[:60] + "...",
                })
            resp = {
                "index": index_entries,
                "search_log": server.get_search_log(),
                "total_index_entries": server.index_entry_count,
            }
            self._send(200, json.dumps(resp), "application/json")

        else:
            self._send(404, "Not Found")

    def do_POST(self):
        if self.path == "/api/add-document":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            doc_id = body.get("doc_id", "").strip()
            content = body.get("content", "").strip()

            if doc_id and content:
                DOCUMENTS[doc_id] = content
                client.add_document(doc_id, content)
                client.upload_all()
                resp = {"status": "ok", "doc_id": doc_id, "index_entries": server.index_entry_count}
            else:
                resp = {"status": "error", "message": "Missing doc_id or content"}

            self._send(200, json.dumps(resp), "application/json")
        else:
            self._send(404, "Not Found")


# ── Main ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    PORT = 5000
    httpd = HTTPServer(("127.0.0.1", PORT), Handler)
    print()
    print("  ╔════════════════════════════════════════════════════════════╗")
    print("  ║   Searchable Encryption — Web Interface                   ║")
    print("  ╠════════════════════════════════════════════════════════════╣")
    print(f"  ║   Open your browser at:  http://localhost:{PORT}            ║")
    print("  ║   Press Ctrl+C to stop                                    ║")
    print("  ╚════════════════════════════════════════════════════════════╝")
    print()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
