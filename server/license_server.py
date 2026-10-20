#!/usr/bin/env python3
"""license_server -- mock server-issued-key license server.

Holds the license key that decrypts the protected asset. The client binary
never contains it: the client authenticates with an opaque token and the server
returns the key only for a valid, non-revoked token, logging every issuance.
This is the property offline protection cannot have. Even a perfectly extracted
client yields only ciphertext; the key is on the server, and the server enforces
per-license policy (revocation, rate limits, usage visibility) that a key
shipped inside the binary cannot.

  POST /key   body: the client's token  ->  200 + key, or 403.

Config in server/licenses.json, re-read each request so revocation takes effect
without a restart:
  {"secret_key": "...",
   "tokens": {"<token>": {"revoked": false, "name": "..."}}}

Honest boundary: once the server releases the key to an authorized client, that
client holds the plaintext asset in memory and could dump it. Stopping that
needs server-side EXECUTION (the secret logic runs on the server; the client
gets only results), the stronger tier this scaffolds toward. The wins here are
real nonetheless: offline or server-down yields nothing, a revoked token yields
nothing, and the key never persists in the client.

  python3 server/license_server.py [--port 8787]
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

CONF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "licenses.json")


def load_conf():
    with open(CONF) as f:
        return json.load(f)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):           # silence default noise; we log below
        pass

    def do_POST(self):
        if self.path != "/key":
            self.send_error(404)
            return
        n = int(self.headers.get("Content-Length", 0))
        token = self.rfile.read(n).decode("utf-8", "replace").strip()
        try:
            conf = load_conf()
        except Exception as e:
            print(f"[error] config: {e}", flush=True)
            self.send_error(500)
            return
        rec = conf.get("tokens", {}).get(token)
        if not rec:
            self._deny(token, "unknown token")
            return
        if rec.get("revoked"):
            self._deny(token, "revoked")
            return
        key = conf["secret_key"].encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(key)))
        self.end_headers()
        self.wfile.write(key)
        print(f"[issue] token={token} name={rec.get('name')!r} key released",
              flush=True)

    def _deny(self, token, why):
        print(f"[deny]  token={token!r} ({why})", flush=True)
        self.send_response(403)
        self.end_headers()


def main():
    port = 8787
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])
    srv = HTTPServer(("127.0.0.1", port), Handler)
    print(f"license server on 127.0.0.1:{port} (POST /key)", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
