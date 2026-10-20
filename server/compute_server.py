#!/usr/bin/env python3
"""compute_server -- server-side execution tier (the strongest).

The secret here is an ALGORITHM, not a static asset: proprietary pricing
coefficients that live only on this server. The client sends inputs (quantity,
tier) with its token; the server validates the token, runs the secret model, and
returns only the resulting price. The algorithm and its coefficients never reach
the client, so reverse-engineering the client reveals the request shape and
nothing about the IP: there is no key, asset, or formula in the binary to
recover, even while the server is up and answering.

  POST /compute   body: "<token> <qty> <tier>"   ->  200 + price, or 403.

Reuses the token database in server/licenses.json (valid, non-revoked), so the
same revocation and usage-visibility apply.

Honest boundary: this reduces the attack from "read the code" to "black-box
model extraction": an authorized caller can probe the oracle with many inputs
and try to approximate the model. That is a much harder attack, needs many
queries, and the server can rate-limit, add noise, or detect scraping. For IP
that must produce client-visible outputs, this is the strongest tier; there is
nothing beyond it, because any output at all is information.

  python3 server/compute_server.py [--port 8788]
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
LIC = os.path.join(HERE, "licenses.json")

# --- the IP: these live only on the server, never in any client ------------
COEFFS = {"base": 42.13, "elastic": 1.87, "ceiling": 2000.0, "decay": 0.000417}
TIER_MULT = {"basic": 1.0, "pro": 1.4, "ent": 2.2}
MODEL_TAG = "PRICING-MODEL-v3-C0EF-7x31"      # proprietary; never sent anywhere


def price(qty, tier):
    c = COEFFS
    base = c["base"] + c["elastic"] * qty - c["decay"] * qty * qty
    return max(0.0, min(c["ceiling"], base * TIER_MULT.get(tier, 1.0)))


def valid_token(token):
    try:
        with open(LIC) as f:
            conf = json.load(f)
    except Exception:
        return False
    rec = conf.get("tokens", {}).get(token)
    return bool(rec) and not rec.get("revoked")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        if self.path != "/compute":
            self.send_error(404)
            return
        n = int(self.headers.get("Content-Length", 0))
        parts = self.rfile.read(n).decode("utf-8", "replace").split()
        if len(parts) < 3:
            self.send_error(400)
            return
        token, qty_s, tier = parts[0], parts[1], parts[2]
        if not valid_token(token):
            print(f"[deny]    token={token!r}", flush=True)
            self.send_response(403)
            self.end_headers()
            return
        try:
            qty = float(qty_s)
        except ValueError:
            self.send_error(400)
            return
        p = price(qty, tier)
        out = f"{p:.4f}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
        print(f"[compute] token={token} qty={qty} tier={tier} -> {p:.4f}",
              flush=True)


def main():
    port = 8788
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])
    print(f"compute server on 127.0.0.1:{port} (POST /compute)", flush=True)
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
