#!/usr/bin/env bash
# Server-side execution tier: the secret pricing model runs on the server; the
# client sends inputs and shows only the returned price. Start the server, show
# valid/revoked/down clients, and that the client binary holds no coefficients.
set -u
cd "$(dirname "$0")/.."
PORT=8788

python3 server/compute_server.py --port "$PORT" &
SRV=$!
trap 'kill "$SRV" 2>/dev/null' EXIT

python3 - "$PORT" <<'PY'
import socket, sys, time
p = int(sys.argv[1])
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", p), 0.1).close(); break
    except OSError:
        time.sleep(0.05)
PY

echo "== valid token: the server runs the secret model, returns only a price =="
REN_PORT=$PORT ./build/compute_o0 100 pro || true
REN_PORT=$PORT ./build/compute_o0 500 ent || true
echo "== revoked token (server declines) =="
REN_PORT=$PORT REN_TOKEN=CUST-9000-rv ./build/compute_o0 100 pro || true
echo "== server down =="
REN_PORT=9999 ./build/compute_o0 100 pro || true
echo "== coefficients / model in the client binary? =="
strings -n 4 build/compute_o0 | grep -E "0\.000417|42\.13|1\.87|PRICING-MODEL|C0EF" \
  || echo "  not present (no model in the client)"
