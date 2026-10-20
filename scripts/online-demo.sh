#!/usr/bin/env bash
# Server-issued-key tier demo: start the license server, show that a valid
# client unlocks the asset, a revoked token and a down server do not, and the
# key/asset are not in the client binary. The key lives only on the server.
set -u
cd "$(dirname "$0")/.."
PORT=8787

python3 server/license_server.py --port "$PORT" &
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

echo "== valid token + server up (asset unlocks) =="
REN_PORT=$PORT ./build/online_o0 || true
echo "== revoked token (server declines) =="
REN_PORT=$PORT REN_TOKEN=CUST-9000-rv ./build/online_o0 || true
echo "== server down (no offline key) =="
REN_PORT=9999 ./build/online_o0 || true
echo "== key/asset in the client binary? =="
strings -n 5 build/online_o0 | grep -E "ACME-PRO|UNLOCK-OK" \
  || echo "  not present (token + ciphertext only)"
