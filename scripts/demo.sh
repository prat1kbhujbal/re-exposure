#!/usr/bin/env bash
#
# Demo script for a GIF / asciinema recording. It tells the re-exposure story in
# four beats: measure -> an agent cracks the hardened binary -> what actually
# holds -> the takeaway.
#
# Record with:   asciinema rec demo.cast -c ./scripts/demo.sh
# or screen-record a terminal while running it.
#
# Pacing is built in via helpers so the GIF is readable. Requires: binutils, a
# local Ollama model (REEXPOSE_MODEL) for the agent beats, and OpenSSL for the
# server-side tier. The make targets build what they need.
set -e
cd "$(dirname "$0")/.."

pause() { sleep "${1:-2}"; }
say()   { printf '\n\033[1;36m# %s\033[0m\n' "$1"; pause 1; }
run()   { printf '\033[1;32m$ %s\033[0m\n' "$*"; pause 1; eval "$*"; pause 2; }

say "1. Measure: how exposed is an unprotected binary to an AI reverse-engineer?"
run "python3 harness/reexpose.py build/baseline --quiet"

say "2. Turn an iterating agent loose: obfuscation does not stop it"
say "   plaintext is read at step 1; string-encrypted is cracked at step 3, read"
say "   off the strcmp at runtime. Obfuscation buys a step or two, not safety."
run "make attack-demo 2>/dev/null | grep -E 'CRACKED|not recovered|readable at' || true"

say "3. What holds: keep the secret off the client (server-side execution)"
say "   the secret logic runs on the server; the client gets only results."
run "make compute-demo 2>/dev/null | tail -n 6"

say "Takeaway: you cannot stop RE on the client, and an agent only makes it cheaper."
say "What you can do is not ship the secret. re-exposure measures the gap, and shows the ladder."
pause 2
