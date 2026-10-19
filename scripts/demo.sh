#!/usr/bin/env bash
#
# Demo script for a GIF / asciinema recording. It tells the REN story in four
# beats: measure -> harden -> re-measure -> the AI-specific result.
#
# Record with:   asciinema rec ren-demo.cast -c ./scripts/demo.sh
# or screen-record a terminal while running it.
#
# Pacing is built in via `step` (a short pause + a printed command) so the GIF
# is readable. Requires: the repo built (`make all`), Docker + grammatech/ddisasm
# for the harden beat, and a local Ollama model for the agent beat.
set -e
cd "$(dirname "$0")/.."

pause() { sleep "${1:-2}"; }
say()   { printf '\n\033[1;36m# %s\033[0m\n' "$1"; pause 1; }
run()   { printf '\033[1;32m$ %s\033[0m\n' "$*"; pause 1; eval "$*"; pause 2; }

say "1. Measure: how exposed is an unprotected binary to an AI reverse-engineer?"
run "python3 harness/reexpose.py build/baseline --quiet"

say "2. Harden: strip metadata + encrypt strings, with a byte-exact behavior gate"
run "make m3-encrypt 2>/dev/null | grep -E 'per-use|load-time|verify'"

say "3. Re-measure: the exposure score drops, behavior unchanged"
run "python3 harness/reexpose.py build/baseline --compare build/hardened.strip | tail -n 3"

say "4. The AI-specific result: ask a local LLM to explain the function"
say "   clean vs control-flow-flattened (the static metrics do NOT move; this does)"
run "make agent-demo 2>/dev/null | grep -E 'exposure|summary|clean|flatten' || make agent-demo"

say "Takeaway: obfuscation collapses what the AI can recover (66.7 -> 0),"
say "while symbols/strings/metadata stay put. REN measures that gap."
pause 2
