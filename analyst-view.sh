#!/usr/bin/env bash
# The "analyst view": the first things a reverse engineer looks at.
# No decompiler needed -- symbols, strings, and the disassembled control
# flow of check_license are exactly what the hardening layers change.
set -euo pipefail
BIN="${1:?usage: analyst-view.sh <binary>}"

line() { printf '\n==== %s ====\n' "$1"; }

line "FILE / SYMBOLS PRESENT?  (layer 1 target)"
file "$BIN" | sed 's/, */,\n  /g'
echo "-- exported/defined function symbols:"
nm "$BIN" 2>/dev/null | grep -iE ' [TtWw] ' || echo "  (none -- stripped)"

line "STRINGS  (layer 2 target: landmarks for xref search)"
strings -n 5 "$BIN" | grep -iE 'licen|acme|valid|invalid|welcome|key' \
  || echo "  (no obvious license landmarks found)"

line "DISASSEMBLY of check_license (control-flow / constants)"
if nm "$BIN" 2>/dev/null | grep -q 'check_license'; then
  objdump -d --disassemble='check_license' "$BIN" 2>/dev/null \
    | sed -n '/<check_license>:/,/^$/p' | head -60
else
  echo "  symbol stripped -- an analyst must now FIND the function first."
  echo "  (with a decompiler they still can; the point is it costs more.)"
fi
echo
