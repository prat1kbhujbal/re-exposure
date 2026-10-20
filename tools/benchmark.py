#!/usr/bin/env python3
"""benchmark -- tiered agent-exposure table across attacker strengths.

Runs the agent summary-accuracy axis (tools/agent_summary.py) over a small
fixed corpus at three escalating "attacker strengths" and prints one table, so
the progression is reproducible instead of anecdotal:

  pseudocode  one-shot LLM on Ghidra's decompiled C   (trusts the decompiler)
  disasm      one-shot LLM on raw objdump output      (reads asm directly)
  agentic     one-shot LLM on disasm + binary strings (what an agent gathers)

The point the table is meant to make honestly: obfuscation that breaks the
decompiler drops the `pseudocode` score to near zero, but `disasm` and
`agentic` recover much of it, and `agentic` recovers a plaintext .rodata secret
outright. So a low pseudocode number is decompiler difficulty, not agent
resistance. The gap between the columns is the real signal.

Each cell is scored 0-100; a `*` marks that the model reproduced the literal
secret. Runs a LOCAL model via Ollama (set REEXPOSE_MODEL, e.g.
qwen2.5-coder:32b). `pseudocode` additionally needs Ghidra (GHIDRA_HOME); it is
slow, so narrow the run with --sources when you only want the asm-based columns.

Usage:
  benchmark.py [--sources pseudocode,disasm,agentic] [--json]
  REEXPOSE_MODEL=qwen2.5-coder:32b python3 tools/benchmark.py --sources disasm,agentic
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent_summary import evaluate, MODEL  # type: ignore

B = os.environ.get("REN_BUILD", "build")

# (label, binary, func, secret). Same function, built clean vs control-flow
# flattened, behavior identical -- so any column that moves between the two
# rows is measuring the obfuscation, not a different program.
CORPUS = [
    ("clean -O0",     f"{B}/clean_o0", "check_license", "ACME-PRO-2026-XK7Q"),
    ("flattened -O0", f"{B}/flat_o0",  "check_license", "ACME-PRO-2026-XK7Q"),
]

SOURCES = ["pseudocode", "disasm", "agentic"]


def run(sources, corpus):
    rows = []
    for label, binary, func, secret in corpus:
        cells = {}
        for src in sources:
            try:
                sc, d = evaluate(binary, func, secret, source=src)
                cells[src] = {"score": round(sc, 1),
                              "secret": d["secret_recovered"],
                              "hedged": d["hedged"]}
                note = f"{sc:5.1f}  secret={d['secret_recovered']}"
            except Exception as e:                       # one cell, not the run
                cells[src] = {"error": str(e)[:70]}
                note = f"n/a  ({str(e)[:50]})"
            print(f"  {label:16} {src:11} -> {note}", file=sys.stderr,
                  flush=True)
        rows.append((label, cells))
    return rows


def table(rows, sources):
    w = 16
    head = "binary".ljust(w) + "".join(s.ljust(12) for s in sources)
    out = [head, "-" * len(head)]
    for label, cells in rows:
        line = label.ljust(w)
        for s in sources:
            c = cells[s]
            if "error" in c:
                cell = "n/a"
            else:
                cell = f"{c['score']:.0f}" + ("*" if c["secret"] else "")
            line += cell.ljust(12)
        out.append(line)
    out += ["", "score 0-100 (higher = more exposed); "
            "* = model reproduced the literal secret."]
    return "\n".join(out)


def main() -> int:
    a = sys.argv[1:]
    sources = SOURCES
    if "--sources" in a:
        i = a.index("--sources")
        if i + 1 >= len(a):
            raise SystemExit("error: --sources needs a value")
        sources = [s.strip() for s in a[i + 1].split(",") if s.strip()]
        bad = [s for s in sources if s not in SOURCES]
        if bad:
            raise SystemExit(f"error: unknown source(s): {','.join(bad)}")

    print(f"model: {MODEL}   sources: {','.join(sources)}", file=sys.stderr)
    rows = run(sources, CORPUS)

    if "--json" in a:
        print(json.dumps({"model": MODEL, "sources": sources,
                          "rows": {label: cells for label, cells in rows}},
                         indent=2))
    else:
        print()
        print(table(rows, sources))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
