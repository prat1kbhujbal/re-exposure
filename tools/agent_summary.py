#!/usr/bin/env python3
"""agent_summary -- LLM summary-accuracy axis (the licensed-product core).

Decompiles a target function with Ghidra, asks a local LLM (Ollama) to explain
it, and scores how well the model understood it. Clean code -> accurate summary
-> HIGH exposure. Obfuscated code -> hedged/wrong summary -> LOW exposure. This
is the axis that directly measures resistance to AI/agent reverse engineering.

Uses a LOCAL model via Ollama, so the analyzed code never leaves the machine --
a selling point for a product customers run on their own binaries. Override with
OLLAMA_URL / REEXPOSE_MODEL.

Usage: agent_summary.py <binary> --func <name> [--secret "<literal>"]
                        [--concepts "a,b,c"] [--disasm] [--json]

  --secret   a literal value (e.g. the license key) whose appearance in the
             model's answer proves it recovered the logic; weighted heavily.
  --disasm   feed the model raw disassembly instead of Ghidra pseudocode. This
             models the agentic attacker, who reads asm directly. It matters:
             obfuscation that breaks the decompiler scores low with pseudocode
             but is partly recovered from disasm (flattened check_license:
             0 via pseudocode, 25 via disasm on a 32b model). So "pseudocode"
             measures decompiler readability, "disasm" the stronger attacker.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ghidra_readability import find_ghidra  # type: ignore

OLLAMA = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("REEXPOSE_MODEL", "qwen2.5-coder:1.5b")
HEDGES = ("unclear", "cannot", "can't", "unable", "not clear", "hard to tell",
          "difficult to", "unknown", "obfuscat", "not sure", "can not determine")


def pseudocode(binary: str, func: str | None) -> str:
    home = find_ghidra()
    if not home:
        raise SystemExit("agent_summary: no Ghidra (set GHIDRA_HOME)")
    hl = os.path.join(home, "support", "analyzeHeadless")
    sd = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghidra")
    with tempfile.TemporaryDirectory() as td:
        proj = os.path.join(td, "p")
        os.mkdir(proj)
        out = os.path.join(td, "p.c")
        post = ["-postScript", "dump_pseudocode.py", out] + ([func] if func else [])
        subprocess.run([hl, proj, "s", "-import", os.path.abspath(binary),
                        "-scriptPath", sd, *post, "-deleteProject"],
                       capture_output=True, text=True, timeout=240)
        return open(out).read() if os.path.exists(out) else ""


def disasm(binary: str, func: str) -> str:
    """Raw objdump disassembly of one function. This models the agentic
    attacker, who reasons about the asm directly rather than trusting the
    decompiler's structured output, so it recovers flattened control flow the
    decompiler fails on. Needs the symbol (will not find a stripped function)."""
    out = subprocess.run(["objdump", "-d", "--disassemble=" + func, binary],
                         capture_output=True, text=True).stdout
    lines = out.splitlines()
    for i, ln in enumerate(lines):
        if "<" + func + ">:" in ln:
            return "\n".join(lines[i:]).strip()
    return ""


def ask(prompt: str) -> str:
    body = json.dumps({"model": MODEL, "prompt": prompt, "stream": False,
                       "options": {"temperature": 0}}).encode()
    req = urllib.request.Request(OLLAMA + "/api/generate", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=240) as r:
        return json.loads(r.read())["response"].strip()


def score(summary: str, concepts: list[str], secret: str | None):
    """Reward recovered understanding: mechanism concepts (how it works) and,
    heavily, reproducing the literal secret (only possible if the logic was
    recovered). The function NAME leaking 'license' is deliberately not a
    concept, so clean vs obfuscated separate on mechanism, not naming."""
    s = summary.lower()
    hedged = any(h in s for h in HEDGES)
    hits = [c for c in concepts if c.lower() in s]
    concept_acc = len(hits) / max(1, len(concepts))
    secret_hit = bool(secret and secret.lower() in s)
    base = 0.5 * concept_acc + (0.5 if secret_hit else 0.0)
    if hedged:
        base *= 0.3                    # genuine hedging = did not understand
    return max(0.0, min(100.0, 100.0 * base)), hits, secret_hit, hedged


DEFAULT_CONCEPTS = ["compare", "match", "equal", "strcmp", "valid", "string"]


def evaluate(binary: str, func: str, secret: str = None,
             concepts: list[str] = None, source: str = "pseudocode"):
    """Ask the model to explain `func` and score understanding. `source` picks
    what the model sees: "pseudocode" (Ghidra decompiler output, measures
    decompiler readability to a one-shot LLM) or "disasm" (raw objdump, models
    the agentic attacker who reads asm directly). These differ: obfuscation that
    breaks the decompiler scores low under "pseudocode" but is partly recovered
    under "disasm", so report which source you used. Returns (score, detail)."""
    concepts = concepts or DEFAULT_CONCEPTS
    if source == "disasm":
        code = disasm(binary, func)
        if not code.strip():
            raise RuntimeError("no disassembly (stripped, or wrong func name?)")
        prompt = ("Here is x86-64 disassembly (AT&T syntax) of one function.\n\n"
                  "```\n" + code + "\n```\n\nReason about the control flow and "
                  "explain what this function does, how it works, and any "
                  "constant values or strings it compares against.")
    else:
        code = pseudocode(binary, func)
        if not code.strip():
            raise RuntimeError("no pseudocode (wrong func name?)")
        prompt = ("You are reverse engineering a program. Below is decompiled C "
                  "for one function.\n\n```c\n" + code + "\n```\n\nIn one or two "
                  "sentences, explain what this function does, how it works, and "
                  "any constant values it depends on.")
    summary = ask(prompt)
    sc, hits, secret_hit, hedged = score(summary, concepts, secret)
    return sc, {"summary": summary, "concepts_hit": hits, "source": source,
                "secret_recovered": secret_hit, "hedged": hedged}


def _optval(a, flag, default=None):
    """Value after `flag`, or `default` if absent; clean error if it has none."""
    if flag not in a:
        return default
    i = a.index(flag)
    if i + 1 >= len(a):
        raise SystemExit(f"error: {flag} needs a value")
    return a[i + 1]


def main() -> int:
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        return 2
    binary = a[0]
    func = _optval(a, "--func")
    concepts = [c.strip() for c in
                _optval(a, "--concepts", ",".join(DEFAULT_CONCEPTS)).split(",")
                if c.strip()]
    secret = _optval(a, "--secret")
    source = "disasm" if "--disasm" in a else "pseudocode"

    sc, d = evaluate(binary, func, secret, concepts, source)
    summary, hits = d["summary"], d["concepts_hit"]
    secret_hit, hedged = d["secret_recovered"], d["hedged"]

    if "--json" in a:
        print(json.dumps({"binary": binary, "func": func, "model": MODEL,
                          "source": source, "summary": summary,
                          "concepts_hit": hits, "secret_recovered": secret_hit,
                          "hedged": hedged,
                          "summary_accuracy_exposure": round(sc, 1)}, indent=2))
    else:
        print(f"model   : {MODEL}  (source: {source})")
        print(f"summary : {summary}")
        print(f"concepts: {hits}  secret_recovered={secret_hit}  hedged={hedged}")
        print(f"summary-accuracy exposure: {sc:.1f}/100")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
