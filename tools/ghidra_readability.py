#!/usr/bin/env python3
"""ghidra_readability -- run Ghidra headless and return decompiler readability
metrics for an ELF binary (the "deep" axis for reexpose).

Needs Ghidra (GHIDRA_HOME, or ~/ghidra_*_PUBLIC). Slow (tens of seconds): it
imports, auto-analyzes, and decompiles every function. Meant to be opt-in.

Usage: ghidra_readability.py <binary> [--json]
"""
from __future__ import annotations

import glob
import json
import os
import subprocess
import sys
import tempfile


def find_ghidra() -> str | None:
    env = os.environ.get("GHIDRA_HOME")
    if env and os.path.isdir(env):
        return env
    hits = sorted(glob.glob(os.path.expanduser("~/ghidra_*_PUBLIC")))
    return hits[-1] if hits else None


def readability(binary: str, func: str = None, timeout: int = 240) -> dict:
    home = find_ghidra()
    if not home:
        raise SystemExit("ghidra_readability: no Ghidra (set GHIDRA_HOME)")
    headless = os.path.join(home, "support", "analyzeHeadless")
    script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghidra")
    with tempfile.TemporaryDirectory() as td:
        proj = os.path.join(td, "proj")
        os.mkdir(proj)
        out = os.path.join(td, "metrics.json")
        post = ["-postScript", "readability.py", out]
        if func:
            post.append(func)       # restrict metrics to one function
        cmd = [headless, proj, "scan", "-import", os.path.abspath(binary),
               "-scriptPath", script_dir, *post, "-deleteProject"]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if not os.path.exists(out):
            raise SystemExit("ghidra_readability: no metrics produced\n"
                             + p.stdout[-1500:] + p.stderr[-500:])
        with open(out) as fh:
            m = json.load(fh)
    if not m.get("functions"):
        # 0 functions would score 0 (looks "fully hardened"); fail instead so a
        # wrong --func name or empty analysis is visible, not silently perfect.
        raise SystemExit("ghidra_readability: no functions analyzed "
                         "(wrong --func name, or nothing decompiled)")
    return m


def score(m: dict) -> float:
    """Map raw metrics to a 0..100 readability-exposure score: clean,
    decompilable code scores HIGH (exposed); undecompilable, junk-ridden, or
    control-flow-flattened code scores LOW (protected).

    Note: control-flow keyword density is NOT rewarded -- obfuscation inflates
    it (dispatch switches, bogus branches). Instead we reward successful, clean
    decompilation and penalize the obfuscation signatures: decompiler junk
    tokens, flattening, and dispatch (case-label) density."""
    n = max(1, m["functions"])
    lines = max(1, m["nonblank_lines"])
    decompile_rate = m["decompiled_ok"] / n
    junk = m["junk_tokens"] / lines                    # undefined/unaff_/...
    flat = m["flattened_funcs"] / n                    # dispatch-loop signature
    case_density = m.get("case_labels", 0) / lines     # flattening bloat
    r = (decompile_rate
         * max(0.0, 1.0 - 2.5 * junk)
         * (1.0 - 0.7 * flat)
         * (1.0 - min(0.6, 5.0 * case_density)))
    return max(0.0, min(100.0, 100.0 * r))


def main() -> int:
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        return 2
    func = a[a.index("--func") + 1] if "--func" in a else None
    m = readability(a[0], func)
    m["readability_score"] = round(score(m), 1)
    if "--json" in a:
        print(json.dumps(m, indent=2))
    else:
        print(f"{a[0]}: readability-exposure {m['readability_score']}/100")
        print(f"  functions={m['functions']} decompiled={m['decompiled_ok']} "
              f"lines={m['nonblank_lines']} ctrl={m['ctrl_keywords']} "
              f"junk={m['junk_tokens']} flattened={m['flattened_funcs']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
