#!/usr/bin/env python3
"""reharden -- post-build anchor denial for ELF and PE binaries.

Removes the metadata a reverse engineer (and especially an LLM/agent) anchors
on -- the symbol table, debug info, build-id, and toolchain notes -- WITHOUT
recompiling and WITHOUT touching code. This is module 1 (anchor denial) in its
no-rebuild form: it operates on a finished binary, so it drops into a release
pipeline right after the compiler.

It strips *metadata* only. It never obfuscates logic and never changes or hides
what the program DOES; it removes the free navigation aids an analyst gets for
nothing. Removed sections are non-loadable (symbol table, .debug_*, .comment,
build-id / .drectve) -- the loader never maps them -- so behavior is preserved.
PE unwind (.pdata/.xdata), relocations (.reloc) and imports are kept. Pair with
reexpose to measure the exposure drop.

Usage:
    reharden.py <in> [-o <out>] [--aggressive] [--run "<args>"]

    -o <out>       output path (default: <in>.hardened)
    --aggressive   (ELF) also drop .note.ABI-tag / .note.gnu.property
    --run "<args>" execute the hardened binary with <args> to confirm it still
                   runs (PE runs under Wine; reports exit code, crash fails it)
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys

# import the scanner so we can show before/after exposure
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "harness"))
try:
    from reexpose import scan, detect_format  # type: ignore
except Exception:  # scanner is optional; hardening still works without it
    scan = None
    def detect_format(_p):  # minimal fallback
        try:
            with open(_p, "rb") as fh:
                return "elf" if fh.read(4) == b"\x7fELF" else "other"
        except OSError:
            return "unknown"

# non-loadable sections safe to remove without changing behavior
_ELF_SAFE = [".comment", ".note.gnu.build-id", ".note.gnu.gold-version"]
_ELF_AGGRESSIVE = [".note.ABI-tag", ".note.gnu.property"]
# PE: COFF symtab goes via strip; these are non-loadable metadata. NOT removed:
# .pdata/.xdata (unwind), .reloc (ASLR), .idata/.edata (imports/exports).
_PE_SAFE = [".comment", ".drectve", ".debug_info", ".debug_abbrev",
            ".debug_line", ".debug_str", ".debug_line_str", ".debug_aranges",
            ".debug_ranges", ".debug_rnglists", ".debug_loc", ".debug_loclists",
            ".debug_frame", ".debug_pubnames", ".debug_pubtypes"]


def _run(cmd: list[str]) -> tuple[int, str]:
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, (p.stderr or p.stdout)


def _optval(a, flag, default=None):
    """Value after `flag`, or `default` if absent; clean error if it has none."""
    if flag not in a:
        return default
    i = a.index(flag)
    if i + 1 >= len(a):
        raise SystemExit(f"error: {flag} needs a value")
    return a[i + 1]


def _exec(path: str, runargs: list[str]) -> tuple[int, bytes]:
    """Run a binary (PE under Wine) and return (exit code, stdout) with argv[0]
    normalized so two paths compare equal. Bytes, to survive non-UTF-8 output."""
    ap = os.path.abspath(path)
    pe = detect_format(path) == "pe"
    cmd = (["wine64"] if pe else []) + [ap, *runargs]
    env = {**os.environ, "WINEDEBUG": "-all"}
    p = subprocess.run(cmd, capture_output=True, timeout=60, env=env)
    return p.returncode, p.stdout.replace(ap.encode(), b"<SELF>")


def harden(src: str, out: str, aggressive: bool = False) -> list[str]:
    """Produce a hardened copy of `src` at `out`. Returns the steps applied.
    Works on ELF and PE -- both carry a removable symbol table and debug info,
    and `strip`/`objcopy` handle both formats."""
    fmt = detect_format(src)
    if fmt not in ("elf", "pe"):
        raise SystemExit(f"reharden: {src} is {fmt}; only ELF and PE are "
                         "supported (Mach-O: use strip -S/-x).")
    shutil.copy2(src, out)
    os.chmod(out, 0o755)
    steps = []

    rc, err = _run(["strip", "--strip-all", out])
    if rc != 0:
        raise SystemExit(f"reharden: strip failed: {err.strip()}")
    steps.append("strip --strip-all (symbols + debug)")

    if fmt == "elf":
        sections = list(_ELF_SAFE) + (_ELF_AGGRESSIVE if aggressive else [])
    else:
        sections = list(_PE_SAFE)
    for sec in sections:
        # only present sections remove cleanly; objcopy errors on absent ones
        rc, err = _run(["objcopy", f"--remove-section={sec}", out])
        if rc == 0:
            steps.append(f"remove {sec}")
    return steps


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if args else 2

    src = args[0]
    out = _optval(args, "-o", src + ".hardened")
    aggressive = "--aggressive" in args

    before = scan(src) if scan else None
    steps = harden(src, out, aggressive)
    after = scan(out) if scan else None

    print(f"\nhardened: {src}  ->  {out}")
    for s in steps:
        print(f"  - {s}")

    if "--run" in args:
        # byte-exact behavior gate: run original vs hardened, compare rc+stdout
        runargs = shlex.split(_optval(args, "--run"))
        how = " (under Wine)" if detect_format(out) == "pe" else ""
        try:
            rc0, o0 = _exec(src, runargs)
            rc1, o1 = _exec(out, runargs)
        except Exception as e:
            print(f"\nrun check: FAILED to execute -- {e}", file=sys.stderr)
            return 1
        same = rc0 == rc1 and o0 == o1
        print(f"\nrun check{how}: {'identical' if same else 'DIVERGED'} "
              f"(orig rc={rc0}, out rc={rc1})")
        if not same:
            return 1

    if before and after:
        db = before["exposure_score"]
        da = after["exposure_score"]
        print(f"\nexposure: {db} ({before['protection_grade']})"
              f"  ->  {da} ({after['protection_grade']})"
              f"   [-{round(db - da, 1)}]")
        for name in before["axes"]:
            b = before["axes"][name]["score"]
            a = after["axes"][name]["score"]
            if abs(b - a) >= 0.1:
                print(f"    {name:9s} {b:5.1f} -> {a:5.1f}")
    else:
        print("\n(install/colocate reexpose.py to see the exposure delta)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
