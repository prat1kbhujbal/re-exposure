#!/usr/bin/env python3
"""reexpose -- AI-RE exposure scanner (measurement harness, MVP).

Scores how exposed an ELF binary is to reverse engineering by a human + a
decompiler, and especially by an LLM/agent analyzer (REA, GhidraMCP, ...),
which anchors its summaries on human-readable signals. Higher score = more
exposed = easier/cheaper for an agent to understand and clone.

This tool only MEASURES. It never modifies a binary and never hides behavior.
It is the inverse of an RE agent: an RE agent extracts understanding and reports
evidence; this reports how much understanding is cheaply available.

Backends: the static axes need only binutils (nm, readelf, objdump, strings).
The opt-in `--deep` axis adds Ghidra decompiler readability (tools/ghidra_
readability.py); it is slow and skipped cleanly if Ghidra is absent. An LLM
summary-accuracy axis plugs in the same way (future).

Usage:
    reexpose.py <binary> [--json] [--quiet] [--gate <max>]
                [--deep] [--agent <func> [--secret <literal>]]
    reexpose.py <binary> --compare <other-binary> [--deep] [--agent <func>]

    --deep          add the Ghidra decompiler-readability axis (needs Ghidra)
    --agent <func>  add the LLM summary-accuracy axis for <func> (needs Ghidra +
                    a local Ollama model); --secret weights literal recovery
"""
from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

# --- axis weights (sum = 100). Tune as real adversary data comes in. ---------
WEIGHTS = {
    "symbols": 30,     # named functions/vars an agent uses to navigate
    "strings": 30,     # landmark strings for grep/xref pivots
    "metadata": 25,    # debug info, build paths, toolchain/lang provenance
    "entropy": 10,     # plaintext code (low entropy) vs packed/encrypted
    "imports": 5,      # interesting library calls that give an agent pivots
}

# Runtime/CRT symbols that are not application logic -- don't count as exposure.
_CRT_SYMBOLS = {
    "_start", "_init", "_fini", "__libc_csu_init", "__libc_csu_fini",
    "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux",
    "frame_dummy", "__libc_start_main", "__cxa_finalize", "__gmon_start__",
    "data_start", "__data_start", "__dso_handle", "_IO_stdin_used",
    "_ITM_registerTMCloneTable", "_ITM_deregisterTMCloneTable",
    "__TMC_END__", "__bss_start", "_edata", "_end", "__init_array_start",
    "__init_array_end", "completed",
}

# Strings that hand an analyst/agent a pivot straight to interesting logic.
_LANDMARK_LEXICON = [
    r"licen[cs]e", r"serial", r"activat", r"registrat", r"\btrial\b",
    r"\bkey\b", r"secret", r"password", r"passwd", r"token", r"api[_-]?key",
    r"auth", r"crypt", r"decrypt", r"encrypt", r"\bsign(ature)?\b",
    r"premium", r"unlock", r"expired?", r"invalid", r"denied", r"forbidden",
    r"jailbreak|root(ed)?|debugger|frida|ptrace",
]
_SECRET_WORDS = re.compile("|".join(_LANDMARK_LEXICON), re.I)
_SRCPATH = re.compile(r"(/[\w.\-/]+\.(c|cc|cpp|rs|go|swift|m|h))|([A-Za-z]:\\[\w.\-\\]+)")
_URL = re.compile(r"https?://[\w.\-/:%?=&]+", re.I)
_FMT = re.compile(r"%[-+ #0]*\d*(\.\d+)?[hlLqjzt]*[diouxXeEfgGaAcspn%]")

# Library calls that give an agent a strong pivot into behavior.
_PIVOT_IMPORTS = {
    "strcmp", "strncmp", "memcmp", "strcasecmp",          # comparisons (checks)
    "printf", "fprintf", "puts", "fputs",                 # message sites
    "fopen", "open", "read", "write",                     # file IO
    "socket", "connect", "send", "recv", "getaddrinfo",   # network
    "system", "exec", "execve", "fork",                   # exec
    "malloc", "memcpy",                                   # buffers
    "ptrace", "getenv",                                   # anti-debug / config
}


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""


def _clamp(x: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, x))


# --- format detection + cross-format section parsing ------------------------

_MACHO_MAGICS = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                 b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                 b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}  # last two = fat


def detect_format(binary: str) -> str:
    try:
        with open(binary, "rb") as fh:
            magic = fh.read(4)
    except OSError:
        return "unknown"
    if magic == b"\x7fELF":
        return "elf"
    if magic[:2] == b"MZ":
        return "pe"
    if magic in _MACHO_MAGICS:
        return "macho"
    return "unknown"


# code section names across formats (lets entropy find the real .text)
_CODE_SECTIONS = {".text", "__text", "CODE", ".text$mn"}

# objdump -h row:  Idx Name Size VMA LMA File-off Algn
_SECROW = re.compile(
    r"^\s*\d+\s+(\S+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+[0-9a-f]+\s+([0-9a-f]+)\s+2\*\*")


def get_sections(binary: str) -> list[tuple[str, int, int]]:
    """Return [(name, size, file_offset)] via objdump -h (ELF/PE; Mach-O needs
    an objdump that supports it, else empty)."""
    out = _run(["objdump", "-h", binary])
    rows = []
    for line in out.splitlines():
        m = _SECROW.match(line)
        if m:
            rows.append((m.group(1), int(m.group(2), 16), int(m.group(3), 16)))
    return rows


@dataclass
class AxisResult:
    score: float               # 0..100 exposure on this axis
    detail: dict = field(default_factory=dict)


# --- axis analyzers ----------------------------------------------------------

def _is_app_symbol(name: str) -> bool:
    # skip CRT, dunder, linker-defined _ALL_CAPS, and PE section/runtime
    # pseudo-symbols (.CRT$XCA, .rdata$zzz, names with '$')
    return (name not in _CRT_SYMBOLS and not name.startswith("__")
            and not name.startswith(".") and "$" not in name
            and not re.fullmatch(r"_[A-Z][A-Z0-9_]*", name))


def axis_symbols(binary: str) -> AxisResult:
    app = []
    out = _run(["nm", binary])
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] in ("T", "t", "W", "w", "D", "d"):
                if _is_app_symbol(parts[2]):
                    app.append(parts[2])
    else:
        # fallback for PE/Mach-O or nm gaps: objdump -t function symbols
        for line in _run(["objdump", "-t", binary]).splitlines():
            if " F " in line or "\tF\t" in line:
                name = line.split()[-1]
                if _is_app_symbol(name):
                    app.append(name)
    n = len(set(app))
    if n == 0:
        return AxisResult(0.0, {"app_symbols": 0,
                                "note": "no application symbols (stripped?)"})
    # Each recovered application name is a big navigation win for an agent.
    score = _clamp(100 * (1 - math.exp(-n / 4.0)))
    return AxisResult(score, {"app_symbols": n, "sample": sorted(set(app))[:12]})


def axis_strings(binary: str) -> AxisResult:
    out = _run(["strings", "-n", "4", binary])
    lines = out.splitlines()
    landmarks = sorted({s for s in lines if _SECRET_WORDS.search(s)})
    srcpaths = sorted({m.group(0) for s in lines for m in [_SRCPATH.search(s)] if m})
    urls = sorted({m.group(0) for s in lines for m in [_URL.search(s)] if m})
    fmts = sum(1 for s in lines if _FMT.search(s))
    hits = len(landmarks) * 3 + len(srcpaths) * 2 + len(urls) * 2 + min(fmts, 10)
    score = _clamp(100 * (1 - math.exp(-hits / 6.0)))
    return AxisResult(score, {
        "landmarks": landmarks[:12], "landmark_count": len(landmarks),
        "source_paths": srcpaths[:6], "urls": urls[:6], "format_strings": fmts,
    })


def axis_metadata(binary: str) -> AxisResult:
    fmt = detect_format(binary)
    if fmt == "elf":
        # readelf lists non-alloc sections (.symtab, .debug_*) objdump -h omits
        secnames = set(re.findall(r"^\s*\[\s*\d+\]\s+(\S+)",
                                  _run(["readelf", "-SW", binary]), re.M))
    else:
        secnames = {s[0] for s in get_sections(binary)}
    allstr = _run(["strings", binary])
    fileout = _run(["file", binary])
    flags, score = [], 0.0

    # debug info: ELF .debug_*, PE .debug/.pdata, Mach-O __debug*
    if any("debug" in n for n in secnames) or ".pdata" in secnames:
        flags.append("debug_sections"); score += 40
    if fmt == "elf" and ".symtab" in secnames:
        flags.append("symtab"); score += 20
    if "not stripped" in fileout:
        flags.append("not_stripped"); score += 15
    if fmt == "elf" and re.search(r"BuildID|Build ID",
                                  _run(["readelf", "-nW", binary])):
        flags.append("build_id"); score += 10
    if any(".go.buildinfo" in n for n in secnames) or "Go build ID" in allstr:
        flags.append("go_buildinfo"); score += 25
    if re.search(r"rustc|cargo", allstr):
        flags.append("rust_provenance"); score += 10
    if fmt == "pe" and re.search(r"[\w.\-\\/]+\.pdb\b", allstr, re.I):
        flags.append("pdb_path"); score += 20      # PE debug path -> source layout
    if fmt == "macho" and re.search(r"\.dSYM|LC_UUID", allstr):
        flags.append("dsym_ref"); score += 10
    return AxisResult(_clamp(score), {"format": fmt, "flags": flags})


def _section_entropy(binary: str) -> float | None:
    code = [s for s in get_sections(binary) if s[0] in _CODE_SECTIONS]
    if not code:
        return None
    _, size, off = max(code, key=lambda s: s[1])   # largest code section
    if not size:
        return None
    try:
        with open(binary, "rb") as fh:
            fh.seek(off)
            data = fh.read(size)
    except OSError:
        return None
    if not data:
        return None
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def axis_entropy(binary: str) -> AxisResult:
    h = _section_entropy(binary)
    if h is None:
        return AxisResult(50.0, {"note": "no .text section found"})
    # Plaintext compiled code ~6.0-6.6 bits => highly exposed to static read.
    # Packed/virtualized code ~7.8+ => little plaintext logic on disk.
    score = _clamp((7.6 - h) / (7.6 - 5.0) * 100)
    return AxisResult(score, {"text_entropy_bits": round(h, 3)})


def axis_imports(binary: str) -> AxisResult:
    # -T: ELF/Mach-O dynamic syms; -x: PE import table; -D: dynamic fallback
    out = (_run(["objdump", "-T", binary]) + _run(["objdump", "-x", binary])
           + _run(["nm", "-D", binary]))
    found = sorted({imp for imp in _PIVOT_IMPORTS
                    if re.search(rf"\b{imp}\b", out)})
    score = _clamp(100 * (1 - math.exp(-len(found) / 4.0)))
    return AxisResult(score, {"pivot_imports": found})


ANALYZERS = {
    "symbols": axis_symbols, "strings": axis_strings, "metadata": axis_metadata,
    "entropy": axis_entropy, "imports": axis_imports,
}


# --- scoring -----------------------------------------------------------------

def grade(exposure: float) -> str:
    return ("A" if exposure < 10 else "B" if exposure < 25 else
            "C" if exposure < 45 else "D" if exposure < 65 else "F")


READABILITY_WEIGHT = 20   # weight of the opt-in Ghidra decompiler axis
AGENT_WEIGHT = 25         # weight of the opt-in LLM summary-accuracy axis


def _tools_dir():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))


def _axis_readability(binary: str):
    """Opt-in deep axis: Ghidra decompiler readability."""
    _tools_dir()
    from ghidra_readability import readability, score  # type: ignore
    m = readability(binary)
    detail = {k: m[k] for k in ("functions", "decompiled_ok",
                                "junk_tokens", "flattened_funcs")}
    return AxisResult(score(m), detail)


def _axis_agent(binary: str, func: str, secret: str | None):
    """Opt-in axis: how well an LLM (local Ollama) explains `func`."""
    _tools_dir()
    from agent_summary import evaluate  # type: ignore
    sc, detail = evaluate(binary, func, secret)
    detail = {"summary": detail["summary"][:160], **{k: detail[k] for k in
              ("concepts_hit", "secret_recovered", "hedged")}}
    return AxisResult(sc, detail)


def scan(binary: str, deep: bool = False, agent_func: str = None,
         secret: str = None) -> dict:
    fmt = detect_format(binary)
    axes = {name: fn(binary) for name, fn in ANALYZERS.items()}
    weights = dict(WEIGHTS)
    notes = []
    if deep:
        try:
            axes["readability"] = _axis_readability(binary)
            weights["readability"] = READABILITY_WEIGHT
        except Exception as e:   # ghidra missing/failed: skip, don't skew
            notes.append(f"readability axis skipped ({type(e).__name__}: {e})")
    if agent_func:
        try:
            axes["agent"] = _axis_agent(binary, agent_func, secret)
            weights["agent"] = AGENT_WEIGHT
        except Exception as e:   # ollama/ghidra missing: skip, don't skew
            notes.append(f"agent axis skipped ({type(e).__name__}: {e})")
    note = "; ".join(notes) if notes else None
    exposure = sum(axes[n].score * weights[n] for n in weights) / sum(weights.values())
    report = {
        "binary": binary,
        "format": fmt,
        "exposure_score": round(exposure, 1),     # 0 best .. 100 worst
        "protection_grade": grade(exposure),
        "axes": {n: {"score": round(a.score, 1),
                     "weight": weights.get(n, 0), **a.detail}
                 for n, a in axes.items()},
    }
    if note:
        report["note"] = note
    elif fmt == "macho" and not get_sections(binary):
        report["note"] = ("Mach-O sections unreadable by this objdump; "
                          "install llvm-objdump for full entropy/metadata axes")
    elif fmt == "unknown":
        report["note"] = "unrecognized format; only strings axis is reliable"
    return report


# --- presentation ------------------------------------------------------------

def _bar(score: float, width: int = 24) -> str:
    fill = int(round(score / 100 * width))
    return "#" * fill + "." * (width - fill)


def render(report: dict) -> str:
    L = [f"\nTarget : {report['binary']}  [{report.get('format', '?')}]",
         f"Exposure: {report['exposure_score']}/100 "
         f"(0=hardened, 100=wide open)   Grade: {report['protection_grade']}",
         "-" * 60]
    if report.get("note"):
        L.append(f"  note: {report['note']}")
    for name, ax in report["axes"].items():
        L.append(f"  {name:9s} [{_bar(ax['score'])}] {ax['score']:5.1f}  (w{ax['weight']})")
    L.append("")
    sym = report["axes"]["symbols"]
    if sym.get("sample"):
        L.append(f"  recovered names : {', '.join(sym['sample'])}")
    strs = report["axes"]["strings"]
    if strs.get("landmarks"):
        L.append(f"  string landmarks: {', '.join(strs['landmarks'][:8])}")
    meta = report["axes"]["metadata"]
    if meta.get("flags"):
        L.append(f"  metadata leaks  : {', '.join(meta['flags'])}")
    return "\n".join(L)


def _optval(a, flag, default=None):
    """Value after `flag`, or `default` if absent; clean error if it has none."""
    if flag not in a:
        return default
    i = a.index(flag)
    if i + 1 >= len(a):
        print(f"error: {flag} needs a value", file=sys.stderr)
        raise SystemExit(2)
    return a[i + 1]


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__); return 2
    for tool in ("nm", "readelf", "objdump", "strings", "file"):
        if not shutil.which(tool):
            print(f"warning: '{tool}' not on PATH; some axes will under-report",
                  file=sys.stderr)
    binary = args[0]
    as_json = "--json" in args
    quiet = "--quiet" in args
    deep = "--deep" in args          # add the Ghidra decompiler-readability axis
    agent_func = _optval(args, "--agent")
    secret = _optval(args, "--secret")
    if "--compare" in args:
        other = _optval(args, "--compare")
        a = scan(binary, deep, agent_func, secret)
        b = scan(other, deep, agent_func, secret)
        if as_json:
            print(json.dumps({"a": a, "b": b,
                              "delta": round(a["exposure_score"] - b["exposure_score"], 1)}))
        else:
            print(render(a)); print(render(b))
            d = a["exposure_score"] - b["exposure_score"]
            print(f"\nDelta: {binary} is {d:+.1f} exposure vs {other} "
                  f"({'more exposed' if d > 0 else 'better protected'})\n")
        return 0
    report = scan(binary, deep, agent_func, secret)
    if as_json:
        print(json.dumps(report, indent=2))
    elif not quiet:
        print(render(report))
    else:
        print(f"{report['exposure_score']}  {report['protection_grade']}  {binary}")

    # CI gate: fail the build if exposure exceeds the allowed maximum.
    if "--gate" in args:
        try:
            limit = float(args[args.index("--gate") + 1])
        except (IndexError, ValueError):
            print("error: --gate needs a numeric max exposure", file=sys.stderr)
            return 2
        exposure = report["exposure_score"]
        ok = exposure <= limit
        print(f"{'PASS' if ok else 'FAIL'}: exposure {exposure} "
              f"{'<=' if ok else '>'} gate {limit}", file=sys.stderr)
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
