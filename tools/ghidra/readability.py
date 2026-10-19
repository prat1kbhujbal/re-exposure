# Ghidra headless post-script (Jython / Python 2.7).
# Decompiles every non-library function and writes readability metrics as JSON.
# These measure how easily a human + decompiler (and an LLM reading the
# pseudocode) can understand the code -- the signal the static axes miss and
# that control-flow obfuscation attacks.
#
# Invoked by tools/ghidra_readability.py via:
#   analyzeHeadless <proj> tmp -import <bin> -scriptPath tools/ghidra \
#       -postScript readability.py <out.json> -deleteProject
import re
import json

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

CTRL = re.compile(r"\b(if|for|while|switch|case|goto)\b")
TERN = re.compile(r"\?")
# decompiler "I couldn't recover this cleanly" tokens
JUNK = re.compile(r"\b(undefined\d*|unaff_\w+|extraout_\w+|in_[A-Z]\w+|"
                  r"halt_baddata|code_r0x\w+)\b|WARNING")


CASE = re.compile(r"\bcase\b")


def main():
    args = getScriptArgs()
    out = args[0] if args else "readability.json"
    only = args[1] if len(args) > 1 else None   # optional: one function name

    di = DecompInterface()
    di.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()
    fm = currentProgram.getFunctionManager()

    n = ok = lines = ctrl = cases = junk = flat = 0
    for f in fm.getFunctions(True):
        if f.isThunk() or f.isExternal():
            continue
        if only is not None and f.getName() != only:
            continue
        n += 1
        res = di.decompileFunction(f, 60, monitor)
        if res is None or not res.decompileCompleted():
            continue
        dec = res.getDecompiledFunction()
        if dec is None:
            continue
        code = dec.getC()
        ok += 1
        nonblank = [ln for ln in code.splitlines() if ln.strip()]
        lines += len(nonblank)
        ctrl += len(CTRL.findall(code)) + len(TERN.findall(code))
        cases += len(CASE.findall(code))
        junk += len(JUNK.findall(code))
        # control-flow-flattening signature: a dispatch loop over a state switch
        if "while( true )" in code and code.count("case ") >= 5 \
                and "switch" in code:
            flat += 1

    with open(out, "w") as fh:
        json.dump({
            "functions": n,
            "decompiled_ok": ok,
            "nonblank_lines": lines,
            "ctrl_keywords": ctrl,
            "case_labels": cases,
            "junk_tokens": junk,
            "flattened_funcs": flat,
        }, fh)


main()
