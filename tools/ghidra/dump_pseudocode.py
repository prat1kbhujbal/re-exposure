# Ghidra headless post-script (Jython): dump the decompiled C of one function
# (or all non-library functions) to a file, for the agent summary-accuracy axis.
#   analyzeHeadless <proj> t -import <bin> -scriptPath tools/ghidra \
#       -postScript dump_pseudocode.py <out.c> [funcname]
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def main():
    args = getScriptArgs()
    out = args[0] if args else "pseudocode.c"
    only = args[1] if len(args) > 1 else None

    di = DecompInterface()
    di.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()
    fm = currentProgram.getFunctionManager()

    chunks = []
    for f in fm.getFunctions(True):
        if f.isThunk() or f.isExternal():
            continue
        if only is not None and f.getName() != only:
            continue
        res = di.decompileFunction(f, 60, monitor)
        if res is not None and res.decompileCompleted():
            dec = res.getDecompiledFunction()
            if dec is not None:
                chunks.append(dec.getC())

    with open(out, "w") as fh:
        fh.write("\n\n".join(chunks))


main()
