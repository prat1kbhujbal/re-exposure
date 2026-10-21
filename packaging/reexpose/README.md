# reexpose

**Score how exposed a binary is to AI-assisted reverse engineering.**

Reverse engineering is increasingly agent-driven (REA, GhidraMCP, ida-pro-mcp):
an LLM reads your binary and explains it from the symbols, strings, and metadata
the compiler left behind. `reexpose` reads a finished binary the way such an
analyst would and gives it a 0-100 exposure score, so you can see what is cheap
to recover and whether your hardening actually moved the needle.

It only measures. It never modifies a binary and never hides anything.

## Install

```bash
pipx install reexpose        # or: pip install reexpose
```

Needs `binutils` (`nm`, `readelf`, `objdump`, `strings`) on PATH for the static
axes. ELF is fully supported; PE and Mach-O are detected and scored where the
tools allow.

## Use

```bash
reexpose ./your-binary                 # scored report
reexpose ./your-binary --json          # machine-readable
reexpose ./your-binary --quiet         # one line: score grade path
reexpose a.out --compare b.out         # before/after delta
reexpose ./your-binary --gate 40       # CI: exit 1 if exposure > 40
```

Exposure runs 0 (hardened) to 100 (wide open), graded A to F, as a weighted sum
over five axes: recovered symbols, landmark strings, debug/toolchain metadata,
code entropy, and interesting imports.

## The deeper axes

Two optional axes measure what the static ones cannot:

- `--deep`: Ghidra decompiler readability.
- `--agent <func>`: ask a local LLM to explain a function and score how much it
  recovered. With the default Ghidra-pseudocode source this measures
  decompiler-output readability to a one-shot LLM; with raw disassembly it
  approximates an agentic attacker. The two differ on obfuscated code, and that
  gap is the useful signal, not the pseudocode number alone.

These, plus the hardening tools that reduce the score (metadata denial and
reference-correct string encryption), are part of the full re-exposure toolkit.

## License

MIT. The full re-exposure toolkit (the hardening transforms and the deep axes)
is licensed separately.
