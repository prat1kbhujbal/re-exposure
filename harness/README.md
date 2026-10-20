# reexpose - AI-RE exposure scanner

The measurement harness: the open-core, zero-misuse heart of the anti-AI-RE
project. It scores how cheaply a reverse engineer - especially an **LLM/agent**
analyzer like REA or GhidraMCP - can understand and clone a binary.

It only **measures**. It never modifies a binary and never hides behavior. It is
the inverse of an RE agent: an agent extracts understanding and reports
evidence; `reexpose` reports how much understanding is lying around for free.

## Use

```bash
python3 reexpose.py <binary>                 # scored report
python3 reexpose.py <binary> --json          # machine-readable
python3 reexpose.py <binary> --quiet         # one line: score grade path
python3 reexpose.py <a> --compare <b>        # before/after delta
python3 reexpose.py <binary> --gate 40       # CI: exit 1 if exposure > 40
python3 reexpose.py <binary> --deep          # + Ghidra decompiler-readability axis
python3 reexpose.py <binary> --agent <func> --secret <lit>   # + LLM axis
make scan                                    # score all lab variants
```

The `--deep` and `--agent` axes are opt-in (slow; need Ghidra / a local Ollama
model) and skip cleanly with a `note` if their tooling is absent, so the fast
static scan always works. Note on the agent axis: with the default Ghidra-
pseudocode source it measures decompiler-output readability to a one-shot LLM,
not resistance to an agent reading disassembly. A flattened function scores 0
there only because Ghidra failed to structure it; from raw asm a 32b model
recovers the mechanism (see the main README, section 3.4). Treat the gap between
pseudocode and `--disasm` as the real signal, not the pseudocode number alone.

Exposure is `0` (hardened) .. `100` (wide open); grade A - F.

### Formats

ELF is fully supported. PE and Mach-O are detected by magic bytes and scored
through the cross-format path (`objdump -h` sections, `strings`, imports);
where a tool can't read a format (this binutils has no Mach-O target), the
affected axes degrade gracefully and the report carries a `note`. Install
`llvm-objdump` for full Mach-O section/entropy/metadata coverage.

### CI gate

`--gate <max>` makes the scanner a release guard: it prints `PASS`/`FAIL` to
stderr and exits non-zero when exposure exceeds the limit, so a regression in
protection fails the pipeline. Example:

```yaml
# fail the build if the shipped binary is too exposed
- run: python3 harness/reexpose.py dist/app --gate 35
```

## What it measures (and why an agent cares)

| Axis | Weight | Signal an LLM agent anchors on |
| --- | --- | --- |
| `symbols` | 30 | Named functions/vars = free navigation + naming for the agent's summary |
| `strings` | 30 | Landmark strings (license/key/error/URLs/source paths) = grep + xref pivots |
| `metadata` | 25 | debug_info, symtab, build paths, Go/Rust provenance = the agent reads it verbatim |
| `entropy` | 10 | Low `.text` entropy = plaintext code on disk; high = packed/virtualized |
| `imports` | 5 | `strcmp`/`socket`/`ptrace`… = behavior pivots the agent reasons from |

Weights are a starting point. Calibrate them against real agent accuracy as you
collect data (see roadmap).

## Measured on the lab (proves the score tracks real hardening)

```
73.7  F  baseline            (unprotected)
60.0  D  hardened            (strings encrypted, symbols still present)
38.4  C  baseline.strip      (symbols stripped only)
29.7  C  hardened.strip      (strip + encrypted strings = layers 1+2)
```

Residual 29.7 is mostly the `entropy` axis - the code is still plaintext on
disk. That is exactly what layer 3 (control-flow obfuscation) and layer 6
(packing/virtualization) attack, and the scanner will register them when applied.

## Architecture: pluggable analyzer backends

The static axes need only binutils (`nm`, `readelf`, `objdump`, `strings`).
Heavier axes plug in behind the same `fn(binary) -> AxisResult` interface:

- **`readability` (`--deep`, DONE)** - runs Ghidra `analyzeHeadless` with
  `tools/ghidra/readability.py`, decompiles every function, and scores
  *decompiler readability*: decompile success rate, control-flow structure
  density, decompiler "junk" tokens (`undefined`/`unaff_`/`extraout_`), and a
  control-flow-flattening signature. Clean structured code scores HIGH (exposed);
  junky/flattened/undecompilable code scores LOW. This is the axis the static
  ones can't provide and the one control-flow obfuscation attacks. Weight 20,
  renormalized in; skipped cleanly (with a `note`) if Ghidra is absent.
- **`agent` axis (DONE - `reexpose --agent <func>`, or `tools/agent_summary.py`)**
 - the real differentiator. Decompiles the target function, asks an LLM to explain it, and
  scores whether it recovered the mechanism + the literal secret. Clean code →
  accurate summary → HIGH exposure; obfuscated → model recovers nothing → LOW.
  Runs a **local** model via Ollama, so the analyzed code never leaves the
  machine (a product selling point). On a 32b model, clean `check_license`
  scores 75 (the model quotes the key); flattened scores 0 from Ghidra
  pseudocode but 25 from raw disassembly (`--disasm`), because the stub Ghidra
  produced hides what the asm still shows. `make agent-demo`.

### Ghidra setup for `--deep`

Needs Ghidra on `GHIDRA_HOME` or at `~/ghidra_*_PUBLIC`. This repo was validated
with **Ghidra 10.1.5** (the last release that runs on JDK 11; newer Ghidra needs
JDK 17/21). `--deep` is slow (imports + auto-analyzes + decompiles), so keep it
out of fast/CI scans and use it when measuring an obfuscation change.

### Validation (axis responds to obfuscation)

`make readability-demo` scores the same `check_license` clean vs manually
control-flow-flattened (`src/license_flattened.c`), behavior identical:

```
clean       readability-exposure 100.0   (decompiles cleanly, no junk)
flattened   readability-exposure   0.0   (decompiler junk tokens dominate)
```

Scoring note: control-flow keyword density is deliberately NOT rewarded -
obfuscation inflates it (dispatch switches, bogus branches). The score rewards
clean, successful decompilation and penalizes the obfuscation signatures
(decompiler junk tokens, flattening, dispatch/case density). The flattened
sample stands in for a Tigress/ollvm `--flatten` pass, which is license- or
build-gated; the axis itself is engine-agnostic.

## Roadmap

- [x] **PE + Mach-O** detection + cross-format scoring (ELF full; Mach-O needs
      `llvm-objdump` for the section-based axes).
- [x] **`--gate <max>`** exit-nonzero CI mode so releases fail if exposure regresses.
- [x] **Ghidra headless backend** (`--deep` decompiler-readability axis).
- [x] **Agent backend** (`--agent` summary-accuracy axis, pseudocode + `--disasm`).
- [x] **Model the agentic attack** (`agent_summary --agentic`: disasm + the
      binary's strings in one pass; `tools/benchmark.py` for the tiered table).
      Result: it recovers the plaintext secret on clean and flattened builds
      alike, so flattening does not help; string encryption is what denies it.
- [x] **Iterated/tool-using agent** (`tools/agent_attack.py`): an LLM with
      `strings`/`disasm`/`run` tools recovers the key and reports the step count.
      Under it, XOR string encryption only delays recovery (plaintext step 1 ->
      encrypted step 3, read off the compare via the LD_PRELOAD spy); a build
      that stores `SHA-256(key)` instead of the key is not cracked at all.
- [ ] **Calibration harness**: correlate axis scores with real agent accuracy to
      set weights empirically instead of by hand.
- [ ] Real PE/Mach-O test fixtures (needs a cross-compiler; none on the dev box).

## Scope / ethics

This scanner is safe to open-source as-is: it reveals exposure, it does not
conceal anything. Keep it that way - it is the trust-building, lead-generating
front door for the commercial transforms, and its credibility depends on it
being a pure measurement tool.
