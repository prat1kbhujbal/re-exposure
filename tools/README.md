# tools/reharden - post-build anchor denial (ELF + PE)

Module 1 (anchor denial) in its **no-rebuild** form. It takes a finished ELF or
PE and removes the metadata a reverse engineer / LLM agent anchors on - symbol
table, debug info, build-id, toolchain notes - so it drops into a release
pipeline *after* the compiler, with no source changes.

It removes **metadata only**. Every section it strips (`.symtab`/COFF symbols,
`.debug_*`, `.comment`, build-id / `.drectve`) is non-loadable - the loader
never maps it - so **behavior is preserved**. PE unwind (`.pdata`/`.xdata`),
relocations (`.reloc`) and imports are kept. `--run` executes the result (PE
under Wine) to confirm it still works. It never obfuscates logic or hides what
the program does.

Measured: ELF `baseline` 73.7 (F) → 35.8 (C); **PE `license.exe` 79.0 (F) →
47.9 (D)** (symbol table + DWARF debug gone), behavior preserved under Wine.
The PE residual is the Win32 import names + app strings - those need string
encryption (the blocked PE round-trip, see tools/pe/README.md), not metadata
stripping.

## Use

```bash
python3 tools/reharden.py <in.elf> [-o out] [--aggressive] [--run "<args>"]
make reharden          # demo: hardens the unprotected baseline, shows the drop
```

- `-o out` - output path (default `<in>.hardened`)
- `--aggressive` - also drop `.note.ABI-tag` / `.note.gnu.property`
- `--run "<args>"` - execute the result to confirm it still runs (fails on crash)

It auto-imports `reexpose` (from `../harness`) to print the before/after
exposure delta.

## Measured (on the unprotected baseline)

```
exposure: 73.7 (F)  ->  35.8 (C)   [-37.9]
    symbols    39.3 ->   0.0    # names gone
    metadata   85.0 ->   0.0    # debug/build-id/notes gone
    strings    97.0 ->  81.1    # only debug-derived strings gone
```

## The boundary (important for product positioning)

`reharden` is the **zero-integration quick win**. It cannot touch the residual
`strings` exposure: the plaintext key and messages live in `.rodata`, and the
loader *does* map that, so removing it without breaking the program needs
either:

- **source-level** secret encryption (see `src/license_hardened.c`), or
- **binary rewriting** that relocates/encrypts `.rodata` references (future).

So the product tiers fall out naturally:
1. `reharden` (free/open) - instant metadata denial, any ELF, no rebuild.
2. source-level anchor denial - bigger drop, needs build integration.
3. obfuscation / packing (modules 2 - 6) - attacks the code itself.

## Not yet

- PE (`/PDBSTRIPPED`, link `/DEBUG:NONE`) and Mach-O (`strip -S/-x`) equivalents.
- `.rodata` string relocation/encryption via binary rewriting.

---

# tools/encrypt_strings - M1 .rodata string encryption (ELF, non-PIE)

Encrypts selected `.rodata` string literals on disk and injects an entry-point
stub that decrypts them in memory before the original entry runs. This reaches
the exposure `reharden` cannot: the in-code plaintext that the loader maps.

## Use

```bash
python3 tools/encrypt_strings.py <in.elf> -o <out> \
    [--all] [--min-len 4] [--key 0x5a] [--verify "<args>"]...
make harden-full      # demo: strip + encrypt the non-PIE target, measured
```

- `--all` encrypt every string run (default: only risk-lexicon hits)
- `--verify A` run original vs output with args A and diff stdout+exit;
  repeatable; **any divergence fails the harden** (behavior-preservation gate)

## How it works

1. Select NUL-terminated string runs in `.rodata` (allows embedded `\t\n\r`).
2. XOR-encrypt the chosen bytes in place.
3. Assemble a position-independent stub: `mprotect` the `.rodata` pages RW,
   XOR-decrypt the exact ranges, `mprotect` back to R, then jump to the saved
   original entry. Inject it as a new R+X segment; repoint the ELF entry at it.

Behavior is preserved because the identical original bytes are restored before
any application code runs. The `--verify` gate proves it per build.

## Measured (full pipeline on the non-PIE demo)

```
original   66.8 (F)
strip      36.1 (C)   # reharden: symbols/debug/notes gone
+ strings  11.8 (B)   # encrypt_strings: .rodata landmarks gone; strings axis 0.0
```

## As built (M1 + M2)

- **PIE and non-PIE** (x86-64). The stub is base-relative: it derives the
  runtime load base `B` from a RIP-relative `lea` and addresses everything as
  `B + image_vaddr`; non-PIE is the `B=0` case, so one stub serves both. For
  PIE, adding a segment makes LIEF relayout the image, so the stub is built from
  the post-add (shifted) vaddrs and the LIEF-corrected entry.
- **Entry-point hijack**, not an `.init_array` entry - avoids editing dynamic
  tags / relocations.
- **Rolling keystream key** - byte `i` uses `(seed + i*step) & 0xff`
  (`--key`/`--step`); upgradeable to a block cipher.
- **Scans `.rodata`, `.rodata.str1.*`, `.data.rel.ro`.** Each touched section's
  pages are flipped writable around decryption, then restored read-only.
- **Verified on a real binary:** `/usr/bin/true` (PIE, 44 `.rodata` strings)
  survives `--all` with behavior intact (`--version` still prints correctly).
- **Decryptor + key are visible** in the injected segment: this defeats static
  `strings`/anchor search, not an analyst who finds the stub or a memory dump.
  Combine with control-flow obfuscation on the stub (modules 2 - 6) to raise that.

## Still open (M3+)

- Rolling key is a linear keystream, not a block cipher (adequate to zero the
  strings axis; not cryptographically strong).
- M3: reference-correct rewriting (GTIRB/egalito) for per-use decryption so
  plaintext need not sit in memory for the whole process lifetime.
- M4: PE (`.rdata`) and Mach-O (`__cstring`).

## Dependency

- **LIEF** (`pip install lief`) for segment injection + entry repoint.

---

# tools/agent_summary - LLM summary-accuracy axis (licensed-product core)

Measures resistance to AI/agent RE directly: decompile a function (Ghidra),
ask an LLM to explain it, score whether it recovered the mechanism + secret.

- **Local model via Ollama** (`REEXPOSE_MODEL`, default `qwen2.5-coder:1.5b`,
  `OLLAMA_URL` default `http://localhost:11434`) - the analyzed code never
  leaves the machine, which is the right default for a tool customers run on
  their own binaries.
- Scoring: mechanism-concept overlap (0.5) + literal `--secret` recovery (0.5),
  times 0.3 if the model genuinely hedges. The function *name* is deliberately
  not a concept, so clean vs obfuscated separate on recovered logic, not naming.

```bash
python3 tools/agent_summary.py <bin> --func <name> --secret "<literal>" [--json]
make agent-demo        # clean vs flattened check_license
```

Validated (qwen2.5-coder:1.5b):

```
clean       66.7   model: "...matches the constant string ACME-PRO-2026-XK7Q..."
flattened    0.0   model: "...calls a function pointed to by a switch..." (no logic)
```

A bigger local model raises fidelity; the axis is model-agnostic.

---

# tools/m3_rewrite - reference-correct rewriting via GTIRB (M3 foundation)

Round-trips a binary through GrammaTech GTIRB, reference-correctly:

```
ddisasm (Docker grammatech/ddisasm)  bin   -> GTIRB
[transform()  -- extension point]    GTIRB -> GTIRB
gtirb-pprinter (Docker)              GTIRB -> assembly
host clang                           asm   -> binary   (host glibc)
```

Lift/print run in the container; the final link runs on the **host** because
the image's glibc is older (in-container reassembly fails on versioned libc
symbols). Validated: `demo_nopie` round-trips behavior-identical.

```bash
python3 tools/m3_rewrite.py <bin> -o <out> --verify "<args>"...                 # round-trip
python3 tools/m3_rewrite.py <bin> -o <out> --encrypt-strings --verify "<args>"  # per-use encrypt
make m3-roundtrip        # round-trip only
make m3-encrypt          # per-use string encryption on the demo
```

## String encryption (`--encrypt-strings`)

Transforms run on the **assembly** gtirb-pprinter emits, where every reference
is a symbolic label - so inserting/replacing instructions and moving data is
reference-correct for free (assembler + linker recompute all offsets). Two
reference classes are handled:

- **Per-use** (strongest): a string referenced only by `leaq (L)(%rip),%reg`.
  Encrypt the bytes; rewrite each reference into a guarded call to an injected
  `rea_decrypt` that decrypts into a **per-site buffer**. Plaintext is only
  transiently resident - the improvement over M1/M2, which decrypt the whole
  `.rodata` block at load and leave it plaintext for the process lifetime.
- **Load-time**: a string reached via a `.quad L` pointer table, or a clang
  `-O2` relative-lookup pool (a `.byte` object of 32-bit offsets + a string
  blob), where there's no code `leaq` to rewrite. Move the (string-region-)
  encrypted bytes to a **writable** section (symbolic refs follow) and decrypt
  in place via an injected `.init_array` constructor - no `mprotect`. For
  offset-table pools the offset entries stay plaintext; only `[T:]` is encrypted.
  Plaintext is resident, but gone from disk.

A string is only touched if it starts at a **NUL boundary** - nothing reads
*into* it from an earlier label (handles merged `.ascii`-continuation strings
like coreutils' "GNU "+"coreutils", which stay plaintext). The host link adds
the input's `DT_NEEDED` libraries so real binaries with extra deps (e.g.
`libselinux`) relink.

The host link **matches the input's PIE-ness** (`-pie` for `ET_DYN`, `-no-pie`
for `ET_EXEC`), so a PIE input stays PIE (ASLR preserved).

Validated:
- `demo_nopie` 4 per-use; PIE `baseline` 4 per-use (output stays PIE);
  `/usr/bin/true` 48 per-use; `.quad` table (`-O0`) 3 load-time; clang `-O2`
  offset-table pool 1 load-time - all behavior-identical.
- Real `/bin/ls`: **130 per-use + 83 load-time = 213 objects**, `--version` and
  a real directory listing behavior-identical, output stays PIE.

**Fails closed.** The `--verify` gate refuses any rewrite that changes behavior
(byte-level stdout+exit), so an unhandled pattern degrades to a safe refusal,
never a corrupt binary.

Limits: merged `.ascii`-continuation strings are skipped (stay plaintext); XOR
ciphertext adds incidental printable noise to `strings` (not meaningful
landmarks); the per-site/offset-table scans assume single-value `.byte` lines.

Requires: `docker` + `grammatech/ddisasm` image; `pip install gtirb`.
