# Spec: `.rodata` string rewriting (post-build string encryption, no source)

Status: **M1 + M2 shipped** (`tools/encrypt_strings.py`). **M3 per-use string
encryption implemented and validated, incl. a real binary**
(`tools/m3_rewrite.py --encrypt-strings`). M4 open. Target: x86-64 ELF.

**M3 as built:** transforms run on the *assembly* gtirb-pprinter emits (symbolic
references → reference-correct for free). `--encrypt-strings` encrypts each
`.rodata` string that (a) starts at a NUL boundary - nothing reads into it from
an earlier label (handles merged `.ascii`-continuation strings like coreutils'
"GNU "+"coreutils") - and (b) is referenced in a handled way. **Per-use**:
references all `leaq (L)(%rip),%reg` → rewrite each to a guarded call into an
injected `rea_decrypt` into a per-site buffer (plaintext transient). **Load-time**:
reached via a `.quad L` pointer table → move the encrypted bytes to a writable
section (symbolic refs follow) and decrypt in place via an injected `.init_array`
constructor, no mprotect (plaintext resident, gone from disk). The host link
adds the input's DT_NEEDED libraries. Validated: `demo_nopie` + PIE `baseline`
(4 per-use), `/usr/bin/true` (48 per-use), a `.quad` table (3 load-time), and
**real `/bin/ls` (130 per-use + 83 load-time = 213 strings), `--version` + a
directory listing behavior-identical**. Also handled: clang `-O2` relative-
lookup **offset-table pools** (a `.byte` object of 32-bit offsets + string blob;
offsets stay plaintext, `[T:]` encrypted, load-time), and the host link now
**matches the input's PIE-ness** (`-pie`/`-no-pie`), so a PIE input stays PIE.
The `--verify` gate fails closed (byte-level), so any unhandled pattern degrades
to a safe refusal.
Remaining: merged `.ascii`-continuation strings are skipped; the `.byte` scans
assume single-value-per-line. M4 (PE/Mach-O) needs cross-compilers (none on this
host).

**M3 toolchain:** `gtirb` Python lib via pip; `ddisasm`
and `gtirb-pprinter` via the **`grammatech/ddisasm` Docker image** (ddisasm
1.9.5). The image's glibc is older than the host's, so in-container reassembly
fails on versioned libc symbols; the working pipeline is **lift + emit assembly
in the container, then link on the host** (host glibc). `tools/m3_rewrite.py`
implements this and is validated: `demo_nopie` round-trips to a
behaviorally-identical binary (all `--verify` cases OK). GTIRB loads in the
Python lib (sections/byte-intervals readable), so references are available for
the transform.

**Remaining M3 work:** `transform()` in `tools/m3_rewrite.py` is currently
identity. The next increment encrypts `.rodata` string bytes in the GTIRB and
injects a per-use decryptor; because GTIRB keeps references symbolic, this is
the reference-correct path that lets plaintext *not* be resident for the whole
process lifetime (the M1/M2 limitation).

**M2 (done):** PIE **and** non-PIE via a base-relative stub (computes load base
B from a RIP-relative `lea`; non-PIE is the B=0 case, so one path serves both).
Rolling keystream key (`seed + i*step`). Scans `.rodata`, `.rodata.str1.*`,
`.data.rel.ro`. The PIE path handles LIEF's relayout by building the stub from
post-add vaddrs. Verified: PIE full pipeline 35.8 C -> 11.5 B behavior-identical;
**real `/usr/bin/true` (PIE, 44 strings) survives `--all` with behavior intact.**

**M1 (done):** non-PIE, entry-point hijack, `.rodata` only, single-byte key.
Deviations from the original draft (non-PIE first, entry-point hijack over
`.init_array`) are retained in M2.

## Problem

`tools/reharden.py` removes metadata anchors but cannot touch the residual
`strings` exposure: literals live in `.rodata`, the loader maps that segment,
and the program reads the bytes as plaintext at runtime. On the lab baseline
this leaves the `strings` axis at ~81 even after a full metadata strip.

Goal: given a **finished ELF** (no source), make the chosen string literals
disappear from `strings` and xref search while **preserving behavior** - i.e.
binary-level equivalent of the source-level encryption in
`src/license_hardened.c`.

Non-goal: defeating a runtime memory dump. Like the source-level layer, this
targets static triage (`strings`, landmark/xref search, LLM anchoring), not
dynamic analysis. State this limit in output and docs.

## Why this is hard (the constraint that drives the design)

Strings are referenced by **address**, mostly RIP-relative `lea` on x86-64.
Two ways to make code see plaintext while disk shows ciphertext:

1. **Decrypt in place before use** - no reference changes needed, but the
   plaintext then exists in memory. (Easy, weaker.)
2. **Decrypt a private copy per use** - references must be redirected to a
   decryptor thunk. Requires rewriting instructions, which changes their
   length, which shifts everything, which requires full relocation. (Hard,
   stronger.)

The reference-redir/(2) problem is the entire difficulty of binary rewriting.
So the plan is phased: ship (1) first, reach (2) via a rewriting framework
later, and never hand-patch references.

## Approach A - MVP: load-time bulk decryption (chosen for M1)

Encrypt target strings on disk; inject an ELF constructor that decrypts them in
memory before `main`.

### Rewrite-time steps
1. **Select strings.** Parse `.rodata` and `.rodata.str1.*`. Collect
   NUL-terminated printable runs as `(section, offset, length)`. Filter by the
   reexpose risk lexicon by default (`--filter risk`), or `--all`. Record an
   exact manifest; we will restore precisely these bytes, so non-string
   constants (jump tables, FP constants, vtables) are never mis-handled.
2. **Encrypt in place.** XOR with a rolling key (upgradeable to a block cipher).
   Key generated per-build, embedded in the stub, never in a named symbol.
3. **Inject a decryptor constructor** via **LIEF**: add a code blob + a new
   `PT_LOAD` segment, and prepend an `.init_array` entry so it runs first.

### Runtime stub (position-independent)
- Resolve `.rodata` runtime base: section vaddr + load bias (PIE). Derive bias
  from the stub's own relocated address or `getauxval(AT_PHDR)`.
- `mprotect` the covered pages `PROT_READ|PROT_WRITE` (RELRO may have set them
  RO; we own the process, so this succeeds).
- XOR-decrypt exactly the manifest ranges back to the original bytes.
- `mprotect` back to `PROT_READ` (`--keep-rodata-ro`, default on). **Never RWX**
 - that trips AV heuristics.

### Why behavior is preserved
We restore the identical original bytes before any application code runs, so
every consumer (including non-string `.rodata` data we happened to encrypt)
sees exactly what it saw before. The only correctness requirement is accurate
range selection + faithful restore.

### Known MVP weaknesses (must be documented in output)
- Plaintext lives in memory for the whole process lifetime → a dump / core /
  `/proc/<pid>/mem` recovers it. Static-triage defense only.
- An analyst who finds the constructor + key undoes it. Hiding the stub is a
  later concern (combine with control-flow obfuscation on the stub).
- **Constructor-ordering edge:** another `.init_array` entry that uses an
  encrypted string *before* ours would see ciphertext. We insert at highest
  priority; still, flag any pre-existing constructors and fail loudly if the
  binary has them until M2 handles it.
- Risk on exotic layouts: heavy RELRO, non-PIE, `.rodata` merged oddly,
  packed inputs. Scope M1 to PIE x86-64 with a normal layout; refuse others
  with a clear message.

## Approach C - production: reference-correct rewriting (M3)

Use a rewriting framework that tracks references, so moving/encrypting data is
reflected everywhere automatically, enabling per-use decryption (Approach 2
semantics) and robustness on real binaries:

- **GTIRB + ddisasm** (GrammaTech): Datalog disassembly to a reference-accurate
  IR, rewrite, reassemble. Strong on reference recovery.
- **egalito**: binary recompilation with a complete layout graph.

Hand-rolled instruction patching (Approach 2 without a framework) is explicitly
**out of scope** - it is a relocation engine in disguise and not worth owning.

## Interface

Extend `reharden.py` with a stage that runs after the metadata strip:

```bash
reharden.py <in.elf> --encrypt-strings \
    [--filter risk|all] [--min-len 4] [--key <hex>] \
    [--keep-rodata-ro] [--verify "<run-args>"] -o <out>
```

- Reuses the existing before/after `reexpose` delta.
- `--verify` runs original vs hardened on sample args and **diffs stdout/exit**;
  any divergence fails the harden (behavior-preservation gate).

## Testing

- **Lab targets** (`build/baseline`): strings axis must drop sharply; behavior
  diff must be clean.
- **Real small ELFs**: a handful of distro binaries, PIE, run with safe args,
  output-diffed. Track a pass/break list.
- **Selector fuzzing**: odd `.rodata` (overlapping runs, no NUL, UTF-8,
  single-byte) must never corrupt non-string data (checked by full restore +
  behavior diff).
- **Negative tests**: non-PIE, pre-existing constructors, packed input → must
  refuse, not silently produce a broken binary.

## Milestones

- **M1** (this spec): Approach A on PIE x86-64, risk filter, LIEF-injected
  constructor, `--verify` gate, reexpose delta. Refuse unsupported inputs.
- **M2**: RELRO/mprotect-back hardening, constructor-priority + pre-existing
  constructor handling, non-PIE, `--all`, more real binaries.
- **M3**: GTIRB/egalito path for per-use decryption (strong mode) + robustness.
- **M4**: PE (`.rdata`, TLS-callback or CRT init) and Mach-O (`__cstring`,
  `__mod_init_func`).

## Dependencies

- **LIEF** (Python) - ELF segment/section injection + `.init_array` editing.
  Not currently installed; add to project deps for M1.
- Later: GTIRB + ddisasm, or egalito (M3); a small PIC stub toolchain.

## Ethics / positioning

This encrypts the product's *own* strings to protect IP and raise analysis
cost - the same legitimate purpose as the source-level layer. It is also a
known malware technique for hiding strings from scanners, so: keep the framing
to IP/anti-cloning, never market it as AV/defender evasion, avoid RWX memory
(AV heuristics), and keep the measurement tool (`reexpose`) honest and separate.
