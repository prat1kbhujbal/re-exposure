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

# tools/agent_summary - LLM summary-accuracy axis

Asks an LLM to explain a function and scores whether it recovered the mechanism
and secret. The `source` matters and the tool defaults are easy to misread, so
there are three, in order of attacker strength:

- `pseudocode` (default, Ghidra output) measures decompiler-output readability
  to a one-shot LLM.
- `--disasm` (raw objdump) models an attacker who reads asm directly.
- `--agentic` (disasm + the binary's strings) models what an agent gathers in
  its first few tool calls, so it recovers a plaintext `.rodata` secret even
  when control flow is flattened. It is the honest upper bound on a one-pass
  agentic read; it cannot see a secret that is encrypted on disk.

Obfuscation that breaks the decompiler scores low under `pseudocode` but is
recovered under `--disasm`/`--agentic`, so report the progression, not the
pseudocode number alone.

- **Local model via Ollama** (`REEXPOSE_MODEL`, default `qwen2.5-coder:1.5b`,
  `OLLAMA_URL` default `http://localhost:11434`) - the analyzed code never
  leaves the machine, which is the right default for a tool customers run on
  their own binaries.
- Scoring: mechanism-concept overlap (0.5) + literal `--secret` recovery (0.5),
  times 0.3 if the model genuinely hedges. The function *name* is deliberately
  not a concept, so clean vs obfuscated separate on recovered logic, not naming.

```bash
python3 tools/agent_summary.py <bin> --func <name> --secret "<literal>" [--disasm|--agentic] [--json]
make agent-demo        # clean vs flattened check_license
make benchmark         # the full tiered table below (slow; needs a strong model)
```

Measured on a 32b model (`qwen2.5-coder:32b`), same `check_license`, clean vs
control-flow-flattened (behavior identical). `*` = the model quoted the literal
secret:

```
                 clean    flattened
pseudocode        75.0      0.0      (flattened: Ghidra gave the model a stub)
--disasm          41.7     25.0      (model reconstructs the compare from asm)
--agentic         91.7*    75.0*     (disasm + strings; recovers the secret)
```

Read the flattened column top to bottom: 0 -> 25 -> 75 as the attacker gets
stronger. The flattened 0 under `pseudocode` reflects the decompiler failing,
not the binary being protected. From raw asm the model recovers the mechanism;
given the strings too, it recovers the plaintext secret outright, on the
flattened build as readily as the clean one. So control-flow flattening does not
stop an agent, and the thing that would (removing the plaintext secret from
`.rodata`) is string encryption, not obfuscation. A bigger model raises clean-
code fidelity; it does not change that conclusion.

---

# tools/agent_attack - iterating tool-using agent (honest cost curve)

Where `agent_summary` is a one-shot read, this is a real agent loop: an LLM is
given a goal (recover the license key the program checks against) and a small
toolset, and it picks one action per turn until it recovers the key or gives up.
The output is a *cost to recover* (how many steps, which tool cracked it), not a
static score.

Tools the agent can call: `strings` (static), `disasm <func>` (static),
`run <probe>` (dynamic: executes the target under `cmpspy.c`, an LD_PRELOAD shim
that logs every string-comparison's operands), and `answer <key>`. The `run`
tool is the debugger step the common objection points at: a key XOR-encrypted on
disk is still read straight off the `strcmp` once the program decrypts it in
memory.

The driver is a LOCAL Ollama model (`REEXPOSE_MODEL`), so the measured attacker
is a floor, not a ceiling. We record the first step at which the real key became
visible in a tool result (what any agent reads off), separately from whether
this particular model then typed it back.

```bash
python3 tools/agent_attack.py <bin> --secret "<key>" [--max-steps 6] [--json]
make attack-demo        # the three builds below, each run under the agent loop
```

Measured on a 32b model, same program built three ways (behavior identical):

```
build               protection                    cracked?  key readable at
clean_o0            none (plaintext in .rodata)    yes       step 1  (strings)
enc_o0              XOR string encryption          yes       step 3  (run: spy)
verifier_o0         key not in client (SHA-256)    no        never
locked_o0           key-as-lock (AES-256-GCM)      no        never
```

The point: string encryption moved recovery from step 1 to step 3, it did not
prevent it; the agent saw `strings` fail, ran the binary under the compare-spy,
and read the decrypted key off the `strcmp`. The two builds it could not crack
both keep the secret off the client: `verifier_o0` ships `SHA-256(key)` instead
of the key (`src/license_verifier.c`), and `locked_o0` ships the asset as
AES-256-GCM ciphertext that only the key decrypts (`src/license_locked.c`, see
below). The honest lesson is that static obfuscation raises the step count by
one or two, and the thing that actually holds is not shipping the secret.

`cmpspy.c` is built to `build/cmpspy.so` (the harness compiles it on demand).

---

# tools/seal + src/license_locked - key-as-lock (the protection that holds)

The cost curve above shows obfuscation only delays an agent. This is the model
that does not: the license key is a **lock, not a gate**. Instead of
`if (valid) unlock()` (one branch to patch, and the compared key is in memory),
the protected asset ships as ciphertext and the key is what decrypts it. There
is no success branch to bypass, and no plaintext and no key in the client to
read.

- `tools/seal.c` (build time): takes the asset and the developer's license key,
  derives an AES key with PBKDF2-HMAC-SHA256, encrypts with AES-256-GCM (real
  OpenSSL, not a hand-rolled cipher), and emits `build/locked.h` with the salt,
  IV, tag and ciphertext. The license key is a build input; it is NOT in the
  header or the binary.
- `src/license_locked.c` (runtime): re-derives the key from the key the *user*
  supplies and AES-256-GCM-decrypts the asset. A wrong key fails the GCM auth
  tag, so no plaintext is ever produced.

```bash
make locked-demo     # right key prints the asset; wrong key gets nothing
python3 tools/agent_attack.py build/locked_o0 --secret "UNLOCK-OK-7f3a9c21"
```

Measured: under `agent_attack` the 32b never recovers the asset (the marker
never appears via `strings`, `disasm`, or `run`); only ciphertext is in the
file, so the agent falls back to guessing keys and gets nothing.

**Honest boundary.** This stops an attacker *without* a valid key (the agent, an
unlicensed user). A user *with* a valid key decrypts the asset into their own
memory and can dump it from there; defeating extraction by an authorized user
needs server-side execution or per-user keys (the online layer that derives or
fetches the key instead of taking it from argv). Brute force is bounded by key
entropy; PBKDF2 raises the per-guess cost but a guessable key is still guessable.
Dependency: OpenSSL (`-lcrypto`).

---

# server/license_server.py + src/license_online.c - server-issued key

The strongest tier the repo builds. `license_locked` keeps the key out of the
binary but a copy still reaches the client (the user types it). This goes
further: **the client holds no key at all.** It authenticates to a license
server with an opaque token, the server validates it and returns the key, and
only then is the asset decrypted. The key lives on the server; the client ships
a token plus ciphertext.

- `server/license_server.py`: holds the key, serves `POST /key` for a valid,
  non-revoked token, and logs every issue/deny. Config in `server/licenses.json`
  (re-read per request, so revocation is immediate).
- `src/license_online.c`: opens a socket to the server, presents its token, and
  decrypts the asset with the returned key. Server down or token declined means
  no key and no asset. `REN_TOKEN` / `REN_PORT` override the demo defaults.

```bash
make online-demo     # starts the server, runs valid/revoked/down clients, stops it
```

What this gives that offline protection cannot, shown by the demo:

```
valid token + server up     -> asset unlocks   (server logs the issue)
revoked token               -> declined        (binary unchanged; server said no)
server down                 -> declined        (no offline key to fall back on)
client binary, statically   -> token + ciphertext only; the key is never in it
```

Under `agent_attack` with the server unreachable (a stolen binary), the asset is
not recovered: there is no key in the file and none to fetch.

**Honest boundary (unchanged and important).** While the server is up and the
token is valid, running the client decrypts the asset into its own memory, so an
authorized attacker can still dump it, and an extracted token works until it is
revoked or bound. The wins are real but bounded: no offline cracking, immediate
revocation, per-use visibility, and no key at rest in the client. The only tier
that removes the authorized-user dump is server-side EXECUTION, where the secret
logic runs on the server and the client receives only results, never the asset
or the key. This demo also speaks plain HTTP to localhost; production needs TLS,
a signed and device-bound token, and short-lived keys.

---

# server/compute_server.py + src/compute_client.c - server-side execution

The strongest tier, and the end of the ladder. The protected IP is an
ALGORITHM (proprietary pricing coefficients), and it never leaves the server.
The client sends inputs and the server returns only the result. Unlike every
earlier tier, there is no key, asset, or formula on the client at all, up or
down, so reverse-engineering the client reveals the request shape and nothing
about the IP.

- `server/compute_server.py`: holds the coefficients, serves `POST /compute`
  (token-gated against `server/licenses.json`), runs the secret model, returns
  only the price, and logs every call.
- `src/compute_client.c`: sends `<qty> <tier>` with its token and prints the
  returned price. Contains no coefficients.

```bash
make compute-demo    # valid token gets a price; revoked/down get nothing;
                     # and `strings` on the client shows no coefficients
python3 tools/agent_attack.py build/compute_o0 --secret "0.000417"  # a coefficient
```

Measured: with the server live, `agent_attack` on the client cannot recover any
coefficient; the client only ever yields computed prices, never the model.

**Honest boundary (the real one for this tier).** The IP is safe from *reading*,
but an authorized caller can PROBE the oracle: send many `(qty, tier)` inputs,
collect prices, and try to fit/approximate the model (model extraction). That is
a much harder attack than reading the code, it needs many queries, and the
server can rate-limit, add noise, log, and revoke. There is no tier beyond this,
because any output the client is allowed to see is information an attacker can
collect. Server-side execution turns "steal the code" into "reconstruct a black
box from its answers", which is the best achievable for logic that must run for
a client at all.

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
