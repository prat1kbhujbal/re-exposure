# The worked example (learning lab)

The `src/` + `make` targets are a small, measurable lab: one toy
`check_license()` is the lab rat, hardened layer by layer, inspected with the
same tools an analyst uses. This is where the toolkit's ideas are easiest to see
end to end. For the tools themselves, see [harness/README.md](../harness/README.md)
and [tools/README.md](../tools/README.md).

## Layout

| Path | What it is |
| --- | --- |
| `src/license.c` | Baseline, unprotected target (named symbol, plaintext secret + messages) |
| `src/license_hardened.c` | Source-level layers 1+2: encrypted secrets, decrypt-at-use, wipe-after |
| `src/license_flattened.c` | Manually control-flow-flattened, to exercise the readability axis |
| `src/gen_secrets.py` | Build-time secret encryptor; emits `build/secrets_enc.h` |
| `secrets/secrets.txt` | Plaintext secrets kept OUT of the shipped binary |
| `analyst-view.sh` | The "first look": symbols, strings, disasm of `check_license` |
| `Makefile` | `all`, `scan`, `reharden`, `m3-encrypt`, `readability-demo`, `agent-demo`, `pe-demo` |

## Run it

```bash
make all
./analyst-view.sh build/baseline        # the easy target
./analyst-view.sh build/hardened.strip  # source-level layers 1+2 applied
```

## What the source-level layers show

| Signal (what the analyst reads first) | baseline | hardened + strip |
| --- | --- | --- |
| `check_license` symbol | present | gone (stripped) |
| Plaintext key in `strings` | present | gone |
| Message landmarks (`Invalid license key.`) for xref search | present | gone |
| Encrypted blobs in `.rodata` | n/a | present (meaningless to `strings`) |

- **Layer 1 (strip):** `strip --strip-all`. Deletes the function/variable names
  a decompiler uses for navigation. Cheapest, highest ROI. You lose readable
  crash traces, so keep a private unstripped copy for your own debugging.
- **Layer 2 (encrypt secrets):** store secrets XOR-obfuscated, decrypt into a
  stack buffer at point of use, `wipe()` after. Kills `strings` + xref search.

The no-rebuild equivalents of these are `tools/reharden.py` (layer 1 on any
finished binary) and `tools/encrypt_strings.py` / `tools/m3_rewrite.py` (layer 2
without source).

## The finding that matters: the optimizer undoes naive obfuscation

The first build of layer 2 **still leaked the plaintext at `-O2`** even though
the source only stored ciphertext. Cause: `SEC_*` and `SEC_KEY` were
compile-time constants, so clang's constant-propagation folded the XOR away and
baked the plaintext back into `.rodata`. At `-O0` it was clean; at `-O2` it
leaked.

Lesson: **obfuscation computable at compile time gets optimized away.** The
decryption must depend on something the compiler cannot fold. Fix applied here:
mark the key/ciphertext `volatile` so the compiler must emit real loads.
Stronger real-world fix: derive the key at runtime (from argv, a file, a licence
server, a device id) so the plaintext is never computable statically.

Verify the lesson yourself:

```bash
clang -O0 -Ibuild -o /tmp/h0 src/license_hardened.c   # (revert volatile first to see the leak)
strings -a /tmp/h0 | grep -i acme
```

## Boundary of layers 1+2

These defeat automated triage and landmark search. They do **not** stop someone
who finds and reads the decrypt routine: the key sits near the ciphertext.
Hiding or scrambling the routine is control-flow obfuscation (layer 3), which
the readability axis measures.

## Layer 3: control-flow obfuscation (needs an external obfuscator)

Ghidra is set up for the readability axis (see
[harness/README.md](../harness/README.md)), but no automated obfuscator is
installed. `src/license_flattened.c` is a hand-written stand-in that the
readability axis scores at 0 (clean `check_license` scores 100). To use a real
obfuscator:

- **Tigress** (source-to-source C, non-commercial license): download from
  <https://tigress.wtf/>, then flatten + add opaque predicates to just
  `check_license` and diff the Ghidra pseudocode before/after. Note the
  non-commercial license if you intend to ship a product.
- **obfuscator-LLVM** (LLVM passes `-mllvm -fla -bcf -sub`): needs an ollvm
  build; stock clang has no obfuscation passes.

## Deliberately NOT implemented

Runtime layers (anti-debug, anti-instrumentation, integrity / anti-tamper) are
dual-use, break legitimate users, and trip antivirus. If you ever add them, do
it only around the one asset that matters, with a quiet-degrade response rather
than a crash, and test on every target OS.
