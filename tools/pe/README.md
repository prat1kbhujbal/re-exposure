# tools/pe - Windows PE support (build, run, measure on Linux)

Lets the toolkit target Windows PE binaries **without a Windows machine and
without `gcc-mingw-w64`**, using what this box already has.

## Build a PE (no gcc-mingw-w64)

`build-pe.sh <src.c> <out.exe>` compiles with **clang targeting
`x86_64-w64-windows-gnu`** against the mingw *sysroot* (`/usr/x86_64-w64-mingw32`,
present as runtime libs) plus a one-instruction `__chkstk_ms` stub (`chkstk.s`)
that stands in for the missing `libgcc`. Produces a real `PE32+`.

```bash
./tools/pe/build-pe.sh src/license.c build/license.exe
wine64 build/license.exe ACME-PRO-2026-XK7Q    # run it on Linux
make pe-demo                                    # build + run + measure
```

## What works today

- **Build**: C -> PE32+ on Linux (validated: `license.exe`, correct behavior).
- **Run / verify**: under **Wine** (`wine64`), so the `--verify` behavior gate
  can exercise PE outputs.
- **Measure**: `reexpose` detects PE by magic bytes and scores it via objdump
  (validated on `license.exe` = 79 F and on a real `zlib1.dll` = 47 D). The
  symbols axis surfaces real imported Win32 APIs.
- **ddisasm** lifts PE to GTIRB (`pe-x86-64`).

## What's blocked: the PE string-encryption round-trip (M4)

`m3_rewrite`'s reference-correct rewriting needs gtirb-pprinter to emit
assembler we can reassemble on the host. For PE it emits **MASM** targeting the
**MSVC** toolchain (`INCLUDELIB KERNEL32.lib`, `ml64`/`link.exe`, Windows-SDK
import libs) - it has no AT&T/GAS option for PE. The MSVC import libs
(`KERNEL32.lib`) clash with the mingw libs here (`libkernel32.a`), and there is
no `lld-link` + Windows SDK set up. `llvm-ml-14` is present but bridging MASM
output to the mingw linker is substantial. So PE string encryption is the real
M4 blocker; ELF (M1/M2/M3) is unaffected.

Bridge attempt (2026-10-18), recorded so we don't repeat it: tried assembling
gtirb-pprinter's PE MASM with `llvm-ml-14`. It parses the MASM directives
(`EXTERN`/`PROC`) but not gtirb's Microsoft-`ml64` dialect: `$L_x::` global
labels fail, and after transforming those, `SEGMENT READ/WRITE 'DATA'` directives
fail too - a cascade of dialect gaps. gtirb emits for MS `ml64`/`link.exe`
specifically, and `llvm-ml-14` cannot consume it. Conclusion: a real bridge
needs either MS `ml64.exe` + `link.exe` + the Windows SDK (installable and
runnable under Wine), or a full MASM-dialect translator (a project in itself).
Not worth forcing; ELF (M1/M2/M3) is unaffected and is the primary surface.

## Note

`reharden` (metadata strip) now supports **PE** as well as ELF (`strip`/`objcopy`
handle both). On the lab `license.exe` it drops exposure 79 F -> 47.9 D (symbol
table + DWARF debug removed), behavior preserved under Wine. Full PE hardening
(strings) still awaits the blocked round-trip above.
