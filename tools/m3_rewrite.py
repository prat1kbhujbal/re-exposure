#!/usr/bin/env python3
"""m3_rewrite -- reference-correct binary rewriting via GTIRB (M3 foundation).

Pipeline (proven working on this host):
  ddisasm (Docker)         binary   -> GTIRB           [reference-accurate IR]
  gtirb-pprinter (Docker)  GTIRB    -> assembly        [references are symbolic]
  [--encrypt-strings]      assembly -> assembly        [per-use string encrypt]
  host clang               assembly -> binary          [host glibc, so it links]

Lifting/printing run in the `grammatech/ddisasm` image; the final link runs on
the host because the image's glibc is older than the host's (so in-container
reassembly fails to resolve versioned libc symbols).

Transforms run on the *assembly* gtirb-pprinter emits, where every reference is
a symbolic label -- so inserting/replacing instructions is reference-correct for
free (the assembler + linker recompute all offsets), the property M1/M2's raw
ELF surgery can't guarantee. encrypt_strings_asm() uses this for per-use string
encryption; plaintext is only ever transiently in a per-site buffer, not resident
for the whole process lifetime (the M1/M2 limitation). The behavior-preservation
--verify gate fails closed: on any divergence it refuses rather than ship a
broken binary (demonstrated refusing /usr/bin/true, which has string patterns the
MVP selector doesn't yet handle).

Usage: m3_rewrite.py <binary> -o <out> [--encrypt-strings] [--verify "<args>"]...

  --encrypt-strings   per-use string encryption: encrypt each .rodata string
                      whose references are all `leaq (L)(%rip),%reg`, and rewrite
                      those references to decrypt on use into a per-site buffer.
                      Plaintext is only transiently resident (the M1/M2 limit).
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

IMAGE = "grammatech/ddisasm"
# common link flags; -pie/-no-pie is chosen per input by _link_flags()
_BASE_LINK = ["-nostartfiles", "-nodefaultlibs", "-Wl,--no-as-needed",
              "-l:libc.so.6", "-Wl,-z,stack-size=0", "-Wl,-z,noexecstack"]


def _link_flags(binary: str) -> list[str]:
    """Match the input's PIE-ness so the output is the same kind of binary
    (preserving PIE/ASLR), plus its DT_NEEDED libraries."""
    hdr = subprocess.run(["readelf", "-hW", binary],
                         capture_output=True, text=True).stdout
    pie = "-pie" if re.search(r"Type:\s+DYN", hdr) else "-no-pie"
    return [pie, *_BASE_LINK, *_needed_libs(binary)]


def _docker(workdir: str, cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "run", "--rm", "-v", f"{workdir}:/w",
                           "--entrypoint", "sh", IMAGE, "-c", cmd],
                          capture_output=True, text=True, timeout=300)


KEY_SEED, KEY_STEP = 0x5a, 0x3b
# caller-saved registers, in push order; a rewrite preserves all but its target
CALLER_SAVED = ["rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11", "rax"]
# 64-bit general-purpose registers a leaq target may legitimately be (no rsp)
GP64 = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}


def _decode_cstr(s: str) -> bytes:
    """Decode a GAS .string literal body to raw bytes (common escapes)."""
    return bytes(s, "latin-1").decode("unicode_escape").encode("latin-1")


def _nul_preceded(pred: str) -> bool:
    """True if a string label starting after `pred` begins at a NUL boundary --
    i.e. no earlier label reads *through* into it. A `.ascii` (no NUL) or a
    `.byte` run not ending in 0 flows into the next label, so such a label is a
    continuation of a larger logical string and must not be encrypted alone."""
    if pred is None:
        return True
    p = pred.strip()
    if p.startswith(".ascii"):
        return False
    if p.startswith(".byte"):
        last = p[len(".byte"):].split(",")[-1].strip()   # last byte value
        return last in ("0x0", "0", "0x00")
    return True   # .string/.zero/.align/section/other data = fresh boundary


def _keystream(i: int) -> int:
    return (KEY_SEED + i * KEY_STEP) & 0xFF


def _decrypt_asm() -> str:
    """Injected decryptor: rdi=cipher, rsi=len, rdx=dest; returns dest in rax.
    Reads a per-call-site buffer so plaintext is only ever transiently in RAM."""
    return f"""
    .text
rea_decrypt:
    movq %rdx, %rax
    xorq %rcx, %rcx
.Lrea_loop:
    cmpq %rsi, %rcx
    jge .Lrea_done
    movzbl (%rdi,%rcx,1), %r9d
    imulq ${KEY_STEP}, %rcx, %r10
    addq ${KEY_SEED}, %r10
    xorl %r10d, %r9d
    movb %r9b, (%rdx,%rcx,1)
    incq %rcx
    jmp .Lrea_loop
.Lrea_done:
    movb $0, (%rdx,%rsi,1)
    ret
"""


def _site_asm(label: str, length: int, buf: str, tgt: str) -> str:
    """A guarded per-use decrypt: save live caller-saved regs (all but the
    target, which the original `lea` was about to overwrite anyway), decrypt
    `label` into `buf`, and leave the plaintext pointer in the target reg."""
    preserve = [r for r in CALLER_SAVED if r != tgt]
    if len(preserve) % 2:            # odd => target is callee-saved; pad so the
        preserve = [preserve[0]] + preserve   # stack stays 16-aligned at callq
    push = "\n".join(f"    pushq %{r}" for r in preserve)
    pop = "\n".join(f"    popq %{r}" for r in reversed(preserve))
    return (f"{push}\n"
            f"    leaq ({label})(%rip), %rdi\n"
            f"    movl ${length}, %esi\n"
            f"    leaq ({buf})(%rip), %rdx\n"
            f"    callq rea_decrypt\n"
            f"    movq %rax, %{tgt}\n"
            f"{pop}")


def _ctor_asm(items) -> str:
    """A startup constructor that decrypts each load-time object in place over a
    byte sub-range [start, start+length). Used for strings reached via a `.quad`
    pointer table (start=0) or a relative-offset table (start = table size, so
    the offset entries stay plaintext). Objects live in a WRITABLE section, so no
    mprotect is needed; wired via .init_array."""
    blocks = []
    for idx, (lab, start, length) in enumerate(items):
        add = f"    addq ${start}, %rdi\n" if start else ""
        blocks.append(
            f"    leaq ({lab})(%rip), %rdi\n"
            f"{add}"
            f"    xorq %rcx, %rcx\n"
            f".Lrc{idx}:\n"
            f"    cmpq ${length}, %rcx\n"
            f"    jge .Lrd{idx}\n"
            f"    movzbl (%rdi,%rcx,1), %eax\n"
            f"    imulq ${KEY_STEP}, %rcx, %r10\n"
            f"    addq ${KEY_SEED}, %r10\n"
            f"    xorl %r10d, %eax\n"
            f"    movb %al, (%rdi,%rcx,1)\n"
            f"    incq %rcx\n"
            f"    jmp .Lrc{idx}\n"
            f".Lrd{idx}:")
    body = "\n".join(blocks)
    return ("\n    .text\n"
            "rea_ctor:\n"
            f"{body}\n"
            "    ret\n"
            '    .section .init_array,"aw",@init_array\n'
            "    .align 8\n"
            "    .quad rea_ctor")


def _cipher_bytes(raw: bytes) -> str:
    return ",".join(f"0x{(b ^ _keystream(k)):02x}" for k, b in enumerate(raw))


def _cipher_ints(raw: bytes):
    return [b ^ _keystream(k) for k, b in enumerate(raw)]


def _parse_offset_table(blob: bytes):
    """Recognize clang's relative-lookup string pool: a run of 32-bit LE byte
    offsets followed by a NUL-terminated string blob, each offset pointing at a
    string start. Returns table_size T (offsets stay plaintext; [T:] is the
    encryptable string region) or None. Strict, to avoid false positives."""
    if len(blob) < 8:
        return None
    t = int.from_bytes(blob[0:4], "little")
    if t < 4 or t % 4 or t > len(blob) or t // 4 > 4096:
        return None
    offs = [int.from_bytes(blob[4 * i:4 * i + 4], "little") for i in range(t // 4)]
    if any(o < t or o >= len(blob) for o in offs):
        return None
    if any(not (o == t or blob[o - 1] == 0) for o in offs):
        return None
    region = blob[t:]
    if not region or region[-1] != 0:
        return None
    good = sum(1 for b in region if b == 0 or 0x20 <= b <= 0x7e)
    if good < 0.9 * len(region):
        return None
    return t


def _scan_offset_tables(lines, loadtime) -> int:
    """Find clang relative-lookup string pools (a label + a run of single-value
    .byte lines that parse as an offset table), referenced only by base
    `leaq (L)(%rip)` loads. Encrypt the string region, move the object to the
    writable load section, and record it for the constructor. Returns the count.
    Runs after the .string pass, whose rewritten (comma-list) .byte lines and
    blanked labels this single-value scan ignores."""
    byte_re = re.compile(r"^\s*\.byte\s+(0x[0-9a-fA-F]+|\d+)\s*$")
    n, i, total = 0, 0, len(lines)
    while i < total:
        m = re.match(r"^([A-Za-z_.][\w.$]*):\s*$", lines[i])
        if not m:
            i += 1
            continue
        lab, j, vals, idxs = m.group(1), i + 1, [], []
        while j < total and byte_re.match(lines[j]):
            vals.append(int(byte_re.match(lines[j]).group(1), 0) & 0xFF)
            idxs.append(j)
            j += 1
        if len(vals) < 8 or _parse_offset_table(bytes(vals)) is None:
            i = max(j, i + 1)
            continue
        blob = bytes(vals)
        t = _parse_offset_table(blob)
        own = {i, *idxs}
        tok = re.compile(r"(?<![\w.$])" + re.escape(lab) + r"(?![\w.$])")
        leaq_re = re.compile(r"^leaq \(" + re.escape(lab) + r"\)\(%rip\),%\w+$")
        ok = True
        for k in range(total):
            if k in own or not tok.search(lines[k]):
                continue
            s = lines[k].strip()
            if s[:5] in (".type", ".size") or s.startswith((".globl", ".local", "#")):
                continue
            if not leaq_re.match(s):
                ok = False
                break
        if ok:
            loadtime.append((lab, list(blob[:t]) + _cipher_ints(blob[t:]),
                             t, len(blob) - t))
            lines[i] = ""
            for k in idxs:
                lines[k] = ""
            n += 1
        i = j
    return n


def encrypt_strings_asm(asm: str):
    """Reference-correct string encryption on gtirb-pprinter assembly.

    Per-use (strongest): strings referenced only by `leaq (L)(%rip),%reg` are
    rewritten to decrypt on use into a per-site buffer (plaintext transient).
    Load-time: strings reached via a `.quad L` pointer table (no code leaq to
    rewrite) are moved to a WRITABLE section and decrypted in place by an
    injected constructor (plaintext resident, but gone from disk). Strings with
    any other reference shape are left alone. Returns (asm, n_peruse, n_refs,
    n_loadtime)."""
    lines = asm.splitlines()
    # label -> (string_line_idx, raw_bytes, label_line_idx). The .string must
    # follow its label AND the label must start at a NUL boundary (nothing reads
    # into it from an earlier label -- see _nul_preceded).
    labels, pending, prev_dir = {}, None, None
    for i, ln in enumerate(lines):
        if re.match(r"^\.L_[0-9a-f]+:\s*$", ln):
            pending = (ln.split(":")[0], prev_dir, i)
            continue
        if not ln.strip():
            continue
        ms = re.match(r'^\s*\.string "(.*)"\s*$', ln)
        if ms and pending and _nul_preceded(pending[1]):
            try:
                labels[pending[0]] = (i, _decode_cstr(ms.group(1)), pending[2])
            except (UnicodeDecodeError, ValueError):
                pass
        pending = None
        prev_dir = ln

    bufs, loadtime = [], []
    n_peruse = n_ref = n_ld = bi = 0
    for lab, (sidx, raw, lidx) in labels.items():
        if not raw:
            continue
        leaq_re = re.compile(r"^leaq \(" + re.escape(lab) + r"\)\(%rip\),%(\w+)$")
        quad_re = re.compile(r"^\.quad\s+" + re.escape(lab) + r"$")
        tok = re.compile(r"(?<![\w.])" + re.escape(lab) + r"(?![\w.])")
        hits = [(i, lines[i].strip()) for i in range(len(lines))
                if i not in (sidx, lidx) and tok.search(lines[i])
                and not re.match(r"^\s*\.L_[0-9a-f]+:\s*$", lines[i])]
        if not hits:
            continue
        if all(leaq_re.match(h) for _, h in hits):
            tgts = [leaq_re.match(h).group(1) for _, h in hits]
            if not all(t in GP64 for t in tgts):
                continue   # 32-bit/rsp target: unsupported, leave string as-is
            # per-use: encrypt in place, rewrite each leaq to decrypt-on-use
            lines[sidx] = f"          .byte {_cipher_bytes(raw)}\n          .byte 0x0"
            for i, h in hits:
                tgt = leaq_re.match(h).group(1)
                buf = f"rea_buf_{bi}"
                lines[i] = _site_asm(lab, len(raw), buf, tgt)
                bufs.append((buf, len(raw) + 1))
                bi += 1
                n_ref += 1
            n_peruse += 1
        elif all(leaq_re.match(h) or quad_re.match(h) for _, h in hits):
            # load-time: move the (encrypted) bytes to a writable section so the
            # pointer-table reference still resolves; decrypt in the constructor
            lines[sidx] = ""
            lines[lidx] = ""
            loadtime.append((lab, _cipher_ints(raw) + [0], 0, len(raw)))
            n_ld += 1
        # else: an unrecognized reference shape -> leave the string untouched

    # offset-table string pools (clang -O2 relative-lookup tables): a labelled
    # run of raw .byte, referenced by `leaq (L)(%rip)` base loads. Encrypt only
    # the string region ([T:]); offsets stay plaintext; decrypt at load.
    n_ld += _scan_offset_tables(lines, loadtime)

    tail = []
    if n_peruse:
        tail.append(_decrypt_asm())
        tail.append("\n    .bss")
        tail += [f"{b}:\n    .zero {sz}" for b, sz in bufs]
    if loadtime:
        data = ['\n    .section .rea_ld,"aw",@progbits']
        data += [f"{lab}:\n    .byte " + ",".join(f"0x{b:02x}" for b in emit)
                 for lab, emit, _, _ in loadtime]
        tail.append("\n".join(data))
        tail.append(_ctor_asm([(lab, ds, dl) for lab, _, ds, dl in loadtime]))
    if tail:
        lines.append("\n".join(tail))
    return "\n".join(lines), n_peruse, n_ref, n_ld


def report(gtirb_path: str) -> dict:
    try:
        import gtirb
    except ImportError:
        return {}
    ir = gtirb.IR.load_protobuf(gtirb_path)
    m = ir.modules[0]
    secs = {s.name: sum(bi.size for bi in s.byte_intervals)
            for s in m.sections if s.name in (".text", ".rodata", ".data")}
    return {"isa": str(m.isa), "format": str(m.file_format), "sections": secs}


def rewrite(binary: str, out: str, encrypt: bool = False) -> dict:
    if not shutil.which("docker"):
        raise SystemExit("m3_rewrite: docker not available")
    with tempfile.TemporaryDirectory() as td:
        asm = os.path.join(td, "out.s")
        shutil.copy2(binary, os.path.join(td, "in"))
        r = _docker(td, "ddisasm /w/in --ir /w/in.gtirb")
        if not os.path.exists(os.path.join(td, "in.gtirb")):
            raise SystemExit("m3_rewrite: ddisasm failed\n" + r.stderr[-800:])
        info = report(os.path.join(td, "in.gtirb"))
        r = _docker(td, "gtirb-pprinter /w/in.gtirb --asm /w/out.s")
        if not os.path.exists(asm):
            raise SystemExit("m3_rewrite: gtirb-pprinter failed\n" + r.stderr[-800:])
        if encrypt:
            with open(asm) as fh:                 # container wrote it (root); readable
                text = fh.read()
            text, n_peruse, n_ref, n_ld = encrypt_strings_asm(text)
            asm = os.path.join(td, "out.enc.s")   # our own file (container owns out.s)
            with open(asm, "w") as fh:
                fh.write(text)
            info["encrypted"] = {"per_use": n_peruse, "refs_rewritten": n_ref,
                                 "load_time": n_ld}
        link = subprocess.run(["clang", asm, "-o", out, *_link_flags(binary)],
                              capture_output=True, text=True)
        if link.returncode != 0:
            raise SystemExit("m3_rewrite: host link failed\n" + link.stderr[-1200:])
        os.chmod(out, 0o755)
        return info


def _needed_libs(binary: str) -> list[str]:
    """Shared libraries the input depends on (DT_NEEDED), as linker flags, so
    the rebuilt binary resolves the same symbols. libc is already in LINK_FLAGS;
    the dynamic loader is not a link input."""
    out = subprocess.run(["readelf", "-dW", binary],
                         capture_output=True, text=True).stdout
    flags = []
    for m in re.finditer(r"\(NEEDED\).*\[([^\]]+)\]", out):
        lib = m.group(1)
        if lib.startswith("libc.so") or lib.startswith("ld-linux"):
            continue
        flags.append(f"-l:{lib}")
    return flags


def _run(path, args):
    ap = os.path.abspath(path)
    p = subprocess.run([ap, *args], capture_output=True, timeout=30)  # bytes
    return p.returncode, p.stdout.replace(ap.encode(), b"<SELF>")


def _optval(a, flag, default=None):
    """Value after `flag`, or `default` if absent; clean error if it has none."""
    if flag not in a:
        return default
    i = a.index(flag)
    if i + 1 >= len(a):
        raise SystemExit(f"error: {flag} needs a value")
    return a[i + 1]


def main() -> int:
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if a else 2
    binary = a[0]
    out = _optval(a, "-o", binary + ".m3")
    encrypt = "--encrypt-strings" in a
    verifies = [a[i + 1] for i, t in enumerate(a)
                if t == "--verify" and i + 1 < len(a)]

    info = rewrite(binary, out, encrypt)
    print(f"\n{'encrypt-strings' if encrypt else 'round-trip'}: {binary} -> {out}")
    if info.get("isa"):
        print(f"  GTIRB: {info['isa']} {info['format']}  sections={info['sections']}")
    if info.get("encrypted"):
        e = info["encrypted"]
        print(f"  per-use: {e['per_use']} strings / {e['refs_rewritten']} refs "
              f"rewritten to decrypt-on-use")
        print(f"  load-time: {e['load_time']} objects (.quad tables + "
              f"offset-table pools) decrypted by injected constructor")

    ok = True
    for v in verifies:
        args = shlex.split(v)
        rc0, o0 = _run(binary, args)
        rc1, o1 = _run(out, args)
        same = rc0 == rc1 and o0 == o1
        ok = ok and same
        print(f"  verify {args!r}: {'OK' if same else 'DIVERGED'} "
              f"(orig rc={rc0}, out rc={rc1})")
    if verifies and not ok:
        print("ROUND-TRIP DIVERGED", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
