#!/usr/bin/env python3
"""encrypt_strings -- M1 post-build .rodata string encryption for non-PIE ELF.

Encrypts selected .rodata string literals on disk so `strings`/xref/LLM-anchor
search find nothing, and injects an entry-point stub that decrypts them in
memory before the original entry runs. Behavior is preserved: the exact bytes
are restored before any application code executes.

Scope (M2): x86-64 ELF, both PIE (ET_DYN) and non-PIE (ET_EXEC). The stub is
base-relative, so one path serves both. Scans .rodata plus the .rodata.str*
and .data.rel.ro string sections. Rolling keystream key.
Limit: like all load-time decryption, plaintext exists in memory for the
process lifetime -- this defeats STATIC triage, not a runtime dump.

Usage:
    encrypt_strings.py <in.elf> -o <out> [--all] [--min-len 4]
                        [--key 0x5a] [--step 0x3b] [--verify "<args>"]...

    --all         encrypt every printable run (default: only risk-lexicon hits)
    --min-len N   minimum run length to consider (default 4)
    --key 0xNN    keystream seed (default 0x5a)
    --step 0xNN   keystream step; byte i uses (seed + i*step) & 0xff (default 0x3b)
    --verify A    run original vs output with args A and diff stdout+exit;
                  repeatable; any divergence fails the harden
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
import tempfile

import lief

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "harness"))
try:
    from reexpose import scan, _SECRET_WORDS, _SRCPATH, _URL  # type: ignore
except Exception:
    scan = None
    import re
    _SECRET_WORDS = re.compile(r"licen[cs]e|key|secret|password|token|auth", re.I)
    _SRCPATH = re.compile(r"/[\w.\-/]+\.(c|cc|cpp|rs|go|h)")
    _URL = re.compile(r"https?://", re.I)

PAGE = 0x1000
PROT_RW, PROT_R = 3, 1

# string-bearing sections we scan (all present ones are processed)
_STRING_SECTIONS = [".rodata", ".rodata.str1.1", ".rodata.str1.2",
                    ".rodata.str1.4", ".rodata.str1.8", ".data.rel.ro"]


def _risky(s: str) -> bool:
    return bool(_SECRET_WORDS.search(s) or _SRCPATH.search(s) or _URL.search(s))


def _allowed(byte: int) -> bool:
    # visible ASCII plus the common in-string control chars (tab/newline/CR)
    return 0x20 <= byte <= 0x7e or byte in (0x09, 0x0a, 0x0d)


def select_runs(content: bytes, base_va: int, min_len: int, take_all: bool):
    """Find NUL-terminated string runs. Return [(va, offset, text)]."""
    runs, i, n = [], 0, len(content)
    while i < n:
        if 0x20 <= content[i] <= 0x7e:          # start on a visible char
            j = i
            while j < n and _allowed(content[j]):
                j += 1
            printable = sum(1 for k in range(i, j) if 0x20 <= content[k] <= 0x7e)
            # a genuine C string is NUL-terminated and mostly visible
            if j < n and content[j] == 0x00 and printable >= min_len:
                text = content[i:j].decode("latin-1")
                if take_all or _risky(text):
                    runs.append((base_va + i, i, text))
            i = j + 1
        else:
            i += 1
    return runs


def keystream(i: int, seed: int, step: int) -> int:
    return (seed + i * step) & 0xff


def build_stub(spans, seed: int, step: int, orig_entry: int, base_vaddr: int):
    """Assemble the base-relative decryptor stub. `spans` is a list of
    (page_img_vaddr, pages_len, [(range_img_vaddr, length), ...]).

    The stub derives the runtime load base B via a RIP-relative lea minus the
    (image) vaddr of that point, then addresses everything as B + image_vaddr.
    For non-PIE, B computes to 0, so the same stub serves both. Returns
    (raw_bytes, rebase_ref_offset).
    """
    body = []
    lbl = 0
    for page_img, plen, ranges in spans:
        body.append(f"""
    movabs rdi, {page_img}
    add rdi, rbx
    mov rsi, {plen}
    mov rdx, {PROT_RW}
    mov rax, 10
    syscall""")
        for addr, length in ranges:
            body.append(f"""
    movabs rdi, {addr}
    add rdi, rbx
    mov rcx, {length}
    mov al, {seed}
.Lr{lbl}:
    xor byte ptr [rdi], al
    add al, {step}
    inc rdi
    dec rcx
    jnz .Lr{lbl}""")
            lbl += 1
        body.append(f"""
    movabs rdi, {page_img}
    add rdi, rbx
    mov rsi, {plen}
    mov rdx, {PROT_R}
    mov rax, 10
    syscall""")
    asm = f""".intel_syntax noprefix
.text
.globl _stub
.globl rebase_ref
_stub:
    push rdx                 # preserve rtld_fini for the original _start
    lea rbx, [rip+0]         # rbx = runtime addr of the next instruction
rebase_ref:
    .byte 0x48, 0xb8         # movabs rax, imm64 (patched to V + rebase_ref)
    .quad 0
    sub rbx, rax             # rbx = runtime load base B (0 for non-PIE)
    {''.join(body)}
    movabs rax, {orig_entry} # image vaddr of the original entry
    add rax, rbx             # -> runtime entry
    pop rdx
    jmp rax
"""
    with tempfile.TemporaryDirectory() as td:
        s, o, b = (os.path.join(td, f"stub.{e}") for e in ("s", "o", "bin"))
        with open(s, "w") as fh:
            fh.write(asm)
        r = subprocess.run(["as", "--64", s, "-o", o],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit(f"stub assembly failed:\n{r.stderr}\n{asm}")
        subprocess.run(["objcopy", "-O", "binary", "--only-section=.text", o, b],
                       check=True)
        nm = subprocess.run(["nm", o], capture_output=True, text=True).stdout
        rro = next(int(ln.split()[0], 16) for ln in nm.splitlines()
                   if ln.endswith(" rebase_ref"))
        raw = bytearray(open(b, "rb").read())
        # patch the movabs imm64 (at rebase_ref+2) to V + rebase_ref
        raw[rro + 2:rro + 10] = ((base_vaddr + rro) & (2**64 - 1)).to_bytes(8, "little")
        return bytes(raw), rro


def _gather_spans(b, take_all, min_len, seed, step, do_encrypt):
    present = {s.name for s in b.sections}
    spans, all_runs = [], []
    for name in _STRING_SECTIONS:
        if name not in present:
            continue
        sec = b.get_section(name)
        content = bytearray(bytes(sec.content))
        runs = select_runs(bytes(content), sec.virtual_address, min_len, take_all)
        if not runs:
            continue
        ranges = []
        for va, off, text in runs:
            length = len(text)
            if do_encrypt:
                for k in range(length):
                    content[off + k] ^= keystream(k, seed, step)
            ranges.append((va, length))
        if do_encrypt:
            sec.content = list(content)
        # Page-round the span for mprotect. Edge: if a section (e.g.
        # .data.rel.ro) shares its end page with a writable section, restoring
        # the span to PROT_READ could flip that neighbour read-only. In practice
        # RELRO isolates .data.rel.ro on its own pages; the --verify gate catches
        # any case where it does not.
        page_start = sec.virtual_address & ~(PAGE - 1)
        page_end = (sec.virtual_address + sec.size + PAGE - 1) & ~(PAGE - 1)
        spans.append((page_start, page_end - page_start, ranges))
        all_runs += [(name, t) for _, _, t in runs]
    return spans, all_runs


def _make_seg(raw: bytes):
    seg = lief.ELF.Segment()
    seg.type = lief.ELF.Segment.TYPE.LOAD
    seg.flags = lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.X
    seg.content = list(raw)
    return seg


def encrypt_strings(src: str, out: str, take_all: bool, min_len: int,
                    seed: int, step: int):
    # Adding a LOAD segment makes LIEF relayout a PIE (sections + entry shift),
    # so the stub must be built from POST-add vaddrs. Byte offsets within a
    # section are invariant, so content can be encrypted before the add.

    # pass 1: add a correctly-sized placeholder to learn the final layout
    b1 = lief.ELF.parse(src)
    pre_spans, pre_runs = _gather_spans(b1, take_all, min_len, seed, step, False)
    if not pre_runs:
        raise SystemExit("encrypt_strings: no matching strings (try --all)")
    dummy, rro = build_stub(pre_spans, seed, step, b1.entrypoint, 0)
    v = b1.add(_make_seg(dummy)).virtual_address
    orig_entry = b1.entrypoint                       # LIEF-corrected post-add
    post_spans, _ = _gather_spans(b1, take_all, min_len, seed, step, False)

    # pass 2: encrypt content, then add the final stub built from post-add vaddrs
    b = lief.ELF.parse(src)
    _, runs = _gather_spans(b, take_all, min_len, seed, step, True)
    final, rro2 = build_stub(post_spans, seed, step, orig_entry, v)
    if len(final) != len(dummy) or rro2 != rro:
        raise SystemExit("encrypt_strings: stub layout not reproducible")
    new = b.add(_make_seg(final))
    if new.virtual_address != v:
        raise SystemExit(f"encrypt_strings: segment vaddr unstable "
                         f"(0x{v:x} vs 0x{new.virtual_address:x})")
    b.header.entrypoint = v
    b.write(out)
    os.chmod(out, 0o755)
    is_pie = b.header.file_type == lief.ELF.Header.FILE_TYPE.DYN
    return runs, v, orig_entry, is_pie


def _run(path, args):
    ap = os.path.abspath(path)
    # capture bytes, not text: a hardened program may emit non-UTF-8 output,
    # which would crash a text=True decode before the gate can report it.
    p = subprocess.run([ap, *args], capture_output=True, timeout=30)
    # normalize argv[0] so two binaries at different paths compare equal
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
    src = a[0]
    out = _optval(a, "-o", src + ".enc")
    take_all = "--all" in a
    min_len = int(_optval(a, "--min-len", 4))
    seed = int(_optval(a, "--key", "0x5a"), 0)
    step = int(_optval(a, "--step", "0x3b"), 0)
    verifies = [a[i + 1] for i, t in enumerate(a)
                if t == "--verify" and i + 1 < len(a)]

    before = scan(src) if scan else None
    runs, stub_va, orig_entry, is_pie = encrypt_strings(
        src, out, take_all, min_len, seed, step)
    after = scan(out) if scan else None

    kind = "PIE" if is_pie else "non-PIE"
    print(f"\nencrypted {len(runs)} strings in {src} -> {out}  [{kind}]")
    print(f"  stub @ 0x{stub_va:x}, orig entry 0x{orig_entry:x}, "
          f"key seed=0x{seed:02x} step=0x{step:02x}")
    for sec, text in runs[:10]:
        print(f"  - [{sec}] {text!r}")

    # behavior-preservation gate
    ok = True
    for v in verifies:
        args = shlex.split(v)
        rc0, o0 = _run(src, args)
        rc1, o1 = _run(out, args)
        same = (rc0 == rc1 and o0 == o1)
        ok = ok and same
        print(f"  verify {args!r}: {'OK' if same else 'DIVERGED'} "
              f"(orig rc={rc0}, out rc={rc1})")
    if verifies and not ok:
        print("BEHAVIOR DIVERGED -- harden rejected", file=sys.stderr)
        return 1

    if before and after:
        print(f"\nexposure: {before['exposure_score']} "
              f"({before['protection_grade']}) -> {after['exposure_score']} "
              f"({after['protection_grade']})")
        bs, as_ = before["axes"]["strings"]["score"], after["axes"]["strings"]["score"]
        print(f"  strings axis: {bs} -> {as_}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
