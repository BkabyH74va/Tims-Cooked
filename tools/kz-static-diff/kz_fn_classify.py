#!/usr/bin/env python3
"""Classify cross-build region edits inside a member as layout drift vs code.

Wraps `kz_fn_sem_diff.py`'s normalised diff and adds the decisive second test:
for every non-equal block, compare the instruction *shape* (mnemonic + register
operands + memory base, all immediates/displacements masked). Shape-identical
blocks are struct-layout/ABI drift -- the code logic did not change, only the
field offsets or constants it touches. Only shape-differing blocks are real
code edits.

Usage:
    python kz_fn_classify.py <member> <align-output.txt> [shape-check-output.txt]

If the shape-check output is given, only lines flagged REAL there are examined;
otherwise every replace line in the align output is examined.
"""
import difflib
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
import capstone  # noqa: E402
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_MEM  # noqa: E402
from kc_member import load_member, v2o  # noqa: E402

MD = capstone.Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True
MD.skipdata = True

ALIGN_PAT = re.compile(
    r"replace A=(\d+)\s+B=(\d+)\s+szA=(-?\d+|0x[0-9a-f]+)\s+szB=(-?\d+|0x[0-9a-f]+)\s+"
    r"A@0x([0-9a-f]+)\.\.0x([0-9a-f]+)\s+B@0x([0-9a-f]+)\.\.0x([0-9a-f]+)")
REAL_PAT = re.compile(
    r"(?:REAL|COUNT-MISMATCH) A@\s*0x([0-9a-f]+)\s+sz\s+(0x[0-9a-f]+)\s*->\s*"
    r"B@\s*0x([0-9a-f]+)\s+sz\s+(0x[0-9a-f]+)")


def ins_list(bld, member, va, sz):
    b = load_member(bld, member)
    off = v2o(b, va)
    blob = b["data"][off:off + sz]
    # a region may run past its segment into padding; disassemble what is there
    return [(ins.address, ins) for ins in MD.disasm(blob, va)]


def shape(ins):
    try:
        ops = ins.operands
    except capstone.CsError:
        ops = []
    regs = tuple(ins.reg_name(o.reg) for o in ops if o.type == ARM64_OP_REG)
    mem = ""
    for o in ops:
        if o.type == ARM64_OP_MEM:
            mem = "[sp]" if o.mem.base == 0 else "[%s]" % ins.reg_name(o.mem.base)
    return (ins.mnemonic, regs, mem)


def norm(op_str):
    parts = []
    for o in op_str.split(", "):
        try:
            int(o.lstrip("#"), 0)
        except ValueError:
            parts.append(o)
            continue
        parts.append("#KVA" if o.startswith("#0xfffffe") else "#N")
    return ", ".join(parts)


def analyse(member, ava, bva, asz, bsz, verbose=False):
    A = ins_list("24A446", member, ava, asz)
    B = ins_list("24B119", member, bva, bsz)
    ka = [(i.mnemonic, norm(i.op_str)) for _, i in A]
    kb = [(i.mnemonic, norm(i.op_str)) for _, i in B]
    sm = difflib.SequenceMatcher(None, ka, kb, autojunk=False)
    code, drift = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        sa = tuple(shape(i) for _, i in A[i1:i2])
        sb = tuple(shape(i) for _, i in B[j1:j2])
        entry = (tag, A[i1][0] if i1 < i2 else None,
                 B[j1][0] if j1 < j2 else None, i2 - i1, j2 - j1)
        (drift if sa == sb else code).append(entry)
        if verbose and sa != sb:
            print("  CODE %s A@%s (%d) B@%s (%d)" % (tag, entry[1], entry[3],
                                                     entry[2], entry[4]))
            for k in range(i1, min(i2, i1 + 6)):
                print("    A %#x %-8s %s" % (A[k][0], A[k][1].mnemonic, A[k][1].op_str))
            for k in range(j1, min(j2, j1 + 6)):
                print("    B %#x %-8s %s" % (B[k][0], B[k][1].mnemonic, B[k][1].op_str))
    return code, drift


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    member, path = argv[1], argv[2]
    real = {}
    if len(argv) > 3:
        for ln in Path(argv[3]).read_text(errors="replace").splitlines():
            m = REAL_PAT.search(ln)
            if m:
                real[(int(m.group(1), 16), int(m.group(3), 16))] = (
                    int(m.group(2), 16), int(m.group(4), 16))
    print("### %s ###" % member)
    seen = set()
    for ln in Path(path).read_text(errors="replace").splitlines():
        m = ALIGN_PAT.search(ln)
        if not m:
            continue
        na, nb = int(m.group(1)), int(m.group(2))
        asz = int(m.group(3), 0) if m.group(3).startswith(("0x", "-0x")) else int(m.group(3))
        bsz = int(m.group(4), 0) if m.group(4).startswith(("0x", "-0x")) else int(m.group(4))
        ava, bva = int(m.group(5), 16), int(m.group(7), 16)
        key = (ava, bva)
        if real and key not in real:
            continue
        if key in seen:
            continue
        seen.add(key)
        code, drift = analyse(member, ava, bva, asz, bsz, verbose=bool(real))
        print("block A=%d B=%d A@%#x sz %#x -> B@%#x sz %#x : code=%d drift=%d" %
              (na, nb, ava, asz, bva, bsz, len(code), len(drift)))
        for c in code[:12]:
            print("    CODE %-7s A@%s (%d) B@%s (%d)" % (c[0], hex(c[1]) if c[1] else "-",
                                                        c[3], hex(c[2]) if c[2] else "-", c[4]))


if __name__ == "__main__":
    main(sys.argv)
