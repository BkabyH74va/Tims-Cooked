#!/usr/bin/env python3
"""Instruction-level semantic diff of one cross-build region inside a member.

Complements `kz_pair_shape_check.py`: that tool answers "did the instruction
*shape* change", this one shows *what* changed, keeping immediates and
displacements visible while masking only the two things that legitimately
differ between rebased builds (absolute branch targets and ADRP pages).

Usage:
    python kz_fn_sem_diff.py <member> <Ava> <Bva> <Asize> <Bsize> [maxblocks]

Sizes are the region extents (use the sums from `kz_newfunc_align.py`).
"""
import difflib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
import capstone  # noqa: E402
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from kc_member import load_member, v2o  # noqa: E402

MD = capstone.Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True
MD.skipdata = True
MASK_KVA = 0xfffffe0000000000


def norm_ops(ins):
    """Operand string with rebase-sensitive pieces masked, structure kept."""
    parts = []
    for o in ins.op_str.split(", "):
        try:
            v = int(o.lstrip("#"), 0)
        except ValueError:
            parts.append(o)
            continue
        if o.startswith("#0xfffffe"):
            parts.append("#KVA")
        elif -0x10000 <= v <= 0x100000:
            parts.append(o)
        else:
            parts.append("#IMM")
    return ", ".join(parts)


def toks(bld, member, va, sz):
    b = load_member(bld, member)
    off = v2o(b, va)
    out = []
    for ins in MD.disasm(b["data"][off:off + sz], va):
        out.append((ins.address, ins.mnemonic, norm_ops(ins), ins.bytes.hex()))
    return out


def main(argv):
    if len(argv) < 6:
        raise SystemExit(__doc__)
    member = argv[1]
    ava, bva = int(argv[2], 16), int(argv[3], 16)
    asz, bsz = int(argv[4], 16), int(argv[5], 16)
    maxblocks = int(argv[6]) if len(argv) > 6 else 200
    A = toks("24A446", member, ava, asz)
    B = toks("24B119", member, bva, bsz)
    ka = [(m, o) for _, m, o, _ in A]
    kb = [(m, o) for _, m, o, _ in B]
    sm = difflib.SequenceMatcher(None, ka, kb, autojunk=False)
    n = 0
    print("; region A %#x sz %#x (%d insns)  B %#x sz %#x (%d insns)" %
          (ava, asz, len(A), bva, bsz, len(B)))
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        n += 1
        if n > maxblocks:
            print("; ... more blocks suppressed")
            break
        print("\n[%s] A %d..%d (%d) B %d..%d (%d)" %
              (tag.upper(), i1, i2, i2 - i1, j1, j2, j2 - j1))
        for k in range(i1, min(i2, i1 + 14)):
            print("  A %#x  %-8s %s" % (A[k][0], A[k][1], A[k][2]))
        if i2 - i1 > 14:
            print("  A ... (%d more)" % (i2 - i1 - 14))
        for k in range(j1, min(j2, j1 + 14)):
            print("  B %#x  %-8s %s" % (B[k][0], B[k][1], B[k][2]))
        if j2 - j1 > 14:
            print("  B ... (%d more)" % (j2 - j1 - 14))
    if n == 0:
        print("; identical after normalisation")


if __name__ == "__main__":
    main(sys.argv)
