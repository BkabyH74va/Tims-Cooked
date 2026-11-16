#!/usr/bin/env python3
"""Classify `kz_newfunc_align.py` replace blocks as address drift or real edits.

kz_newfunc_align compares normalised instruction fingerprints. When a member's
data segment moves between builds, ADRP page literals change even inside
functions whose code is untouched, so unrelated functions get reported as
rewritten. This script takes the pairing that tool produced and re-compares each
block using instruction **shapes** only (mnemonic + register operands + memory
base), with every immediate/displacement masked.

Usage:
    python kz_pair_shape_check.py <member> <kz_newfunc_align-output.txt>
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "opencode-temp"))
sys.path.insert(0, str(HERE.parent / "pylibs"))
import capstone  # noqa: E402
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from kc_member import load_member  # noqa: E402

BUILDS = ("24A446", "24B119")
MD = capstone.Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True
MD.skipdata = True
PAT = re.compile(
    r"replace A=(\d+)\s+B=(\d+)\s+szA=(\d+)\s+szB=(\d+)\s+"
    r"A@0x([0-9a-f]+)\.\.0x([0-9a-f]+)\s+B@0x([0-9a-f]+)\.\.0x([0-9a-f]+)"
)


def shape(build, member, va, sz):
    b = load_member(build, member)
    off = None
    for nm, (vm, vsz, fo, fsz) in b["segs"].items():
        if vm <= va < vm + vsz:
            off = fo + (va - vm)
            break
    if off is None or sz == 0:
        return ()
    out = []
    for ins in MD.disasm(b["data"][off:off + sz], va):
        try:
            ops = ins.operands
        except capstone.CsError:
            ops = []
        regs = tuple(ins.reg_name(o.reg) for o in ops if o.type == capstone.arm64.ARM64_OP_REG)
        mem = ""
        for o in ops:
            if o.type == capstone.arm64.ARM64_OP_MEM:
                mem = "[sp]" if o.mem.base == 0 else "[%s]" % ins.reg_name(o.mem.base)
        out.append((ins.mnemonic, regs, mem))
    return tuple(out)


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    member, path = argv[1], argv[2]
    drift = real = 0
    for ln in Path(path).read_text(errors="replace").splitlines():
        m = PAT.match(ln)
        if not m:
            continue
        nA, nB, szA, szB = (int(m.group(i)) for i in (1, 2, 3, 4))
        a, bs = int(m.group(5), 16), int(m.group(7), 16)
        if nA != nB:
            real += 1
            print("COUNT-MISMATCH A=%d B=%d  A@%#x sz %#x -> B@%#x sz %#x" % (nA, nB, a, szA, bs, szB))
            continue
        same = shape(BUILDS[0], member, a, szA) == shape(BUILDS[1], member, bs, szB)
        if same:
            drift += 1
        else:
            real += 1
            print("REAL A@%#x sz %#x -> B@%#x sz %#x (delta %+d)" % (a, szA, bs, szB, szB - szA))
    print("%s: blocks drift=%d real=%d" % (member, drift, real))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
