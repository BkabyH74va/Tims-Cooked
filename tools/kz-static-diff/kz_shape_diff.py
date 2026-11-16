#!/usr/bin/env python3
"""Shape-normalised insert/replace classifier for two builds of one member.

`kz_newfunc_align.py` fingerprints instructions including ADRP page numbers and
slide-sensitive operands. When a member's *data* segment moves between builds,
every ADRP-derived literal changes and unrelated functions get reported as
rewritten. This script repeats the alignment but compares only instruction
**shapes** -- mnemonic, register operands, memory-base register -- with every
immediate and displacement masked. Blocks whose shape sequence is identical are
address-only drift; blocks whose shape differs are real code edits and are
printed with both sizes and the containing function start.

Usage:
    python kz_shape_diff.py <member> [buildA buildB]
"""
import bisect
import difflib
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


def funcs(build, member):
    b = load_member(build, member)
    s = b["starts"]
    return b, [(s[i], (s[i + 1] - s[i]) if i + 1 < len(s) else 0) for i in range(len(s))]


def shape(b, va, sz):
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
        regs = tuple(
            ins.reg_name(o.reg) for o in ops if o.type == capstone.arm64.ARM64_OP_REG
        )
        mem = ""
        for o in ops:
            if o.type == capstone.arm64.ARM64_OP_MEM:
                mem = "[sp]" if o.mem.base == 0 else "[%s]" % ins.reg_name(o.mem.base)
        out.append((ins.mnemonic, regs, mem))
    return tuple(out)


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    member = argv[1]
    a_bld = argv[2] if len(argv) > 2 else BUILDS[0]
    b_bld = argv[3] if len(argv) > 3 else BUILDS[1]
    ba, fa = funcs(a_bld, member)
    bb, fb = funcs(b_bld, member)
    sa = [shape(ba, st, sz) for st, sz in fa]
    sb = [shape(bb, st, sz) for st, sz in fb]

    sm = difflib.SequenceMatcher(a=sa, b=sb, autojunk=False)
    drift = real = 0
    lines = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        if tag in ("insert", "delete") or i2 - i1 != j2 - j1:
            real += 1
            lines.append("COUNT %s A=%d B=%d  A@%#x sz %#x  B@%#x sz %#x" % (
                tag.upper(), i2 - i1, j2 - j1, fa[i1][0], fa[i1][1], fb[j1][0], fb[j1][1]))
            continue
        # same count: check whether every pair is shape-identical
        sub_real = [(k, i1 + k, j1 + k) for k in range(i2 - i1) if sa[i1 + k] != sb[j1 + k]]
        if not sub_real:
            drift += 1
            continue
        real += len(sub_real)
        for k, ia, jb in sub_real[:8]:
            lines.append("SHAPE A@%#x sz %#x -> B@%#x sz %#x" % (
                fa[ia][0], fa[ia][1], fb[jb][0], fb[jb][1]))
    print("%s %s->%s: funcs A=%d B=%d, drift-blocks=%d, real-edits=%d" % (
        member, a_bld, b_bld, len(fa), len(fb), drift, real))
    for ln in lines:
        print("  " + ln)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
