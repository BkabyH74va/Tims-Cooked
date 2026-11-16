#!/usr/bin/env python3
"""List every `and xD, xN, #0xfffffffffffffeff` site in a build/member.

Bit 8 clearing appears 0->107 times in IOSkywalkFamily and 16->169 times in the
kernel core between 24A446 and 24B119. This enumerates the sites with their
containing function and that function's string references, so the construct can
be attributed instead of guessed at.

Usage:
    python kz_mask_sites.py <build> [member]   (member 'com.apple.kernel' = core)
"""
import bisect
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
import capstone  # noqa: E402
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from capstone.arm64 import ARM64_OP_IMM  # noqa: E402
from kc_member import load_member  # noqa: E402

MASK = 0xFFFFFFFFFFFFFEFF


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    bld = argv[1]
    member = argv[2] if len(argv) > 2 else "com.apple.kernel"
    if member == "com.apple.kernel":
        from kc_fstarts import load_build, func_refs, func_of
        b = load_build(bld)
        fo, fr = func_of, func_refs
    else:
        from kc_fstarts import func_refs
        from kc_member import func_of
        b = load_member(bld, member)
        fo, fr = func_of, func_refs
    starts = b["starts"]
    md = capstone.Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True
    out = []
    for nm, (vm, vsz, foff, fsz) in sorted(b["segs"].items(), key=lambda x: x[1][0]):
        if "__TEXT" not in nm:
            continue
        for ins in md.disasm(b["data"][foff:foff + fsz], vm):
            if ins.mnemonic != "and":
                continue
            ops = ins.operands
            if len(ops) < 3 or ops[-1].type != ARM64_OP_IMM:
                continue
            if (ops[-1].imm & ((1 << 64) - 1)) != MASK:
                continue
            st = fo(b, ins.address)
            sz = (st[1] - st[0]) if st and st[1] else 0
            refs = sorted(fr(b, st[0], st[0] + sz))[:4] if sz else []
            out.append((ins.address, st[0] if st else 0, refs))
    print("%s %s: %d sites" % (bld, member, len(out)))
    seen = {}
    for va, st, refs in out:
        seen.setdefault(st, []).append((va, refs))
    for st in sorted(seen):
        v = seen[st][0][1]
        print("  fn %#x  sites=%d  refs=%s" % (st, len(seen[st]), v))


if __name__ == "__main__":
    main(sys.argv)
