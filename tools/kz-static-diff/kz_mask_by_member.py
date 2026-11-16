#!/usr/bin/env python3
"""Count `and ...,#0xfffffffffffffeff` sites per fileset member, both builds.

The 27.2 bit-8-clearing idiom grows image-wide (34 -> 477 sites in __TEXT_EXEC).
This attributes the growth to members so the fix surface can be ranked.

Usage:
    python kz_mask_by_member.py [topN]
"""
import struct
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
import capstone  # noqa: E402
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from capstone.arm64 import ARM64_OP_IMM  # noqa: E402
from kc_iosurface import parse_fileset, member_segments  # noqa: E402

MASK = 0xFFFFFFFFFFFFFEFF


def main(argv):
    topn = int(argv[1]) if len(argv) > 1 else 25
    md = capstone.Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True
    res = {}
    for bld in ("24A446", "24B119"):
        d = (ROOT / "firmware" / bld / "kernelcache.release.macho").read_bytes()
        entries, _ = parse_fileset(d)
        c = Counter()
        for e in entries:
            segs = member_segments(d, e["fileoff"])
            n = 0
            for nm, (vm, vsz, fo, fsz) in segs.items():
                if "TEXT" not in nm or nm.startswith("__DATA"):
                    continue
                for ins in md.disasm(d[fo:fo + fsz], vm):
                    if ins.mnemonic != "and":
                        continue
                    ops = ins.operands
                    if len(ops) >= 3 and ops[-1].type == ARM64_OP_IMM and \
                            (ops[-1].imm & ((1 << 64) - 1)) == MASK:
                        n += 1
            if n:
                c[e["name"]] = n
        res[bld] = c
    keys = sorted(set(res["24A446"]) | set(res["24B119"]),
                  key=lambda k: -(res["24B119"].get(k, 0) - res["24A446"].get(k, 0)))
    print("%-52s %8s %8s %8s" % ("member", "24A446", "24B119", "delta"))
    for k in keys[:topn]:
        a, b = res["24A446"].get(k, 0), res["24B119"].get(k, 0)
        print("%-52s %8d %8d %+8d" % (k, a, b, b - a))
    print("totals: A=%d B=%d" % (sum(res["24A446"].values()), sum(res["24B119"].values())))


if __name__ == "__main__":
    main(sys.argv)
