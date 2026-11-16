#!/usr/bin/env python3
"""Print raw disassembly around every `and ...,#0xfffffffffffffeff` site in a function.

Usage:
    python kz_mask_ctx.py <build> <func_va_hex> [ctx]
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
import capstone  # noqa: E402
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from capstone.arm64 import ARM64_OP_IMM  # noqa: E402
from kc_fstarts import load_build, func_of, v2o  # noqa: E402

MASK = 0xFFFFFFFFFFFFFEFF


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    bld, va = argv[1], int(argv[2], 16)
    ctx = int(argv[3]) if len(argv) > 3 else 6
    b = load_build(bld)
    st = func_of(b, va)
    start, end = st[0], st[1]
    off = v2o(b, start)
    md = capstone.Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True
    insns = [(i.address, i.mnemonic, i.op_str)
             for i in md.disasm(b["data"][off:v2o(b, end)], start)]
    idx = []
    for n, (a, m, o) in enumerate(insns):
        if m == "and" and "#%x" % MASK in o.replace("0x", ""):
            idx.append(n)
    print("%s %#x: %d mask sites, %d insns" % (bld, start, len(idx), len(insns)))
    for n in idx[:8]:
        lo, hi = max(0, n - ctx), min(len(insns), n + ctx + 1)
        print("--- site %#x" % insns[n][0])
        for k in range(lo, hi):
            mark = ">>" if k == n else "  "
            print("  %s %#x %-8s %s" % (mark, insns[k][0], insns[k][1], insns[k][2]))


if __name__ == "__main__":
    main(sys.argv)
