#!/usr/bin/env python3
"""Resolve short thunks (b/br) starting at given VAs.

Usage:
    python kz_thunk.py <build> <member> <va_hex> [va_hex ...]
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
import capstone  # noqa: E402
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from kc_member import load_member, v2o  # noqa: E402

md = capstone.Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
md.skipdata = True


def main(argv):
    if len(argv) < 4:
        raise SystemExit(__doc__)
    bld, member = argv[1], argv[2]
    b = load_member(bld, member)
    for a in argv[3:]:
        va = int(a, 16)
        off = v2o(b, va)
        print("%s %#x:" % (bld, va))
        for ins in md.disasm(b["data"][off:off + 0x10], va):
            print("   %#x %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))


if __name__ == "__main__":
    main(sys.argv)
