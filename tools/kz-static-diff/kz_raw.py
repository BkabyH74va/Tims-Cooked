#!/usr/bin/env python3
"""Raw disassembly of one region of a member (no annotation).

Usage:
    python kz_raw.py <build> <member> <va_hex> <size_hex>
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

MD = capstone.Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True
MD.skipdata = True


def main(argv):
    if len(argv) < 5:
        raise SystemExit(__doc__)
    bld, member = argv[1], argv[2]
    va, sz = int(argv[3], 16), int(argv[4], 16)
    b = load_member(bld, member)
    off = v2o(b, va)
    for ins in MD.disasm(b["data"][off:off + sz], va):
        print("%#018x  %-10s %s" % (ins.address, ins.mnemonic, ins.op_str))


if __name__ == "__main__":
    main(sys.argv)
