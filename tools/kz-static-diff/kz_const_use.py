#!/usr/bin/env python3
"""Count distinctive immediate bitmasks / constants used across a member.

Used to test whether a construct seen in a cross-build diff (e.g. an `and`
with a specific mask) is new in the fixed build or already present throughout.

Usage:
    python kz_const_use.py <member> [buildA buildB]
"""
import re
import sys
from collections import Counter
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
    if len(argv) < 2:
        raise SystemExit(__doc__)
    member = argv[1]
    builds = argv[2:] or ["24A446", "24B119"]
    res = {}
    for bld in builds:
        if member == "com.apple.kernel":
            sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
            from kc_fstarts import load_build
            b = load_build(bld)
        else:
            b = load_member(bld, member)
        c = Counter()
        for nm, (vm, vsz, fo, fsz) in b["segs"].items():
            if not nm.endswith("EXEC") and "__TEXT" not in nm:
                continue
            code = b["data"][fo:fo + fsz]
            for ins in MD.disasm(code, vm):
                s = ins.op_str
                if "fffffeff" in s or "fffffdff" in s or "fffffbff" in s:
                    c["mask:" + ins.mnemonic + ":" + s.split(", ")[-1]] += 1
        res[bld] = c
    keys = sorted(set(res[builds[0]]) | set(res[builds[1]]))
    print("%-50s %10s %10s" % ("construct", builds[0], builds[1]))
    for k in keys:
        print("%-50s %10d %10d" % (k, res[builds[0]].get(k, 0), res[builds[1]].get(k, 0)))


if __name__ == "__main__":
    main(sys.argv)
