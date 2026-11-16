#!/usr/bin/env python3
"""Print string references for a list of kernel-core function VAs.

Usage:
    python kz_fn_strings.py <build> <va_hex> [va_hex ...]
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
from kc_fstarts import load_build, func_of, func_refs  # noqa: E402


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    bld = argv[1]
    b = load_build(bld)
    for a in argv[2:]:
        va = int(a, 16)
        st = func_of(b, va)
        if not st:
            print("%#x: no start" % va)
            continue
        sz = (st[1] - st[0]) if st[1] else 0
        refs = sorted(func_refs(b, st[0], st[0] + sz))[:6] if sz else []
        print("%#x fn=%#x sz=%#x refs=%s" % (va, st[0], sz, refs))


if __name__ == "__main__":
    main(sys.argv)
