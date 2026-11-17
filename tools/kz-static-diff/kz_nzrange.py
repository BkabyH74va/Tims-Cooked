#!/usr/bin/env python3
"""Non-zero qword dump of a __DATA/__DATA_CONST range, with stride grouping.

Numpy-free. Prints each non-zero quadword and, when a run of identically spaced
auth-pointer entries is seen, marks the stride so a mixed descriptor table can
be split into its component arrays.

Usage: python kz_nzrange.py <build> <member> <hex-start> <hex-end>
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
from kc_member import load_member, v2o  # noqa: E402

TEXT_VMADDR = 0xFFFFFE0007004000


def fmt(w):
    lo = w & 0xFFFFFFFF
    hi = w >> 32
    if hi == 0:
        return "int %-12d ; 0x%x" % (
            struct.unpack("<i", struct.pack("<I", lo))[0], lo)
    return "auth->0x%x" % (TEXT_VMADDR + lo)


def main(argv):
    if len(argv) < 5:
        raise SystemExit(__doc__)
    bld, member = argv[1], argv[2]
    start = int(argv[3], 16)
    end = int(argv[4], 16)
    b = load_member(bld, member)
    o0, o1 = v2o(b, start), v2o(b, end)
    print("%s %s %#x .. %#x (%d qwords)" % (bld, member, start, end,
                                            (end - start) // 8))
    prev_auth = None
    for o in range(o0, o1, 8):
        w = struct.unpack_from("<Q", b["data"], o)[0]
        if w == 0:
            continue
        va = TEXT_VMADDR + o
        tag = ""
        if w >> 32:
            tgt = TEXT_VMADDR + (w & 0xFFFFFFFF)
            if prev_auth is not None and tgt == prev_auth:
                tag = "  <== repeat"
            prev_auth = tgt
        else:
            prev_auth = None
        print("0x%x  %s%s" % (va, fmt(w), tag))


if __name__ == "__main__":
    main(sys.argv)
