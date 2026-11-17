#!/usr/bin/env python3
"""Dump a __DATA_CONST qword window around a VA and locate a C++ vtable header.

Numpy-free. Decodes arm64e auth-pointer entries as target_va =
TEXT_VMADDR + (entry & 0xFFFFFFFF) when the high dword is non-zero, so a
descriptor/array table can be told apart from a real vtable.

Usage:
    python kz_tblwin.py <build> <member> <hex-va> [before] [after]
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


def fmt(entry):
    lo = entry & 0xFFFFFFFF
    hi = entry >> 32
    if hi == 0:
        return "int %-12d ; 0x%x" % (struct.unpack("<i", struct.pack("<I", lo))[0], lo)
    return "auth->0x%x" % (TEXT_VMADDR + lo)


def main(argv):
    if len(argv) < 4:
        raise SystemExit(__doc__)
    bld, member = argv[1], argv[2]
    va = int(argv[3], 16)
    before = int(argv[4], 16) if len(argv) > 4 else 0x80
    after = int(argv[5], 16) if len(argv) > 5 else 0x80
    b = load_member(bld, member)
    off = v2o(b, va)
    start = off - before
    end = off + after
    print("%s %s window 0x%x .. 0x%x (target 0x%x)" %
          (bld, member, TEXT_VMADDR + start, TEXT_VMADDR + end, va))
    for o in range(start, end, 8):
        w = struct.unpack_from("<Q", b["data"], o)[0]
        mark = "  <-- target" if TEXT_VMADDR + o == va else ""
        print("0x%x  %s%s" % (TEXT_VMADDR + o, fmt(w), mark))


if __name__ == "__main__":
    main(sys.argv)
