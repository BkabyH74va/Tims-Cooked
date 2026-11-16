#!/usr/bin/env python3
"""Find code sites inside a member that build a given VA with ADRP+ADD / ADRP+LDR.

Usage:
    python kz_ref_sites.py <build> <member> <va_hex>
"""
import bisect
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
from kc_member import load_member  # noqa: E402

u = lambda x: x & ((1 << 64) - 1)  # noqa: E731
sx = lambda v, bits: v - (1 << bits) if v & (1 << (bits - 1)) else v  # noqa: E731


def main(argv):
    if len(argv) < 4:
        raise SystemExit(__doc__)
    bld, member = argv[1], argv[2]
    tgt = int(argv[3], 16)
    b = load_member(bld, member)
    starts = b["starts"]

    def fn(va):
        i = bisect.bisect_right(starts, va) - 1
        return "%#x" % starts[i] if i >= 0 else "-"

    for nm, (vm, vsz, fo, fsz) in sorted(b["segs"].items(), key=lambda x: x[1][0]):
        if "__TEXT" not in nm:
            continue
        blob = b["data"][fo:fo + fsz]
        n = len(blob) // 4
        for i in range(0, n * 4 - 24, 4):
            w = struct.unpack_from("<I", blob, i)[0]
            if (w & 0x9F000000) != 0x90000000:
                continue
            rd = w & 0x1F
            imm = sx((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3), 21) << 12
            page = u(((vm + i * 4) & ~0xFFF) + imm)
            for j in range(1, 9):
                if i + 4 * j + 4 > len(blob):
                    break
                w2 = struct.unpack_from("<I", blob, i + 4 * j)[0]
                top = w2 & 0xFFC00000
                if top in (0x91000000, 0xB1000000):
                    if ((w2 >> 5) & 0x1F) == rd:
                        sh = 12 if (top == 0xB1000000 and (w2 & 0x80000000)) else 0
                        t = page + (((w2 >> 10) & 0xFFF) << sh)
                        if t == tgt:
                            print("adrp+add %#x [%s] fn %s" %
                                  (vm + i * 4, nm, fn(vm + i * 4)))
                    break
                if top in (0x14000000, 0xB4000000, 0x94000000, 0x12000000,
                           0x54000000, 0xF4000000, 0x52800000, 0x10000000):
                    break
                if (w2 & 0x9F000000) == 0x90000000 and ((w2 & 0x1F) == rd):
                    break


if __name__ == "__main__":
    main(sys.argv)
