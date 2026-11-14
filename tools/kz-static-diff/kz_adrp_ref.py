#!/usr/bin/env python3
"""Find code sites that build a given VM address with ADRP+ADD (or ADRP+LDR).

Usage: kz_adrp_ref.py <build> <va_hex>
"""
import struct
import sys
from pathlib import Path

import numpy as np

BASE = Path(Path(__file__).resolve().parents[2] / "firmware")


def segments(d):
    ncmds = struct.unpack_from('<I', d, 16)[0]
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', d, off)
        if cmd == 0x19:
            nm = d[off + 8:off + 24].rstrip(b'\0').decode(errors='replace')
            vm, vsz, fo, fsz = struct.unpack_from('<QQQQ', d, off + 24)
            segs.append((nm, vm, vsz, fo, fsz))
        off += cmdsize
    return segs


def u(x):
    return x & ((1 << 64) - 1)


def sx(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def main():
    bld = sys.argv[1]
    target = int(sys.argv[2], 16)
    d = (BASE / bld / "kernelcache.release.macho").read_bytes()
    segs = segments(d)
    hits = []
    for nm, vm, vsz, fo, fsz in segs:
        if "__TEXT" not in nm:
            continue
        blob = d[fo:fo + fsz]
        n = len(blob) - (len(blob) % 4)
        arr = np.frombuffer(blob[:n], dtype='<u4')
        va = (vm + np.arange(0, n, 4, dtype=np.uint64)).astype(np.int64)

        # walk forward maintaining last ADRP page per register
        pages = {}
        for i in range(len(arr)):
            w = int(arr[i])
            cur = int(va[i])
            if (w & 0x9F000000) == 0x90000000:
                rd = w & 0x1F
                imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3)
                pages[rd] = (cur & ~0xFFF) + (sx(imm, 21) << 12)
                continue
            matched = False
            if (w & 0xFF800000) == 0x91000000:  # ADD (imm)
                rn = (w >> 5) & 0x1F
                if rn in pages:
                    imm = ((w >> 10) & 0xFFF) << ((w >> 22) & 3)
                    tgt = pages[rn] + imm
                    if u(tgt) == u(target):
                        hits.append(("add", u(cur)))
                    pages[w & 0x1F] = tgt
                    matched = True
            elif (w & 0xFFC00000) in (0xF9400000, 0xB9400000, 0x39400000,
                                     0xF8400000, 0xB8400000):
                rn = (w >> 5) & 0x1F
                if rn in pages:
                    tgt = pages[rn] + (((w >> 10) & 0xFFF) << ((w >> 30) & 3))
                    if u(tgt) == u(target):
                        hits.append(("ldr", u(cur)))
                    matched = True
            if matched:
                continue
            # conservative invalidation: clear dst reg for common writing ops
            if (w & 0xFC000000) in (0xAA000000, 0x2A000000, 0x53000000,
                                    0x73000000, 0x93400000, 0x93C00000,
                                    0x0B000000, 0x2B000000, 0x4B000000):
                pages.pop(w & 0x1F, None)
    print(f"{bld}: {len(hits)} ADRP+ADD/LDR refs to {target:#x}")
    for kind, site in hits[:40]:
        print(f"   {kind} at {site:#x}")


if __name__ == "__main__":
    main()
