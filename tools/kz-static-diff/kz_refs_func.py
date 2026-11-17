#!/usr/bin/env python3
"""Map ADRP+ADD/LDR reference sites in a VA range to their containing functions.

Numpy-free. Uses LC_FUNCTION_STARTS of the com.apple.kernel member, so every
reported site carries a real function start and extent; a range whose refs all
land in one contiguous code block is a self-contained subsystem, not an
app-facing dispatch surface.

Usage: python kz_refs_func.py <build> <lo_hex> <hi_hex>
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
from kc_fstarts import load_build, func_of  # noqa: E402

BASE = ROOT / "firmware"


def segments(d):
    ncmds = struct.unpack_from("<I", d, 16)[0]
    off = 32
    out = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", d, off)
        if cmd == 0x19:
            nm = d[off + 8:off + 24].rstrip(b"\0").decode(errors="replace")
            vm, vsz, fo, fsz = struct.unpack_from("<QQQQ", d, off + 24)
            out.append((nm, vm, vsz, fo, fsz))
        off += cmdsize
    return out


def u(x):
    return x & ((1 << 64) - 1)


def sx(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def main():
    bld, lo, hi = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16)
    b = load_build(bld)
    d = (BASE / bld / "kernelcache.release.macho").read_bytes()
    segs = segments(d)
    hits = []
    for nm, vm, vsz, fo, fsz in segs:
        if "__TEXT" not in nm:
            continue
        blob = d[fo:fo + fsz]
        pages = {}
        for i in range(0, len(blob) - 3, 4):
            w = struct.unpack_from("<I", blob, i)[0]
            cur = vm + i
            if (w & 0x9F000000) == 0x90000000:
                rd = w & 0x1F
                imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3)
                pages[rd] = (cur & ~0xFFF) + (sx(imm, 21) << 12)
                continue
            matched = False
            if (w & 0xFF800000) == 0x91000000:
                rn = (w >> 5) & 0x1F
                if rn in pages:
                    imm = ((w >> 10) & 0xFFF) << ((w >> 22) & 3)
                    tgt = pages[rn] + imm
                    if lo <= u(tgt) < hi:
                        hits.append(u(cur))
                    pages[w & 0x1F] = tgt
                    matched = True
            elif (w & 0xFFC00000) in (0xF9400000, 0xB9400000, 0x39400000,
                                      0xF8400000, 0xB8400000):
                rn = (w >> 5) & 0x1F
                if rn in pages:
                    tgt = pages[rn] + (((w >> 10) & 0xFFF) << ((w >> 30) & 3))
                    if lo <= u(tgt) < hi:
                        hits.append(u(cur))
                    matched = True
            if matched:
                continue
            if (w & 0xFC000000) in (0xAA000000, 0x2A000000, 0x53000000,
                                    0x73000000, 0x93400000, 0x93C00000,
                                    0x0B000000, 0x2B000000, 0x4B000000):
                pages.pop(w & 0x1F, None)
    import bisect
    starts = b["starts"]
    byfn = {}
    for site in sorted(set(hits)):
        i = bisect.bisect_right(starts, site) - 1
        if i < 0:
            continue
        f = starts[i]
        byfn.setdefault(f, []).append(site)
    print("%s: %d ref sites -> %d distinct functions in %#x..%#x"
          % (bld, len(set(hits)), len(byfn), lo, hi))
    for f in sorted(byfn):
        i = bisect.bisect_right(starts, f) - 1
        end = starts[i + 1] if i + 1 < len(starts) else f + 0x4000
        print("  fn %#x sz %#x  refs=%d" % (f, end - f, len(byfn[f])))


if __name__ == "__main__":
    main()
