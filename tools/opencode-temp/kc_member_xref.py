#!/usr/bin/env python3
"""Per-member ADRP+ADD / ADRP+LDR reference finder (numpy-free).

Scans every MH_FILESET member's own __TEXT* segments word-by-word, tracks ADRP
page registers, and reports every instruction site whose computed VA equals the
target. Attributing sites to LC_FUNCTION_STARTS boundaries is done when the
member's starts are available.

Usage:
    python kc_member_xref.py <build> <va_hex> [more va_hex ...]
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, r"G:/iOS 27.0.1/iOS/tools/opencode-temp")
sys.path.insert(0, r"G:/iOS 27.0.1/iOS/tools/pylibs")
from kc_iosurface import parse_fileset, member_segments, member_load_commands  # noqa: E402

BASE = Path(r"G:/iOS 27.0.1/iOS/firmware")
MASK = (1 << 64) - 1


def u(x):
    return x & MASK


def sx(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def func_starts(data, foff, text_base):
    out = []
    try:
        for cmd, eoff, cmdsize in member_load_commands(data, foff):
            if cmd != 0x26:
                continue
            dataoff = struct.unpack_from("<I", data, eoff + 8)[0]
            size = struct.unpack_from("<I", data, eoff + 12)[0]
            p, end = dataoff, dataoff + size
            addr = 0
            while p < end:
                val = 0
                shift = 0
                while True:
                    b = data[p]
                    p += 1
                    val |= (b & 0x7F) << shift
                    if not (b & 0x80):
                        break
                    shift += 7
                if val == 0:
                    break
                addr += val
                out.append(text_base + addr)
    except Exception:                                             # noqa: BLE001
        pass
    return sorted(set(out))


def main(argv):
    build = argv[1]
    targets = {int(a, 16) for a in argv[2:]}
    data = (BASE / build / "kernelcache.release.macho").read_bytes()
    entries, _ = parse_fileset(data)
    print("build %s: %d members, targets %s" % (
        build, len(entries), ", ".join("%#x" % t for t in sorted(targets))))
    hits = []
    for e in entries:
        segs = member_segments(data, e["fileoff"])
        starts = func_starts(data, e["fileoff"], segs.get("__TEXT", (0, 0, 0, 0))[0])
        for nm, (vm, vsz, fo, fsz) in sorted(segs.items()):
            if "__TEXT" not in nm:
                continue
            blob = data[fo:fo + fsz]
            pages = {}
            n = len(blob) // 4
            for i in range(0, n * 4 - 3, 4):
                w = struct.unpack_from("<I", blob, i)[0]
                va = vm + i
                top = w >> 24
                if (w & 0x9F000000) == 0x90000000:               # ADRP
                    rd = w & 0x1F
                    immlo = (w >> 29) & 3
                    immhi = (w >> 5) & 0x7FFFF
                    imm = sx((immhi << 2) | immlo, 21) << 12
                    pages[rd] = u(va + imm)
                elif (w & 0xFF800000) == 0x91000000:             # ADD (imm, 64-bit)
                    rn = (w >> 5) & 0x1F
                    rd = w & 0x1F
                    imm = (w >> 10) & 0xFFF
                    sh = 12 if (w & 0x400000) else 0
                    if rn in pages:
                        tgt = u(pages[rn] + (imm << sh))
                        if tgt in targets:
                            hits.append((tgt, e["name"], nm, va, starts, w))
                elif (w & 0xFFC00000) == 0xF9400000:             # LDR xt,[xn,#simm]
                    rn = (w >> 5) & 0x1F
                    rt = w & 0x1F
                    imm = ((w >> 10) & 0xFFF) * 8
                    if rn in pages:
                        tgt = u(pages[rn] + imm)
                        if tgt in targets:
                            hits.append((tgt, e["name"], nm, va, starts, w))
                    pages.pop(rt, None)
                elif top == 0xAA or top == 0x2A:                 # MOV/MOVN clears tracking
                    rd = w & 0x1F
                    pages.pop(rd, None)
    if not hits:
        print("no direct ADRP+ADD/LDR references found")
    for tgt, name, nm, va, starts, w in hits:
        fn = None
        if starts:
            import bisect
            j = bisect.bisect_right(starts, va) - 1
            if j >= 0:
                fn = starts[j]
        print("  target %#x  site %#x  member %-52s seg %-14s word %08x  func %s"
              % (tgt, va, name, nm, w, ("%#x" % fn) if fn else "?"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
