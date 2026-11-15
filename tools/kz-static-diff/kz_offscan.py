#!/usr/bin/env python3
"""Scan the whole com.apple.kernel member for LDR/STR at a given unsigned
immediate offset. Prints the instruction and the enclosing LC_FUNCTION_STARTS
function, so object-layout semantics can be mapped statically.

Usage: kz_offscan.py <build> <offset_hex>
"""
import struct
import sys
from pathlib import Path

ROOT = Path("G:/REPO")
sys.path.insert(0, str(ROOT / "tools/opencode-temp"))
sys.path.insert(0, str(ROOT / "tools/pylibs"))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from kc_iosurface import parse_fileset, member_segments, function_starts


def encodings(off):
    out = []
    for pat, kind, scale in ((0xF9400000, "ldr_x", 8), (0xB9400000, "ldr_w", 4),
                             (0xF9000000, "str_x", 8), (0xB9000000, "str_w", 4),
                             (0x39400000, "ldrb_w", 1), (0x39000000, "strb_w", 1),
                             (0x39800000, "ldrb_x", 1),
                             (0x79400000, "ldrh_w", 2), (0x79000000, "strh_w", 2)):
        out.append((pat, 0xFFC00000, kind, scale))
    return out


def main():
    bld = sys.argv[1]
    off = int(sys.argv[2], 16)
    p = ROOT / "firmware" / bld / "kernelcache.release.macho"
    d = p.read_bytes()
    entries, _ = parse_fileset(d)
    e = [x for x in entries if x["name"] == "com.apple.kernel"][0]
    segs = member_segments(d, e["fileoff"])
    seg = segs.get("__TEXT_EXEC") or segs.get("__TEXT")
    base = seg[0]
    text = d[seg[2]:seg[2] + seg[3]]
    fstarts = sorted(function_starts(d, e["fileoff"], e["vmaddr"]))
    import bisect
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    hits = []
    for i in range(0, len(text) - 3, 4):
        w = struct.unpack_from("<I", text, i)[0]
        for (pat, mask, kind, scale) in encodings(off):
            if off % scale:
                continue
            if (w & mask) != pat:
                continue
            if ((w >> 10) & 0xFFF) != off // scale:
                continue
            if (w & 0x3F000000) == 0x3F000000:
                continue
            hits.append((base + i, kind, w))
            break
    print(f"{bld} offset {off:#x}: {len(hits)} hits")
    for addr, kind, w in hits[:80]:
        fi = bisect.bisect_right(fstarts, addr) - 1
        owner = fstarts[fi] if fi >= 0 else None
        for ins in md.disasm(text[addr - base:addr - base + 4], addr):
            print(f"  0x{addr:x} fn 0x{owner:x} {kind:<6s} {ins.mnemonic} {ins.op_str}")


if __name__ == "__main__":
    main()
