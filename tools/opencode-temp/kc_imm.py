#!/usr/bin/env python3
"""Scan the IOSurface kext for LDR/STR with a given unsigned immediate offset.

Prints every instruction that touches [Xn, #imm] (or [Xn, #imm]! scaled) with the
requested displacement, together with the enclosing function, so object layouts
can be mapped statically.
"""
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

sys.path.insert(0, str(Path(__file__).parent))
from kc_iosurface import parse_fileset, member_segments, function_starts

KEXT = "com.apple.iokit.IOSurface"


def load_member(kc_path):
    data = Path(kc_path).read_bytes()
    entries, _ = parse_fileset(data)
    e = [x for x in entries if x["name"] == KEXT][0]
    segs = member_segments(data, e["fileoff"])
    seg = segs.get("__TEXT_EXEC") or segs.get("__TEXT")
    base = seg[0]
    text = data[seg[2]:seg[2] + seg[3]]
    fstarts = function_starts(data, e["fileoff"], e["vmaddr"])
    return base, text, fstarts


def encodings(off):
    """Return [(pattern, mask, kind, scale)] for LDR/STR immediate forms."""
    out = []
    # 64/32-bit unsigned scaled (scale 8)
    for pat, kind in ((0xF9400000, "ldr_x"), (0xB9400000, "ldr_w"),
                      (0xF9000000, "str_x"), (0xB9000000, "str_w")):
        out.append((pat, 0xFFC00000, kind, 8))
    # byte forms (scale 1)
    for pat, kind in ((0x39400000, "ldrb_w"), (0x39000000, "strb_w"),
                      (0x39800000, "ldrb_x")):
        out.append((pat, 0xFFC00000, kind, 1))
    # 16-bit forms (scale 2)
    for pat, kind in ((0x79400000, "ldrh_w"), (0x79000000, "strh_w")):
        out.append((pat, 0xFFC00000, kind, 2))
    return out


def main():
    kc = sys.argv[1]
    off = int(sys.argv[2], 0)
    base, text, fstarts = load_member(kc)
    table = encodings(off)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    hits = []
    for i in range(0, len(text) - 3, 4):
        w = struct.unpack_from("<I", text, i)[0]
        for (pat, mask, kind, scale) in table:
            if (w & mask) != pat:
                continue
            if ((w >> 10) & 0xFFF) != off // scale:
                continue
            if (w & 0x3F000000) == 0x3F000000:  # LDR/STR with register offset
                continue
            hits.append((base + i, kind, w))
            break
    print(f"offset {off:#x}: {len(hits)} hits")
    fset = set(fstarts)
    for (addr, kind, w) in hits:
        prev = None
        for f in fstarts:
            if f > addr:
                break
            prev = f
        for ins in md.disasm(text[addr - base:addr - base + 4], addr):
            print(f"  0x{addr:x}  fn 0x{prev:x}  {kind:<6s} {ins.mnemonic} {ins.op_str}")


if __name__ == "__main__":
    main()
