#!/usr/bin/env python3
"""Find code/data references to a target VA inside an extracted kext.

Decodes ARM64 ADRP + (ADD imm | LDR imm) pairs by hand (no capstone available),
then reports every instruction site that materialises the target address.
"""
import struct
import sys
import kx


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def sign_extend(v, bits):
    if v & (1 << (bits - 1)):
        v -= (1 << bits)
    return v


def decode_adrp(val, pc):
    if (val & 0x9F000000) != 0x90000000:
        return None
    rd = val & 0x1F
    immlo = (val >> 29) & 0x3
    immhi = (val >> 5) & 0x7FFFF
    imm = sign_extend((immhi << 2) | immlo, 21) << 12
    return rd, (pc & ~0xFFF) + imm


def decode_add_imm(val):
    # ADD (immediate), 64-bit: sf=1 op=0 S=0 10001 shift(2) imm12 Rn Rd
    if (val & 0x7F800000) != 0x11000000:
        return None
    sf = (val >> 31) & 1
    if sf != 1:
        return None
    shift = (val >> 22) & 0x3
    imm12 = (val >> 10) & 0xFFF
    rn = (val >> 5) & 0x1F
    rd = val & 0x1F
    if shift:
        return None  # scaled add; still fine but rare for addresses
    return rd, rn, imm12


def decode_ldr_imm(val):
    # LDR (unsigned immediate) 64-bit: 11111001 11 imm12 Rn Rt
    if (val & 0xFFC00000) != 0xF9400000:
        return None
    imm12 = (val >> 10) & 0xFFF
    rn = (val >> 5) & 0x1F
    rt = val & 0x1F
    return rt, rn, imm12 * 8


def scan(m, targets):
    """targets: set of VAs. returns list of (insn_va, kind, target, text_va)."""
    text = m.sec("__TEXT_EXEC", "__text")
    if not text:
        return []
    data = m.data[text["offset"]:text["offset"] + text["size"]]
    base = text["addr"]
    hits = []
    # map of (page_target, rd) -> (insn_va, rd) for adrp
    pending = {}
    for i in range(0, len(data) - 3, 4):
        val = u32(data, i)
        pc = base + i
        a = decode_adrp(val, pc)
        if a is not None:
            rd, page = a
            pending[(pc, rd)] = page
            continue
        add = decode_add_imm(val)
        ldr = decode_ldr_imm(val)
        if add is not None:
            rd, rn, imm12 = add
            # look back up to 8 instructions for the adp
            for back in range(1, 9):
                pv = pending.get((pc - 4 * back, rn))
                if pv is None:
                    continue
                t = pv + imm12
                if t in targets:
                    hits.append((pc, "add", t, pv))
                break
        elif ldr is not None:
            rt, rn, imm = ldr
            for back in range(1, 9):
                pv = pending.get((pc - 4 * back, rn))
                if pv is None:
                    continue
                t = pv + imm
                if t in targets:
                    hits.append((pc, "ldr", t, pv))
                break
    return hits


def main():
    name = sys.argv[1]
    m = kx.MachO(kx.EXTRACT / name)
    if sys.argv[2] == "--str":
        needle = sys.argv[3].encode()
        targets = set()
        for va, txt in m.cstrings():
            if needle.decode() in txt:
                print(f"string {va:#018x}: {txt}")
                targets.add(va)
    else:
        targets = {int(a, 0) for a in sys.argv[2:]}
    hits = scan(m, targets)
    for pc, kind, t, page in sorted(hits):
        print(f"  {pc:#018x}  {kind}  -> {t:#018x}   (adrp page {page:#018x})")
    print(f"hits: {len(hits)}")


if __name__ == "__main__":
    main()
