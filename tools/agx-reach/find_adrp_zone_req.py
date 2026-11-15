#!/usr/bin/env python3
"""Search kernel __TEXT_EXEC for adrp instructions targeting zone_require_ro string page."""
import struct
from pathlib import Path

KERNEL_BASE = 0xFFFFFE0007000000
ANALYSIS_DIR = Path('G:/REPO/tools/agx-reach/kernel_analysis')

def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def decode_adrp(val):
    """Decode ADRP instruction: return (Rd, immhi, immlo) or None."""
    # ADRP: 1001000x | immhi(19) | 0 | Rd(5)
    # x = 0 for ADRP
    if (val & 0xFF000000) != 0x90000000:
        return None
    # Check bit[24] = 0 for ADRP (bit[24] is bit 0 of byte 3 in LE)
    # Actually, ADRP has bit[31]=1, bit[30]=0, bit[29]=0, bit[28]=1, bit[27]=0, bit[26]=0, bit[25]=0, bit[24]=x
    # where x=0 for ADRP
    # Bits[31:24] = 1001000x => 0x90 for ADRP, 0x91 for ADR
    if (val & 0x01000000) != 0:  # bit[24] = 1 means ADR, not ADRP
        return None
    rd = val & 0x1F
    immhi = (val >> 5) & 0x7FFFF
    immlo = (val >> 31) & 1
    imm = ((immlo << 19) | immhi) << 12
    # Sign extend
    if imm & (1 << 32):
        imm -= (1 << 33)
    return rd, immhi, immlo, imm


def main():
    combined = (ANALYSIS_DIR / "all_exec.bin").read_bytes()
    print(f"Scanning {len(combined):,} bytes of kernel exec code")

    # Target page: 0xfffffe000705a000 (contains zone_require_ro error strings)
    target_page = 0xfffffe000705a000

    # Region mapping
    regions = [
        (0xFFFFFE000700C000, 0xFFFFFE0007DC8000, "__PRELINK_TEXT.__text", 0),
        (0xFFFFFE0008498000, 0xFFFFFE000B448000, "__TEXT_EXEC", 0xDC8000),
        (0xFFFFFE000B448000, 0xFFFFFE000B450000, "__TEXT_BOOT_EXEC", 0xDC8000 + 0x2FB0000),
    ]

    def va_from_off(off):
        for va_start, va_end, name, blob_off in regions:
            if blob_off <= off < blob_off + (va_end - va_start):
                return va_start + (off - blob_off), name
        return None, None

    hits = []
    for i in range(0, len(combined) - 3, 4):
        val = read_u32(combined, i)
        result = decode_adrp(val)
        if result is None:
            continue
        rd, immhi, immlo, imm = result
        instr_va = None
        instr_name = None
        for va_start, va_end, name, blob_off in regions:
            blob_off_i = blob_off + i
            if blob_off_i < blob_off + (va_end - va_start):
                instr_va = va_start + i
                instr_name = name
                break
        if instr_va is None:
            continue

        target = instr_va + imm
        if target_page <= target < target_page + 0x1000:
            hits.append((instr_va, instr_name, rd, target, hex(val)))

    print(f"\nFound {len(hits)} ADRP instructions targeting page 0x705a000")
    for va, name, rd, target, hex_val in hits[:50]:
        print(f"  {va:#018x} ({name}): ADRP X{rd}, {target:#018x}  encoding={hex_val}")
    if len(hits) > 50:
        print(f"  ... and {len(hits) - 50} more")

    # Also search for the specific string address 0x705a311
    target_va = 0xfffffe000705a311
    hits2 = []
    for i in range(0, len(combined) - 3, 4):
        val = read_u32(combined, i)
        result = decode_adrp(val)
        if result is None:
            continue
        rd, immhi, immlo, imm = result
        instr_va = None
        for va_start, va_end, name, blob_off in regions:
            blob_off_i = blob_off + i
            if blob_off_i < blob_off + (va_end - va_start):
                instr_va = va_start + i
                break
        if instr_va is None:
            continue

        target = instr_va + imm
        if target == target_va:
            hits2.append((instr_va, name, rd, target, hex(val)))

    print(f"\nFound {len(hits2)} ADRP instructions targeting exact VA 0x705a311")
    for va, name, rd, target, hex_val in hits2[:20]:
        print(f"  {va:#018x} ({name}): ADRP X{rd}, {target:#018x}")
