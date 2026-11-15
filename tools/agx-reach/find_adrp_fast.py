#!/usr/bin/env python3
"""Efficiently scan kernel __TEXT_EXEC for adrp instructions targeting zone_require_ro string page."""
import struct
from pathlib import Path

KERNEL_BASE = 0xFFFFFE0007000000
TEXT_EXEC_BIN = Path('G:/REPO/tools/agx-reach/kernel_analysis/kernel_text_exec.bin')
TEXT_EXEC_VA = 0xFFFFFE000AB44000  # VA of __TEXT_EXEC in extracted kernel

def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def decode_adrp(val):
    """Decode ADRP instruction."""
    if (val & 0xFF000000) != 0x90000000:
        return None
    if (val & 0x01000000) != 0:  # bit[24] = 1 means ADR, not ADRP
        return None
    rd = val & 0x1F
    immhi = (val >> 5) & 0x7FFFF
    immlo = (val >> 31) & 1
    imm = ((immlo << 19) | immhi) << 12
    if imm & (1 << 32):
        imm -= (1 << 33)
    return rd, imm


def main():
    data = TEXT_EXEC_BIN.read_bytes()
    print(f"Scanning {len(data):,} bytes of __TEXT_EXEC")

    target_page = 0xFFFFFE000705A000  # Page containing zone_require_ro error strings

    hits = []
    # Search for ADRP: byte[3] == 0x90 at 4-byte aligned offsets
    for i in range(3, len(data) - 3, 4):
        if data[i + 3] != 0x90:
            continue
        val = read_u32(data, i)
        result = decode_adrp(val)
        if result is None:
            continue
        rd, imm = result
        instr_va = TEXT_EXEC_VA + i
        target = instr_va + imm
        if target_page <= target < target_page + 0x1000:
            hits.append((instr_va, rd, target, hex(val)))

    print(f"\nFound {len(hits)} ADRP instructions targeting page 0x705a000")
    for va, rd, target, hex_val in hits[:50]:
        print(f"  {va:#018x}: ADRP X{rd}, {target:#018x}  ({hex_val})")
    if len(hits) > 50:
        print(f"  ... and {len(hits) - 50} more")

    # Also search for exact string VA 0x705a311
    target_va = 0xFFFFFE000705A311
    hits2 = []
    for i in range(3, len(data) - 3, 4):
        if data[i + 3] != 0x90:
            continue
        val = read_u32(data, i)
        result = decode_adrp(val)
        if result is None:
            continue
        rd, imm = result
        instr_va = TEXT_EXEC_VA + i
        target = instr_va + imm
        if target == target_va:
            hits2.append((instr_va, rd, target, hex(val)))

    print(f"\nFound {len(hits2)} ADRP instructions targeting exact VA 0x705a311")
    for va, rd, target, hex_val in hits2[:20]:
        print(f"  {va:#018x}: ADRP X{rd}, {target:#018x}  ({hex_val})")
