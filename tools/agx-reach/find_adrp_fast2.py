#!/usr/bin/env python3
"""Fast scan for ADRP instructions targeting zone_require_ro string page."""
import struct
from pathlib import Path

TEXT_EXEC_BIN = Path('G:/REPO/tools/agx-reach/kernel_analysis/kernel_text_exec.bin')
TEXT_EXEC_VA = 0xFFFFFE000AB44000

TARGET_PAGE = 0xFFFFFE000705A000  # Page containing zone_require_ro error strings

def main():
    data = TEXT_EXEC_BIN.read_bytes()
    print(f"Scanning {len(data):,} bytes of __TEXT_EXEC")

    hits = []
    pos = 3
    while True:
        pos = data.find(b'\x90', pos)
        if pos == -1:
            break
        # Check if this byte[3] of a 4-byte aligned instruction
        instr_off = pos - 3
        if instr_off < 0 or (instr_off % 4) != 0:
            pos += 1
            continue
        if instr_off + 4 > len(data):
            pos += 1
            continue

        val = struct.unpack_from("<I", data, instr_off)[0]
        # ADRP: bits[31:24] = 0x90 (already checked by finding 0x90 at byte[3])
        # bit[24] = 0 for ADRP (bit[24] is bit 0 of byte[3]... wait, byte[3] = bits[31:24])
        # bit[24] is bit 0 of byte[3], which is bit 0 of 0x90 = 0. So ADRP always has bit[24] = 0.
        # But ADR has bit[24] = 1. 0x90 = 10010000, bit[0] = 0, so it's ADRP.
        # Actually, we already know byte[3] = 0x90, which means bits[31:24] = 10010000.
        # bit[24] = bit 0 of byte[3] = 0, so it's ADRP. Good.

        rd = val & 0x1F
        immhi = (val >> 5) & 0x7FFFF
        immlo = (val >> 31) & 1
        imm = ((immlo << 19) | immhi) << 12
        if imm & (1 << 32):
            imm -= (1 << 33)

        instr_va = TEXT_EXEC_VA + instr_off
        target = instr_va + imm

        if TARGET_PAGE <= target < TARGET_PAGE + 0x1000:
            hits.append((instr_va, rd, target, hex(val)))

        pos += 1

    print(f"\nFound {len(hits)} ADRP instructions targeting page 0x705a000")
    for va, rd, target, hex_val in hits[:50]:
        print(f"  {va:#018x}: ADRP X{rd}, {target:#018x}  ({hex_val})")
    if len(hits) > 50:
        print(f"  ... and {len(hits) - 50} more")

    # Also search for exact string VA 0x705a311
    target_va = 0xFFFFFE000705A311
    hits2 = []
    pos = 3
    while True:
        pos = data.find(b'\x90', pos)
        if pos == -1:
            break
        instr_off = pos - 3
        if instr_off < 0 or (instr_off % 4) != 0:
            pos += 1
            continue
        if instr_off + 4 > len(data):
            pos += 1
            continue

        val = struct.unpack_from("<I", data, instr_off)[0]
        rd = val & 0x1F
        immhi = (val >> 5) & 0x7FFFF
        immlo = (val >> 31) & 1
        imm = ((immlo << 19) | immhi) << 12
        if imm & (1 << 32):
            imm -= (1 << 33)

        instr_va = TEXT_EXEC_VA + instr_off
        target = instr_va + imm

        if target == target_va:
            hits2.append((instr_va, rd, target, hex(val)))

        pos += 1

    print(f"\nFound {len(hits2)} ADRP instructions targeting exact VA 0x705a311")
    for va, rd, target, hex_val in hits2[:20]:
        print(f"  {va:#018x}: ADRP X{rd}, {target:#018x}  ({hex_val})")
