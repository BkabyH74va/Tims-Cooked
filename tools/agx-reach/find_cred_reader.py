#!/usr/bin/env python3
"""Search kernel exec for MRS TPIDR_EL1 (cred reader prologue) and related patterns."""
import struct
from pathlib import Path

KERNEL_BASE = 0xFFFFFE0007000000
ANALYSIS_DIR = Path("G:/REPO/tools/agx-reach/kernel_analysis")

def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def find_all(data, pattern):
    offsets = []
    start = 0
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def main():
    combined = (ANALYSIS_DIR / "all_exec.bin").read_bytes()
    print(f"Scanning {len(combined):,} bytes of kernel exec code")

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

    # 1. Search for MRS X0, TPIDR_EL1: encoding 0xD5300D40
    # Bytes (LE): 40 0D 30 D5
    print("\n=== Searching for MRS X0, TPIDR_EL1 (0xD5300D40) ===")
    mrs_pattern = struct.pack("<I", 0xD5300D40)
    mrs_hits = find_all(combined, mrs_pattern)
    print(f"Found {len(mrs_hits)} MRS X0, TPIDR_EL1 instructions")
    for off in mrs_hits[:30]:
        va, name = va_from_off(off)
        print(f"  {va:#018x} (file off {off:#x}) in {name}")
    if len(mrs_hits) > 30:
        print(f"  ... and {len(mrs_hits) - 30} more")

    # 2. For each MRS hit, check if followed by LDR X1, [X0, #imm]
    print("\n=== Checking MRS+LDR pairs (cred reader prologue) ===")
    mrs_ldr_pairs = []
    for off in mrs_hits:
        # Check next instruction
        if off + 4 < len(combined):
            next_val = read_u32(combined, off + 4)
            # LDR X1, [X0, #imm12]: 11111000010 | imm12 | 0 | Rn(0) | Rt(1)
            # = 0xF9400000 | (imm12 << 10) | (0 << 5) | 1
            # Actually encoding: 11111000010 imm12 0 Rn Rt
            # Rn=0 (X0), Rt=1 (X1)
            # imm12 is unsigned byte offset
            if (next_val & 0xFFE003E0) == 0xF9400000:
                rn = (next_val >> 5) & 0x1F
                rt = next_val & 0x1F
                imm12 = (next_val >> 10) & 0xFFF
                if rn == 0 and rt == 1:
                    mrs_ldr_pairs.append((off, imm12))
    print(f"Found {len(mrs_ldr_pairs)} MRS+LDR X1,[X0,#imm] pairs")
    for mrs_off, imm12 in mrs_ldr_pairs[:20]:
        va, name = va_from_off(mrs_off)
        print(f"  MRS at {va:#018x}, LDR X1,[X0,#0x{imm12:x}] in {name}")
    if len(mrs_ldr_pairs) > 20:
        print(f"  ... and {len(mrs_ldr_pairs) - 20} more")

    # 3. Search for ADRP X8 followed by ADD X8 followed by LDP/LDR
    print("\n=== Searching for ADRP X8; ADD X8,X8; LDP/LDR pattern ===")
    # ADRP X8: 0x90000000 | (immhi << 5) | 8
    # ADD X8, X8, #imm: 0x91000000 | shift | imm12 | 8 | 8
    # LDP X9, X8, [X8]: 0xF8402508
    # LDR X9, [X8]: 0xF8400109
    
    adrp_ldp_hits = []
    for i in range(3, len(combined) - 7, 4):
        val = read_u32(combined, i)
        # ADRP X8: bits [31:24] = 1001000x, Rd = 8 (bits [4:0] = 01000)
        if (val & 0xFF00001F) == 0x90000008:
            # Next instruction: ADD X8, X8, #imm
            val2 = read_u32(combined, i + 4)
            # ADD (unsigned immediate): 1001000 | shift | imm12 | Rn | Rd
            # = 0x91000000 | (shift << 22) | (imm12 << 10) | (Rn << 5) | Rd
            if (val2 & 0xFFC003E0) == 0x91000008:  # ADD X8, X8, #imm
                # Next: LDP X9, X8, [X8] or LDR X9, [X8]
                val3 = read_u32(combined, i + 8)
                if val3 == 0xF8402508 or val3 == 0xF8400109:
                    va, name = va_from_off(i)
                    adrp_ldp_hits.append((i, val, val2, val3, name))
    
    print(f"Found {len(adrp_ldp_hits)} ADRP X8; ADD X8,X8; LDP/LDR sequences")
    for off, v1, v2, v3, name in adrp_ldp_hits[:20]:
        va, _ = va_from_off(off)
        print(f"  {va:#018x} in {name}: ADRP={v1:#010x} ADD={v2:#010x} LDP/LDR={v3:#010x}")
    if len(adrp_ldp_hits) > 20:
        print(f"  ... and {len(adrp_ldp_hits) - 20} more")


if __name__ == "__main__":
    main()
