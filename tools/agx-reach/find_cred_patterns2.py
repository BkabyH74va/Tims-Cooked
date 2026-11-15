#!/usr/bin/env python3
"""Search kernel exec for distinctive cred reader patterns.

Pattern: adrp x8, <page>; add x8, x8, #<offset>; ldp/ldr x9, [x8]
This loads the RO zone anchor for range checking.
"""
import struct
from pathlib import Path

KERNEL_BASE = 0xFFFFFE0007000000
ANALYSIS_DIR = Path("G:/REPO/tools/agx-reach/kernel_analysis")

def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def main():
    combined = (ANALYSIS_DIR / "all_exec.bin").read_bytes()
    print(f"Scanning {len(combined):,} bytes of kernel exec code")

    # Region mapping
    regions = [
        (0xFFFFFE000700C000, 0xFFFFFE0007DC8000, "__PRELINK_TEXT.__text", 0),
        (0xFFFFFE0008498000, 0xFFFFFE000B448000, "__TEXT_EXEC", 0xDC8000),
        (0xFFFFFE000B448000, 0xFFFFFE000B450000, "__TEXT_BOOT_EXEC", 0xDC8000 + 0x2FB0000),
    ]

    # LDP X9, X8, [X8] = 0xF8402508
    # LDR X9, [X8] = 0xF8400109
    LDP_X9_X8_X8 = 0xF8402508
    LDR_X9_X8 = 0xF8400109

    # ADRP X8, <page> = 0x90000000 | immhi
    # ADD X8, X8, #<offset> = 0x91000000 | shift | imm12 | Rn(8) | Rd(8)
    
    print("\n=== Searching for LDP X9, X8, [X8] (RO zone anchor load) ===")
    ldp_hits = []
    for va_start, va_end, name, blob_off in regions:
        region_data = combined[blob_off:blob_off + (va_end - va_start)]
        for i in range(0, len(region_data) - 3, 4):
            val = read_u32(region_data, i)
            if val == LDP_X9_X8_X8:
                instr_va = va_start + i
                ldp_hits.append((instr_va, name))
    print(f"Found {len(ldp_hits)} LDP X9, X8, [X8] instructions")
    for va, name in ldp_hits[:30]:
        print(f"  {va:#018x} in {name}")
    if len(ldp_hits) > 30:
        print(f"  ... and {len(ldp_hits) - 30} more")

    print("\n=== Searching for LDR X9, [X8] (RO zone anchor load, single) ===")
    ldr_hits = []
    for va_start, va_end, name, blob_off in regions:
        region_data = combined[blob_off:blob_off + (va_end - va_start)]
        for i in range(0, len(region_data) - 3, 4):
            val = read_u32(region_data, i)
            if val == LDR_X9_X8:
                instr_va = va_start + i
                ldr_hits.append((instr_va, name))
    print(f"Found {len(ldr_hits)} LDR X9, [X8] instructions")
    for va, name in ldr_hits[:30]:
        print(f"  {va:#018x} in {name}")
    if len(ldr_hits) > 30:
        print(f"  ... and {len(ldr_hits) - 30} more")

    # 3. Search for ADRP X8 pattern (loading a page address)
    print("\n=== Searching for ADRP X8 (page address load) ===")
    # ADRP encoding: 100100 | immlo(1) | immhi(19) | 0 | Rd(5)
    # = 0x90000000 | (immhi << 5) | Rd
    # For X8: Rd=8
    # We search for any ADRP with Rd=8
    adrp_x8_hits = []
    for va_start, va_end, name, blob_off in regions:
        region_data = combined[blob_off:blob_off + (va_end - va_start)]
        for i in range(0, len(region_data) - 3, 4):
            val = read_u32(region_data, i)
            # Check if it's ADRP (bits [31:24] = 1001000x)
            if (val & 0xFF000000) == 0x90000000:
                rd = val & 0x1F
                if rd == 8:
                    instr_va = va_start + i
                    adrp_x8_hits.append((instr_va, name))
    print(f"Found {len(adrp_x8_hits)} ADRP X8 instructions")
    for va, name in adrp_x8_hits[:30]:
        print(f"  {va:#018x} in {name}")
    if len(adrp_x8_hits) > 30:
        print(f"  ... and {len(adrp_x8_hits) - 30} more")


if __name__ == "__main__":
    main()
