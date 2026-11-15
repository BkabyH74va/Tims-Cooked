#!/usr/bin/env python3
"""Scan kernel exec regions for callers of known cred functions."""
import struct
from pathlib import Path

KERNEL_BASE = 0xFFFFFE0007000000
ANALYSIS_DIR = Path("G:/REPO/tools/agx-reach/kernel_analysis")

# Target addresses we're looking for
TARGETS = {
    0xFFFFFE000AC4B5A0: "t_tro_reader",
    0xFFFFFE000B0DB174: "p_proc_ro_reader",
    0xFFFFFE000B411164: "zone_require_ro",
}

def va_to_region_offset(va):
    """Convert kernel VA to offset in combined exec blob."""
    # __PRELINK_TEXT.__text: va=0xfffffe000700c000 size=0xdc8000 off=0x8000 (file)
    # In our combined blob, we just concatenated regions, so we need to track
    # which region each VA falls into
    pass

def find_calls_in_blob(blob_data, blob_base_va, target_va, target_name):
    """Find all bl/b instructions targeting target_va within blob_data."""
    rel = (target_va - blob_base_va) & 0xFFFFFFFFFFFFFFFF
    # bl encoding: 0x98000000 | imm26 (26 bits, shifted by 2)
    # b encoding:  0x18000000 | imm26
    imm26 = (rel >> 2) & 0x3FFFFFFF
    # Check sign extension: imm26 should be sign-extended from 26 bits
    if imm26 & 0x20000000:
        imm26_signed = imm26 - 0x40000000
    else:
        imm26_signed = imm26
    
    bl_opcode = 0x98000000 | imm26
    b_opcode = 0x18000000 | imm26
    
    hits = []
    for i in range(0, len(blob_data) - 3, 4):
        val = struct.unpack_from("<I", blob_data, i)[0]
        if val == bl_opcode or val == b_opcode:
            instr_va = blob_base_va + i
            instr_type = "BL" if val == bl_opcode else "B "
            hits.append((instr_va, instr_type, target_name))
    return hits


def main():
    combined = (ANALYSIS_DIR / "all_exec.bin").read_bytes()
    print(f"Combined exec blob: {len(combined):,} bytes")
    
    # Region mapping: (va_start, va_end, name, offset_in_blob)
    regions = [
        (0xFFFFFE000700C000, 0xFFFFFE0007DC8000, "__PRELINK_TEXT.__text", 0),
        (0xFFFFFE0008498000, 0xFFFFFE000B448000, "__TEXT_EXEC", 0xDC8000),
        (0xFFFFFE000B448000, 0xFFFFFE000B450000, "__TEXT_BOOT_EXEC", 0xDC8000 + 0x2FB0000),
    ]
    
    all_hits = []
    for target_va, target_name in TARGETS.items():
        print(f"\nSearching for callers of {target_name} at {target_va:#018x}")
        for va_start, va_end, name, blob_off in regions:
            if not (va_start <= target_va < va_end):
                continue
            # The target is in this region
            rel_in_region = target_va - va_start
            offset_in_blob = blob_off + rel_in_region
            
            # Find all calls to this target from within this region
            region_data = combined[blob_off:blob_off + (va_end - va_start)]
            hits = find_calls_in_blob(region_data, va_start, target_va, target_name)
            print(f"  In {name}: {len(hits)} direct calls")
            for instr_va, instr_type, tn in hits[:20]:
                print(f"    {instr_va:#018x} {instr_type} {tn}")
            if len(hits) > 20:
                print(f"    ... and {len(hits) - 20} more")
            all_hits.extend(hits)
    
    print(f"\n{'='*60}")
    print(f"TOTAL direct call hits: {len(all_hits)}")
    
    # Also search for calls to zone_require_ro across ALL regions (it could be called from anywhere)
    print(f"\n{'='*60}")
    print("Searching zone_require_ro callers across all exec regions...")
    zr_va = 0xFFFFFE000B411164
    zr_rel_in_region = zr_va - 0xFFFFFE0008498000  # It's in __TEXT_EXEC
    zr_region_data = combined[0xDC8000:0xDC8000 + 0x2FB0000]
    zr_hits = find_calls_in_blob(zr_region_data, 0xFFFFFE0008498000, zr_va, "zone_require_ro")
    print(f"  zone_require_ro callers: {len(zr_hits)}")
    for instr_va, instr_type, tn in zr_hits[:30]:
        print(f"    {instr_va:#018x} {instr_type} {tn}")
    if len(zr_hits) > 30:
        print(f"    ... and {len(zr_hits) - 30} more")


if __name__ == "__main__":
    main()
