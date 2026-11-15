#!/usr/bin/env python3
"""Scan kernel exec regions for BL/B instructions targeting known addresses."""
import struct
from pathlib import Path

KERNEL_BASE = 0xFFFFFE0007000000
ANALYSIS_DIR = Path("G:/REPO/tools/agx-reach/kernel_analysis")

# Target addresses we're looking for (from iPhone17,2/d94ap research - may differ on t8150)
TARGET_VAS = {
    0xFFFFFE000AC4B5A0: "t_tro_reader",
    0xFFFFFE000B0DB174: "p_proc_ro_reader", 
    0xFFFFFE000B411164: "zone_require_ro",
}

def scan_blob_for_calls(blob_data, blob_base_va, target_vas):
    """Find all BL/B instructions whose computed target matches any target_va."""
    hits = []
    for i in range(0, len(blob_data) - 3, 4):
        val = struct.unpack_from("<I", blob_data, i)[0]
        instr_va = blob_base_va + i
        
        # Check if it's a BL (0b100101) or B (0b000101)
        opcode = (val >> 26) & 0x3F
        if opcode == 0b100101:  # BL
            instr_type = "BL"
        elif opcode == 0b000101:  # B
            instr_type = "B "
        else:
            continue
        
        # Extract imm26 (bits 0-25)
        imm26 = val & 0x3FFFFFF
        # Sign-extend 26-bit to 64-bit
        if imm26 & 0x2000000:  # bit 25 is sign bit
            imm26_signed = imm26 - 0x4000000
        else:
            imm26_signed = imm26
        
        # Target = instruction address + (imm26 << 2)
        target = instr_va + (imm26_signed << 2)
        
        if target in target_vas:
            hits.append((instr_va, instr_type, target_vas[target], target))
    
    return hits


def main():
    combined = (ANALYSIS_DIR / "all_exec.bin").read_bytes()
    print(f"Combined exec blob: {len(combined):,} bytes")
    
    # Region mapping
    regions = [
        (0xFFFFFE000700C000, 0xFFFFFE0007DC8000, "__PRELINK_TEXT.__text", 0),
        (0xFFFFFE0008498000, 0xFFFFFE000B448000, "__TEXT_EXEC", 0xDC8000),
        (0xFFFFFE000B448000, 0xFFFFFE000B450000, "__TEXT_BOOT_EXEC", 0xDC8000 + 0x2FB0000),
    ]
    
    all_hits = []
    for va_start, va_end, name, blob_off in regions:
        region_data = combined[blob_off:blob_off + (va_end - va_start)]
        hits = scan_blob_for_calls(region_data, va_start, TARGET_VAS)
        print(f"\n{name}: {len(hits)} direct branch hits to known targets")
        for instr_va, instr_type, target_name, target_va in hits[:30]:
            print(f"  {instr_va:#018x} {instr_type} -> {target_name} ({target_va:#018x})")
        if len(hits) > 30:
            print(f"  ... and {len(hits) - 30} more")
        all_hits.extend(hits)
    
    print(f"\n{'='*60}")
    print(f"TOTAL direct branch hits: {len(all_hits)}")
    
    # Save hits to file for further analysis
    out = ANALYSIS_DIR / "cred_caller_hits.txt"
    with open(out, "w") as f:
        for instr_va, instr_type, target_name, target_va in all_hits:
            f.write(f"{instr_va:#018x} {instr_type} -> {target_name} ({target_va:#018x})\n")
    print(f"Saved to {out}")


if __name__ == "__main__":
    main()
