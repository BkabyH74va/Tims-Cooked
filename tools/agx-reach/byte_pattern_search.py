#!/usr/bin/env python3
"""Byte pattern search in kernel exec regions for fg_cred/so_cred lead.

Searches for:
1. MRS to TPIDR_EL1 (cred reader prologue) - multiple possible encodings
2. LDR with offset 0x418 (t_tro offset from d94ap) or 0x18 (p_proc_ro offset)
3. ADRP+ADD+LDR sequence (RO zone anchor loading)
"""
import struct
from pathlib import Path

KERNEL_BASE = 0xFFFFFE0007000000
ANALYSIS_DIR = Path("G:/REPO/tools/agx-reach/kernel_analysis")

def find_all(data, pattern):
    """Find all occurrences of pattern in data, return offsets."""
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

    # 1. Search for 0x418 (t_tro offset on d94ap) as little-endian bytes
    # This might appear as part of an LDR immediate encoding
    print("\n=== Searching for 0x0418 (t_tro offset on d94ap) as LE bytes ===")
    pattern_418 = struct.pack("<H", 0x418)
    hits_418 = find_all(combined, pattern_418)
    print(f"Found {len(hits_418)} occurrences of 0x18 0x04")
    for off in hits_418[:20]:
        # Find which region this is in
        for va_start, va_end, name, blob_off in regions:
            if blob_off <= off < blob_off + (va_end - va_start):
                va = va_start + (off - blob_off)
                print(f"  {va:#018x} (file off {off:#x}) in {name}")
                break
    if len(hits_418) > 20:
        print(f"  ... and {len(hits_418) - 20} more")

    # 2. Search for 0x0018 (p_proc_ro offset on d94ap)
    print("\n=== Searching for 0x0018 (p_proc_ro offset on d94ap) as LE bytes ===")
    pattern_18 = struct.pack("<H", 0x18)
    hits_18 = find_all(combined, pattern_18)
    print(f"Found {len(hits_18)} occurrences of 0x18 0x00")
    for off in hits_18[:20]:
        for va_start, va_end, name, blob_off in regions:
            if blob_off <= off < blob_off + (va_end - va_start):
                va = va_start + (off - blob_off)
                print(f"  {va:#018x} (file off {off:#x}) in {name}")
                break
    if len(hits_18) > 20:
        print(f"  ... and {len(hits_18) - 20} more")

    # 3. Search for ADRP X8 pattern: byte 3 = 0x90, byte 2 low bits = 01000 (Rd=8)
    # In LE: byte3=0x90, byte2 has Rd=8 in bits [7:3]
    print("\n=== Searching for ADRP X8 (byte3=0x90, byte2 low bits = 01000) ===")
    adrp_hits = []
    for i in range(3, len(combined)):
        if combined[i] == 0x90:
            b2 = combined[i - 1]
            # Check if bits [7:3] of byte 2 == 01000 (Rd=8)
            if (b2 >> 3) == 0b01000:
                off = i - 3
                for va_start, va_end, name, blob_off in regions:
                    if blob_off <= off < blob_off + (va_end - va_start):
                        va = va_start + (off - blob_off)
                        adrp_hits.append((va, name, off))
                        break
    print(f"Found {len(adrp_hits)} potential ADRP X8 instructions")
    for va, name, off in adrp_hits[:30]:
        print(f"  {va:#018x} (file off {off:#x}) in {name}")
    if len(adrp_hits) > 30:
        print(f"  ... and {len(adrp_hits) - 30} more")


if __name__ == "__main__":
    main()
