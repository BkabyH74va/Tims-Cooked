#!/usr/bin/env python3>
"""Examine all MRS->LDR pairs for cred reader pattern."""
import struct
from pathlib import Path

KERNEL_BASE = 0xFFFFFE0007000000
ANALYSIS_DIR = Path("G:/REPO/tools/agx-reach/kernel_analysis")

def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def main():
    combined = (ANALYSIS_DIR / "all_exec.bin").read_bytes()
    print(f"Scanning {len(combined):,} bytes of kernel exec code")

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

    # Find all MRS->LDR X1,[X0,#imm] pairs
    pairs = []
    for i in range(0, len(combined) - 7, 4):
        val1 = read_u32(combined, i)
        if (val1 & 0xFF000000) == 0xD5000000 and not (val1 & (1 << 21)):
            val2 = read_u32(combined, i + 4)
            if (val2 & 0xFFE003E0) == 0xF9400000:
                rn = (val2 >> 5) & 0x1F
                rt = val2 & 0x1F
                imm12 = (val2 >> 10) & 0xFFF
                if rn == 0 and rt == 1:
                    pairs.append((i, imm12))

    print(f"Found {len(pairs)} MRS->LDR X1,[X0,#imm] pairs\n")
    
    # Sort by offset (largest first - t_tro is likely at a large offset)
    pairs.sort(key=lambda x: -x[1])
    
    for idx, (mrs_off, imm12) in enumerate(pairs):
        va, name = va_from_off(mrs_off)
        
        # Check if followed by ADRP X8 (RO zone anchor loading)
        has_anchor = False
        for j in range(1, 8):  # Check next 7 instructions
            check_off = mrs_off + j * 4
            if check_off + 4 > len(combined):
                break
            check_val = read_u32(combined, check_off)
            # ADRP X8: bits [31:24] = 0x90, Rd = 8 (bits [4:0] = 01000)
            if (check_val & 0xFF00001F) == 0x90000008:
                has_anchor = True
                break
        
        marker = " <-- possible cred reader (has ADRP)" if has_anchor else ""
        print(f"  {idx:2d}. {va:#018x} LDR X1,[X0,#0x{imm12:x}] ({imm12}) in {name}{marker}")

if __name__ == "__main__":
    main()
