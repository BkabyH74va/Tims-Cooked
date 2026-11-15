#!/usr/bin/env python3
"""Search for ANY MRS instruction (top byte 0xD5) and analyze system register accesses."""
import struct
from pathlib import Path

KERNEL_BASE = 0xFFFFFE0007000000
ANALYSIS_DIR = Path("G:/REPO/tools/agx-reach/kernel_analysis")

def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def find_all(data, predicate):
    """Find all offsets where predicate(u32_value) is True."""
    offsets = []
    for i in range(0, len(data) - 3, 4):
        val = struct.unpack_from("<I", data, i)[0]
        if predicate(val):
            offsets.append(i)
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

    # Search for any MRS instruction (top byte 0xD5)
    # MRS encoding: bits [31:24] = 0xD5, bit [21] = 0 (distinguishes MRS from MSR)
    # Actually: bits [31:24] = 0xD5 for both MRS and MSR
    # Bit [21] distinguishes: 0 = MRS, 1 = MSR
    
    print("\n=== Searching for any MRS instruction (top byte 0xD5) ===")
    mrs_hits = []
    for i in range(0, len(combined) - 3, 4):
        val = read_u32(combined, i)
        if (val & 0xFF000000) == 0xD5000000:
            # Bit 21 = 0 for MRS
            if not (val & (1 << 21)):
                mrs_hits.append((i, val))
    print(f"Found {len(mrs_hits)} MRS instructions")
    
    # Decode system registers
    sysreg_names = {}
    for off, val in mrs_hits[:50]:
        op0 = (val >> 20) & 0x3
        op1 = (val >> 16) & 0xF
        crn = (val >> 12) & 0xF
        crm = (val >> 8) & 0xF
        op2 = (val >> 5) & 0x7
        rt = val & 0x1F
        va, name = va_from_off(off)
        key = (op0, op1, crn, crm, op2)
        if key not in sysreg_names:
            sysreg_names[key] = []
        sysreg_names[key].append((va, rt, name))
    
    print(f"\nUnique system register combinations (first 50 MRS hits):")
    for key, hits in list(sysreg_names.items())[:20]:
        op0, op1, crn, crm, op2 = key
        print(f"  op0={op0} op1={op1} CRn={crn} CRm={crm} op2={op2}: {len(hits)} hits, e.g. {hits[0][0]:#018x} Rt=X{hits[0][1]}")

    # Now search for LDR X1, [X0, #imm] following any MRS
    print("\n=== MRS followed by LDR from X0 ===")
    mrs_ldr_pairs = []
    for i in range(0, len(combined) - 7, 4):
        val1 = read_u32(combined, i)
        if (val1 & 0xFF000000) == 0xD5000000 and not (val1 & (1 << 21)):
            val2 = read_u32(combined, i + 4)
            # LDR X1, [X0, #imm12]: 11111000010 | imm12 | 0 | Rn(0) | Rt(1)
            if (val2 & 0xFFE003E0) == 0xF9400000:
                rn = (val2 >> 5) & 0x1F
                rt = val2 & 0x1F
                imm12 = (val2 >> 10) & 0xFFF
                if rn == 0 and rt == 1:
                    mrs_ldr_pairs.append((i, imm12))
    print(f"Found {len(mrs_ldr_pairs)} MRS->LDR X1,[X0,#imm] pairs")
    for off, imm12 in mrs_ldr_pairs[:30]:
        va, name = va_from_off(off)
        print(f"  {va:#018x} LDR X1,[X0,#0x{imm12:x}] in {name}")
    if len(mrs_ldr_pairs) > 30:
        print(f"  ... and {len(mrs_ldr_pairs) - 30} more")


if __name__ == "__main__":
    main()
