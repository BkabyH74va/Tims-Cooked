#!/usr/bin/env python3
"""Search kernel exec regions for fg_cred/so_cred lead patterns.

Targets on iPhone18,1/V53AP/t8150/iOS 27.0.1 (24A446):
- Find mrs x0, tpidr_el1 (start of cred readers)
- Find cmp w?, #3 / cmp w?, #5 (zone id checks for thread_ro/proc_ro)
- Find ldr from struct offsets that could be fg_cred/so_cred
"""
import struct
from pathlib import Path

KERNEL_BASE = 0xFFFFFE0007000000
ANALYSIS_DIR = Path("G:/REPO/tools/agx-reach/kernel_analysis")

# MRS X0, TPIDR_EL1 encoding: op0=3, op1=0, CRn=0, CRm=0, op2=0, Rt=0
# Binary: 1101010100 11 000 0000 0000 000 00000 = 0xD5180000
MRS_TPIDR_EL1_X0 = 0xD5180000

# Common struct offsets to check (XNU typical values)
# fileglob.fg_cred and socket.so_cred offsets vary by iOS version
FG_CRED_CANDIDATES = [0x58, 0x60, 0x68, 0x70, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8]
SO_CRED_CANDIDATES = [0x58, 0x60, 0x68, 0x70, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8]

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
    
    # 1. Search for MRS X0, TPIDR_EL1 (cred reader start)
    print("\n=== Searching for MRS X0, TPIDR_EL1 (cred reader prologue) ===")
    mrs_hits = []
    for va_start, va_end, name, blob_off in regions:
        region_data = combined[blob_off:blob_off + (va_end - va_start)]
        for i in range(0, len(region_data) - 3, 4):
            val = read_u32(region_data, i)
            if val == MRS_TPIDR_EL1_X0:
                instr_va = va_start + i
                mrs_hits.append((instr_va, name))
    print(f"Found {len(mrs_hits)} MRS X0, TPIDR_EL1 instructions")
    for va, name in mrs_hits[:20]:
        print(f"  {va:#018x} in {name}")
    if len(mrs_hits) > 20:
        print(f"  ... and {len(mrs_hits) - 20} more")
    
    # 2. Search for CMP W?, #3 and CMP W?, #5 (zone id checks)
    print("\n=== Searching for CMP W?, #3 and CMP W?, #5 (zone id checks) ===")
    # CMP W?, #imm: 0b11110100100 | imm16(5) | 0 | Rn(5) | sf(1) | opcode(5)
    # For CMP W8, #3: 0x1100043F? Let me just search for common patterns
    # CMP W8, #3: 11110100100 00011 0 01000 1 00111 = 0x1100043F? No...
    # Let me just search for all CMP W?, #imm where imm is 3 or 5
    # CMP (immediate) encoding: 11110100100 | imm16 | 0 | Rn | 1 | 00111
    # imm16 is bits 5-20, Rn is bits 0-4, sf is bit 31
    # For 32-bit: sf=0, opcode bits [31:22]=1111010010, bit 21=0
    # Encoding: 0x11000000 | (imm16 << 5) | (Rn << 0) | (0 << 31) ... wait this is wrong
    
    # Let me use a different approach: search for the raw bytes of common CMP patterns
    # CMP W8, #3: 0x1100 043F? No.
    # Let me just search for 0x??00??3F patterns where bits [31:22] = 0b1111010010
    
    cmp3_hits = []
    cmp5_hits = []
    for va_start, va_end, name, blob_off in regions:
        region_data = combined[blob_off:blob_off + (va_end - va_start)]
        for i in range(0, len(region_data) - 3, 4):
            val = read_u32(region_data, i)
            opcode_top = (val >> 22) & 0x3FF  # bits [31:22]
            if opcode_top == 0b1111010010:  # CMP immediate
                imm16 = (val >> 5) & 0xFFFF
                rn = val & 0x1F
                sf = (val >> 31) & 1
                if sf == 0:  # 32-bit
                    if imm16 == 3:
                        instr_va = va_start + i
                        cmp3_hits.append((instr_va, rn, name))
                    elif imm16 == 5:
                        instr_va = va_start + i
                        cmp5_hits.append((instr_va, rn, name))
    
    print(f"Found {len(cmp3_hits)} CMP W?, #3 instructions")
    for va, rn, name in cmp3_hits[:20]:
        print(f"  {va:#018x} CMP W{rn}, #3 in {name}")
    if len(cmp3_hits) > 20:
        print(f"  ... and {len(cmp3_hits) - 20} more")
    
    print(f"Found {len(cmp5_hits)} CMP W?, #5 instructions")
    for va, rn, name in cmp5_hits[:20]:
        print(f"  {va:#018x} CMP W{rn}, #5 in {name}")
    if len(cmp5_hits) > 20:
        print(f"  ... and {len(cmp5_hits) - 20} more")
    
    # 3. Search for LDR from struct offsets that could be fg_cred/so_cred
    print("\n=== Searching for LDR from candidate fg_cred/so_cred offsets ===")
    # LDR X1, [X0, #imm]: 0b11111000010 | imm12(9) | 0 | Rn(5) | Rt(5)
    # Actually LDR (unsigned immediate): 11111000010 | imm12 | 0 | Rn | Rt
    # For LDR X1, [X0, #off]: Rn=0, Rt=1, off=various
    
    ldr_cred_hits = []
    for va_start, va_end, name, blob_off in regions:
        region_data = combined[blob_off:blob_off + (va_end - va_start)]
        for i in range(0, len(region_data) - 3, 4):
            val = read_u32(region_data, i)
            opcode_top = (val >> 22) & 0x3FF
            if opcode_top == 0b1111100001:  # LDR (unsigned immediate)
                imm12 = (val >> 10) & 0xFFF
                rn = (val >> 5) & 0x1F
                rt = val & 0x1F
                # Looking for LDR X1, [X0, #off] where off is a candidate
                if rn == 0 and rt == 1 and imm12 in FG_CRED_CANDIDATES:
                    instr_va = va_start + i
                    ldr_cred_hits.append((instr_va, imm12, name))
    
    print(f"Found {len(ldr_cred_hits)} LDR X1, [X0, #candidate_offset] instructions")
    for va, off, name in ldr_cred_hits[:30]:
        print(f"  {va:#018x} LDR X1, [X0, #{off}] (0x{off:x}) in {name}")
    if len(ldr_cred_hits) > 30:
        print(f"  ... and {len(ldr_cred_hits) - 30} more")


if __name__ == "__main__":
    main()
