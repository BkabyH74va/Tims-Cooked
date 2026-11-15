#!/usr/bin/env python3
"""Analyze disassembly part 2 with UTF-16LE encoding."""
import re
from pathlib import Path

disasm_file = Path('G:/REPO/tools/agx-reach/kernel_analysis/text_exec_part2.txt')

with open(disasm_file, 'r', encoding='utf-16-le') as f:
    lines = f.readlines()

print(f"Analyzing {len(lines)} lines of disassembly")

# Pattern 1: bl calls
bl_calls = []
for i, line in enumerate(lines):
    if '\tbl\t' in line or '\tbl ' in line:
        bl_calls.append((i, line.strip()))
print(f"\n=== BL calls: {len(bl_calls)} ===")
for i, line in bl_calls[:20]:
    print(f"  Line {i}: {line[:120]}")

# Pattern 2: cmp w?, #imm
cmp_imm = []
for i, line in enumerate(lines):
    if '\tcmp\tw' in line.lower():
        cmp_imm.append((i, line.strip()))
print(f"\n=== CMP w?, #imm: {len(cmp_imm)} ===")
for i, line in cmp_imm[:30]:
    print(f"  Line {i}: {line[:120]}")

# Pattern 3: adrp x8
adrp_x8 = []
for i, line in enumerate(lines):
    if '\tadrp\tx8,' in line.lower():
        adrp_x8.append((i, line.strip()))
print(f"\n=== ADRP X8: {len(adrp_x8)} ===")
for i, line in adrp_x8[:30]:
    print(f"  Line {i}: {line[:120]}")

# Pattern 4: mrs tpidr_el1
mrs_t1 = []
for i, line in enumerate(lines):
    if '\tmrs\tx' in line.lower() and 'tpidr_el1' in line.lower():
        mrs_t1.append((i, line.strip()))
print(f"\n=== MRS X?, TPIDR_EL1: {len(mrs_t1)} ===")
for i, line in mrs_t1[:20]:
    print(f"  Line {i}: {line[:120]}")

# Pattern 5: msr tpidr_el1
msr_t1 = []
for i, line in enumerate(lines):
    if '\tmsr\ttpidr_el1' in line.lower():
        msr_t1.append((i, line.strip()))
print(f"\n=== MSR TPIDR_EL1: {len(msr_t1)} ===")
for i, line in msr_t1[:20]:
    print(f"  Line {i}: {line[:120]}")

# Pattern 6: ldr x?, [x0, #0x418]
ldr_418 = []
for i, line in enumerate(lines):
    if 'ldr' in line.lower() and '#0x418' in line:
        ldr_418.append((i, line.strip()))
print(f"\n=== LDR from offset 0x418: {len(ldr_418)} ===")
for i, line in ldr_418[:20]:
    print(f"  Line {i}: {line[:120]}")

# Pattern 7: ldr x?, [x0, #0x18]
ldr_18 = []
for i, line in enumerate(lines):
    if 'ldr' in line.lower() and '#0x18' in line:
        ldr_18.append((i, line.strip()))
print(f"\n=== LDR from offset 0x18: {len(ldr_18)} ===")
for i, line in ldr_18[:20]:
    print(f"  Line {i}: {line[:120]}")
