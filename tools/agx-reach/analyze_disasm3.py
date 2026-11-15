#!/usr/bin/env python3
"""Analyze disassembly part 2 with corrected patterns."""
import re
from pathlib import Path

disasm_file = Path('G:/REPO/tools/agx-reach/kernel_analysis/text_exec_part2.txt')

with open(disasm_file) as f:
    lines = f.readlines()

print(f"Analyzing {len(lines)} lines of disassembly")

# Pattern 1: bl (branch with link) calls
bl_calls = []
for i, line in enumerate(lines):
    if re.search(r'\bbl\s+0x', line):
        bl_calls.append((i, line.strip()))
print(f"\n=== BL calls: {len(bl_calls)} ===")
for i, line in bl_calls[:30]:
    print(f"  Line {i}: {line[:120]}")

# Pattern 2: cmp w?, #imm (comparisons)
cmp_imm = []
for i, line in enumerate(lines):
    m = re.search(r'cmp\s+w\d+,\s*#', line)
    if m:
        cmp_imm.append((i, line.strip()))
print(f"\n=== CMP w?, #imm: {len(cmp_imm)} ===")
for i, line in cmp_imm[:30]:
    print(f"  Line {i}: {line[:120]}")

# Pattern 3: adrp x8
adrp_x8 = []
for i, line in enumerate(lines):
    if re.search(r'\badrp\s+x8,', line):
        adrp_x8.append((i, line.strip()))
print(f"\n=== ADRP X8: {len(adrp_x8)} ===")
for i, line in adrp_x8[:30]:
    print(f"  Line {i}: {line[:120]}")

# Pattern 5: mrs tpidr_el1
mrs_tpidr1 = []
for i, line in enumerate(lines):
    if 'mrs' in line.lower() and 'tpidr_el1' in line.lower():
        mrs_tpidr1.append((i, line.strip()))
print(f"\n=== MRS tpidr_el1: {len(mrs_tpidr1)} ===")
for i, line in mrs_tpidr1[:20]:
    print(f"  Line {i}: {line[:120]}")

# Pattern 6: mrs tpidr_el0
mrs_tpidr0 = []
for i, line in enumerate(lines):
    if 'mrs' in line.lower() and 'tpidr_el0' in line.lower():
        mrs_tpidr0.append((i, line.strip()))
print(f"\n=== MRS tpidr_el0: {len(mrs_tpidr0)} ===")
for i, line in mrs_tpidr0[:20]:
    print(f"  Line {i}: {line[:120]}")

# Pattern 7: msr tpidr_el1
msr_tpidr1 = []
for i, line in enumerate(lines):
    if 'msr' in line.lower() and 'tpidr_el1' in line.lower():
        msr_tpidr1.append((i, line.strip()))
print(f"\n=== MSR tpidr_el1: {len(msr_tpidr1)} ===")
for i, line in msr_tpidr1[:20]:
    print(f"  Line {i}: {line[:120]}")
