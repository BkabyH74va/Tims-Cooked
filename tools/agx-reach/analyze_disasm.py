#!/usr/bin/env python3
"""Analyze disassembly for cred reader patterns."""
import re
from pathlib import Path

disasm_file = Path('G:/REPO/tools/agx-reach/kernel_analysis/text_exec_part1.txt')

with open(disasm_file) as f:
    lines = f.readlines()

print(f"Analyzing {len(lines)} lines of disassembly")

# Pattern 1: Calls to panic (bl panic)
panic_calls = []
for i, line in enumerate(lines):
    if 'bl ' in line and 'panic' in line.lower():
        panic_calls.append((i, line.strip()))
print(f"\n=== Calls to panic: {len(panic_calls)} ===")
for i, line in panic_calls[:20]:
    print(f"  Line {i}: {line[:120]}")

# Pattern 2: CMP w0, #small_number (zone-id check)
cmp_zone = []
for i, line in enumerate(lines):
    if re.search(r'cmp\s+w\d+,\s*#0x[0-9a-fA-F]{1,2}', line):
        cmp_zone.append((i, line.strip()))
print(f"\n=== CMP w?, #small (zone-id checks): {len(cmp_zone)} ===")
for i, line in cmp_zone[:30]:
    print(f"  Line {i}: {line[:120]}")

# Pattern 3: ADRP X8 (RO zone anchor loading)
adrp_x8 = []
for i, line in enumerate(lines):
    if 'adrp' in line and ', x8' in line:
        adrp_x8.append((i, line.strip()))
print(f"\n=== ADRP X8: {len(adrp_x8)} ===")
for i, line in adrp_x8[:30]:
    print(f"  Line {i}: {line[:120]}")

# Pattern 4: LDP X9, X8, [X8] (load RO zone anchor values)
ldp_pattern = []
for i, line in enumerate(lines):
    if 'ldp' in line.lower() and 'x9' in line and 'x8' in line:
        ldp_pattern.append((i, line.strip()))
print(f"\n=== LDP X9, X8, [X8]: {len(ldp_pattern)} ===")
for i, line in ldp_pattern[:30]:
    print(f"  Line {i}: {line[:120]}")

# Pattern 5: MRS TPIDR_EL1 (cred reader start)
# Look for MRS followed by LDR
mrs_ldr = []
for i, line in enumerate(lines):
    if 'mrs' in line.lower() and 'tpidr' in line.lower():
        # Check next few lines for LDR
        for j in range(i+1, min(i+5, len(lines))):
            if 'ldr' in lines[j].lower() and ', [' in lines[j]:
                mrs_ldr.append((i, line.strip(), j, lines[j].strip()))
                break
print(f"\n=== MRS TPIDR + LDR pairs: {len(mrs_ldr)} ===")
for i, line1, j, line2 in mrs_ldr[:20]:
    print(f"  Line {i}: {line1[:100]}")
    print(f"  Line {j}: {line2[:100]}")
