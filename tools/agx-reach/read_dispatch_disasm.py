#!/usr/bin/env python3
"""
Read disassembly around key addresses to understand dispatch logic.
"""
from pathlib import Path

DISASM = Path("G:/REPO/analysis/agx/2701.disasm.txt")

with open(DISASM, "r", encoding="utf-16-le") as f:
    lines = f.readlines()

def print_context(line_num, context=30):
    """Print lines around a given line number."""
    start = max(0, line_num - context - 1)
    end = min(len(lines), line_num + context)
    print(f"\n=== Lines {start+1}-{end} (centered on {line_num}) ===")
    for i in range(start, end):
        marker = ">>> " if i == line_num - 1 else "    "
        print(f"{marker}{i+1:5d}: {lines[i].rstrip()[:140]}")

# Key addresses from the disassembly
key_addresses = [
    0xfffffe00084e864c,  # cmp w24, #0x100 at line 56124
    0xfffffe00084e87e8,  # cmp w8, #0x100 at line 56227
    0xfffffe00084e888c,  # cmp w24, #0x100 at line 56268
    0xfffffe00084e88a4,  # cmp w24, #0x100 at line 56274
    0xfffffe00084e890c,  # cmp w24, #0x100 at line 56300
    0xfffffe00084f4ef8,  # cmp x8, #0x101 at line 68967
    0xfffffe00084f501c,  # cmp x8, #0x101 at line 69040
]

# Find line numbers for each address
addr_to_line = {}
for i, line in enumerate(lines):
    # Parse address from line like "0xfffffe00084e864c:  ..."
    parts = line.split(":")
    if len(parts) >= 1:
        try:
            addr = int(parts[0].strip(), 16)
            addr_to_line[addr] = i + 1
        except ValueError:
            pass

for addr in key_addresses:
    line_num = addr_to_line.get(addr)
    if line_num:
        print_context(line_num, context=40)
    else:
        print(f"\nAddress {addr:#018x} not found in disassembly")
