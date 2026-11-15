#!/usr/bin/env python3
"""
Read disassembly around AGXG18P externalMethod dispatch to understand
argument sizes for each selector.
"""
from pathlib import Path

DISASM = Path("G:/REPO/analysis/agx/2701.disasm.txt")

with open(DISASM, "r", encoding="utf-16-le") as f:
    lines = f.readlines()

def print_context(addr, context=80):
    """Print disassembly around a given address."""
    # Find line with this address
    target = f"{addr:#018x}:"
    line_num = None
    for i, line in enumerate(lines):
        if line.startswith(target):
            line_num = i + 1
            break
    
    if line_num is None:
        print(f"Address {addr:#018x} not found")
        return
    
    start = max(0, line_num - context - 1)
    end = min(len(lines), line_num + context)
    print(f"\n=== Lines {start+1}-{end} (around {addr:#018x}) ===")
    for i in range(start, end):
        marker = ">>> " if i == line_num - 1 else "    "
        print(f"{marker}{i+1:5d}: {lines[i].rstrip()[:150]}")

# Key addresses from the dispatch logic
addrs = [
    0xfffffe00084e85ac,   # Start of dispatch function area
    0xfffffe00084e864c,   # cmp w24, #0x100 (first comparison)
    0xfffffe00084e87e4,   # Handler for selector 0x100
    0xfffffe00084e88ac,   # Handler for selector 0x100 (alt)
    0xfffffe00084e8914,   # Handler for other selectors
]

for addr in addrs:
    print_context(addr, context=50)
