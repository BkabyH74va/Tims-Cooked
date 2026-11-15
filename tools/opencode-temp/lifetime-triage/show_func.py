#!/usr/bin/env python3
"""Show disassembly around an address and find the enclosing function start."""
import re, sys

DIS = r"G:/REPO\tools\opencode-temp\lifetime-triage\disasm\com_apple_driver_AppleJPEGDriver.__TEXT_EXEC___text.txt"
target = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xfffffe000900cac0
span = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x120

lines = open(DIS, "r", errors="replace").read().splitlines()
rows = []
for l in lines:
    m = re.match(r"\s*(?:0x)?(fffffe[0-9a-f]+):", l)
    if m:
        rows.append((int(m.group(1), 16), l.rstrip()))

idx = None
for i, (a, l) in enumerate(rows):
    if a == target:
        idx = i
        break
if idx is None:
    # nearest
    for i, (a, l) in enumerate(rows):
        if a >= target:
            idx = i
            break
print(f"=== around 0x{target:x} (line {idx}) ===")
for a, l in rows[max(0, idx - 40): idx + 40]:
    print(l)

# find preceding function starts
print("\n=== preceding bti c / pacibsp starts ===")
prev = None
for i, (a, l) in enumerate(rows):
    if a > target:
        break
    if "bti\tc" in l or "pacibsp" in l:
        prev = (a, l)
print(prev)
