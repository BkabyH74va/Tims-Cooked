#!/usr/bin/env python3
"""Read UTF-16LE disassembly and search for key patterns."""
from pathlib import Path

DISASM = Path("G:/REPO/analysis/agx/2701.disasm.txt")

with open(DISASM, "r", encoding="utf-16-le") as f:
    lines = f.readlines()

print(f"Total lines: {len(lines)}")

# Search for adrp to page containing site.AGXDeviceUserClient (0xfffffe000712c122 -> page 0xfffffe000712c000)
print("\n=== adrp to page 0xfffffe000712c000 (contains site.AGXDeviceUserClient) ===")
for i, line in enumerate(lines):
    if "adrp" in line and "0xfffffe000712c000" in line:
        # Print context
        start = max(0, i - 2)
        end = min(len(lines), i + 5)
        for j in range(start, end):
            marker = ">>> " if j == i else "    "
            print(f"{marker}{j+1:6d}: {lines[j].rstrip()}")
        print()

# Search for calls to helper function (0xfffffe0008556f50 or f54)
print("\n=== Calls/branches to helper 0xfffffe0008556f5* ===")
for i, line in enumerate(lines):
    if "0xfffffe0008556f5" in line and ("bl " in line or "b " in line or "blr" in line):
        print(f"{i+1:6d}: {lines[i].rstrip()}")

# Search for AGXDeviceUserClient references via adrp
print("\n=== All adrp instructions targeting 0xfffffe000712c* (cstring page) ===")
for i, line in enumerate(lines):
    if "adrp" in line and "0xfffffe000712c" in line:
        print(f"{i+1:6d}: {lines[i].rstrip()}")
