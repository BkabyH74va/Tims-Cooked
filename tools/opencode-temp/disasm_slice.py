#!/usr/bin/env python3
"""Print a slice of iosurface_27_0_1.disasm.txt between two addresses (inclusive)."""
import sys

PATH = r"G:/REPO\tools\opencode-temp\iosurface_27_0_1.disasm.txt"

start = sys.argv[1].lower().lstrip("0x")
end = sys.argv[2].lower().lstrip("0x") if len(sys.argv) > 2 else None

lines = open(PATH, "r", encoding="utf-8", errors="replace").read().splitlines()

def addr(line):
    p = line.split(None, 1)
    return p[0].lower() if p else ""

out = []
started = False
for line in lines:
    a = addr(line)
    if not started:
        if a == start:
            started = True
        else:
            continue
    if end is not None and a >= end:
        break
    out.append(line)

print("\n".join(out))
print("--- lines:", len(out))
