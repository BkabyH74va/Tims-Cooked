#!/usr/bin/env python3
import re
dis = "/Users/USER/iosurface-kext/dis.txt"
lines = open(dis).read().splitlines()

print("=== all refs to [x19, #0x3b8] ===")
for i, l in enumerate(lines):
    if "#0x3b8" in l:
        print(i, l.strip())

print("\n=== context around each write to #0x3b8 ===")
for i, l in enumerate(lines):
    if "#0x3b8" in l and ("str" in l or "stur" in l):
        lo = max(0, i-18); hi = min(len(lines), i+6)
        print(f"\n--- line {i} ---")
        for j in range(lo, hi):
            print((">>" if j==i else "  "), lines[j].strip())
