#!/usr/bin/env python3
import re

dis = "/Users/USER/iosurface-kext/dis.txt"
lines = open(dis).read().splitlines()

# 1. direct immediate hits for the message strings
print("=== message-string immediates ===")
for i, l in enumerate(lines):
    if re.search(r'#0xb81\b|#0xbcf\b|#0xc2b\b', l):
        print(i, l.strip())

# 2. find function start before the key reference (line 7537)
start = 7537
for j in range(start, 0, -1):
    if re.search(r'\bpacibsp\b', lines[j]) or re.search(r'sub\s+sp, sp, #0x', lines[j]):
        print(f"\n=== candidate prologue at line {j} ===")
        print(lines[j].strip())
        break

print("\n=== function body (from prologue) ===")
lo = j
hi = min(len(lines), lo + 220)
for k in range(lo, hi):
    print(lines[k])
