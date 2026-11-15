#!/usr/bin/env python3
import re
dis = "/Users/USER/iosurface-kext/dis.txt"
lines = open(dis).read().splitlines()

def in_range(l, lo, hi):
    m = re.match(r'\s*(fffffe[0-9a-f]+):', l)
    if not m: return False
    a = int(m.group(1), 16) & 0xffffffff
    return lo <= a <= hi

print("=== parser region a32cc00..a32ce00 ===")
for l in lines:
    if in_range(l, 0xa32cc00, 0xa32ce00):
        print(l.strip())

print("\n=== error block e180..e1d0 ===")
for l in lines:
    if in_range(l, 0xa32e180, 0xa32e1d0):
        print(l.strip())

print("\n=== error block e440..e4d0 ===")
for l in lines:
    if in_range(l, 0xa32e440, 0xa32e4d0):
        print(l.strip())
