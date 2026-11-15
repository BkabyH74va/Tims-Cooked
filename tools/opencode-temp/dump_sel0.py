#!/usr/bin/env python3
import re
dis = "/Users/USER/iosurface-kext/dis.txt"
lines = open(dis).read().splitlines()

target = 0xfffffe000a345114
print(f"=== around {target:#x} ===")
started = False
for i, l in enumerate(lines):
    m = re.match(r'\s*(fffffe[0-9a-f]+):', l)
    if not m: continue
    a = int(m.group(1), 16)
    if a < target - 8: continue
    if a > target + 0x180: break
    print(l.strip())
