#!/usr/bin/env python3
import re, sys

dis = "/Users/USER/iosurface-kext/dis.txt"
lines = open(dis).read().splitlines()

TARGETS = {
    0xfffffe0007a1a033: "KEY  IOSurfacePlaneHeaderRegionBytesPerSlice",
    0xfffffe0007a1db81: "MSG  ... %d exeeds maximum value.",
    0xfffffe0007a1dbcf: "MSG  ... %d is smaller than expected value",
    0xfffffe0007a1dc2b: "MSG  ... must be present for multi-slice plane",
}

adrp = {}
hits = []
for i, l in enumerate(lines):
    m = re.search(r'adrp\s+(x\d+), (0x[0-9a-f]+)', l)
    if m:
        adrp[m.group(1)] = int(m.group(2), 16)
        continue
    m2 = re.search(r'add\s+(x\d+), (x\d+), #(0x[0-9a-f]+|[0-9]+)', l)
    if m2:
        dst, src, imm = m2.group(1), m2.group(2), int(m2.group(3), 0)
        if src in adrp:
            addr = adrp[src] + imm
            if addr in TARGETS:
                hits.append((i, addr, l.strip()))

print(f"hits: {len(hits)}")
for i, addr, l in hits:
    print(f"\n--- line {i}  {TARGETS[addr]}  @{hex(addr)} ---")
    lo = max(0, i - 14)
    hi = min(len(lines), i + 10)
    for j in range(lo, hi):
        mark = ">>" if j == i else "  "
        print(f"{mark} {lines[j]}")
