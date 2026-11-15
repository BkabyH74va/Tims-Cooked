#!/usr/bin/env python3
"""Show cached disassembly lines around a VA from the disasm cache.

Usage: showat.py <member> <va> [count]
"""
import re
import sys
from pathlib import Path

import dis

name = sys.argv[1]
va = int(sys.argv[2], 0)
cnt = int(sys.argv[3]) if len(sys.argv) > 3 else 40

p = dis.disasm(name, "__TEXT_EXEC.__text")
lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
rx = re.compile(r"^0x([0-9a-f]+):")
out = []
for l in lines:
    mm = rx.match(l)
    if mm:
        out.append((int(mm.group(1), 16), l))
out.sort(key=lambda x: x[0])
lo = va - cnt * 4
hi = va + cnt * 4
for a, l in out:
    if lo <= a <= hi:
        mark = ">>" if a == va else "  "
        print(f"{mark} {l}")
