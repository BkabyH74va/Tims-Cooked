#!/usr/bin/env python3
"""Show cached disassembly lines in [start, end) address range.

Usage: showrange.py <member> <start_va> <end_va>
"""
import re
import sys
from pathlib import Path

import dis

name = sys.argv[1]
lo = int(sys.argv[2], 0)
hi = int(sys.argv[3], 0)

p = dis.disasm(name, "__TEXT_EXEC.__text")
lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
rx = re.compile(r"^0x([0-9a-f]+):")
out = []
for l in lines:
    mm = rx.match(l)
    if mm:
        out.append((int(mm.group(1), 16), l))
out.sort(key=lambda x: x[0])
for a, l in out:
    if lo <= a < hi:
        print(l)
