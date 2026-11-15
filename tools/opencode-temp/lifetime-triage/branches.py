#!/usr/bin/env python3
"""Find branch instructions whose target falls in a given address range.

Handles conditional branches (cbz/tbz/b.eq/...) where the target is not the
first operand, as well as b/bl/braa.

Usage: branches.py <member> <lo_va> <hi_va>
"""
import re
import sys
import dis

name = sys.argv[1]
lo = int(sys.argv[2], 0)
hi = int(sys.argv[3], 0)

p = dis.disasm(name, "__TEXT_EXEC.__text")
lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
rx = re.compile(r"^0x([0-9a-f]+):\s+(?:[0-9a-f]{2} ){4}\s*(\S+)\s*(.*)$")
hexrx = re.compile(r"0x[0-9a-f]{6,}")
for l in lines:
    m = rx.match(l)
    if not m:
        continue
    addr = int(m.group(1), 16)
    mn = m.group(2)
    ops = m.group(3).split(";")[0].strip().replace("\t", " ")
    if not mn.startswith("b") and mn not in ("cbz", "cbnz", "tbz", "tbnz"):
        continue
    targets = [int(t, 16) for t in hexrx.findall(ops)]
    for t in targets:
        if lo <= t < hi:
            print(f"{addr:#018x}  {mn:8s} {ops}   -> {t:#018x}")
            break
