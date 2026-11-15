#!/usr/bin/env python3
"""Find direct BL/B call sites to target addresses in a cached disassembly.

Usage: callers.py <member> <target_va> [target_va ...]
"""
import re
import sys
import dis

name = sys.argv[1]
targets = {int(t, 0): [] for t in sys.argv[2:]}

p = dis.disasm(name, "__TEXT_EXEC.__text")
lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
rx = re.compile(r"^0x([0-9a-f]+):\s+(?:[0-9a-f]{2} ){4}\s*(\S+)\s*(.*)$")
for l in lines:
    m = rx.match(l)
    if not m:
        continue
    addr = int(m.group(1), 16)
    mn = m.group(2)
    ops = m.group(3).split(";")[0].strip().replace("\t", " ")
    if mn not in ("bl", "b", "braa", "blraa", "b.eq", "b.ne", "b.hi", "b.lo",
                  "b.ls", "b.hs", "b.ge", "b.gt", "b.mi", "b.pl", "b.cs", "b.cc",
                  "b.vs", "b.vc", "cbnz", "cbz", "tbz", "tbnz"):
        continue
    mm = re.match(r"(0x[0-9a-f]+)", ops)
    if not mm:
        continue
    try:
        t = int(mm.group(1), 16)
    except ValueError:
        continue
    if t in targets:
        targets[t].append((addr, mn, ops))

for t, hits in targets.items():
    if hits:
        print(f"{t:#018x}:")
        for a, mn, ops in hits:
            print(f"    {a:#018x}  {mn} {ops}")
    else:
        print(f"{t:#018x}: no direct call site found")
