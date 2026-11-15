#!/usr/bin/env python3
"""Find ldr/str instructions referencing a given immediate offset.

Usage: immrefs.py <member> <offset_hex> [min_va] [max_va]
"""
import re
import sys
import dis

name = sys.argv[1]
off = int(sys.argv[2], 0)
lo = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0
hi = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0xFFFFFFFFFFFFFFFF

p = dis.disasm(name, "__TEXT_EXEC.__text")
lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
rx = re.compile(r"^0x([0-9a-f]+):\s+(?:[0-9a-f]{2} ){4}\s*(\S+)\s*(.*)$")
hexrx = re.compile(r"#0x([0-9a-f]+)")
for l in lines:
    m = rx.match(l)
    if not m:
        continue
    addr = int(m.group(1), 16)
    if not (lo <= addr <= hi):
        continue
    mn = m.group(2)
    ops = m.group(3).split(";")[0].strip().replace("\t", " ")
    for h in hexrx.findall(ops):
        if int(h, 16) == off:
            print(f"{addr:#018x}  {mn:8s} {ops}")
            break
