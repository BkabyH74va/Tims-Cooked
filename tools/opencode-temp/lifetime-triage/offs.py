#!/usr/bin/env python3
"""Find instructions in a cached disassembly that access a given struct offset.

Usage: offs.py <member> <offset_hex> [context]
"""
import re
import sys
import dis

name = sys.argv[1]
off = sys.argv[2]
ctx = int(sys.argv[3]) if len(sys.argv) > 3 else 0

p = dis.disasm(name, "__TEXT_EXEC.__text")
lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
rx = re.compile(r"^0x([0-9a-f]+):\s+(?:[0-9a-f]{2} ){4}\s*(\S+)\s*(.*)$")
parsed = []
for l in lines:
    m = rx.match(l)
    if m:
        parsed.append((int(m.group(1), 16), l))
pat = re.compile(r"#%s\]" % re.escape(off))
hits = [i for i, (a, l) in enumerate(parsed) if pat.search(l)]
seen = set()
for i in hits:
    a = parsed[i][0]
    if a in seen:
        continue
    seen.add(a)
    print(f"--- hit at {a:#018x}")
    for j in range(max(0, i - ctx), min(len(parsed), i + ctx + 1)):
        print(f"    {parsed[j][1]}")
print(f"\n{len(seen)} hit(s) for offset {off} in {name}")
