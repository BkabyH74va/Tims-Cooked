#!/usr/bin/env python3
"""Find references to target addresses inside a cached ipsw disassembly.

Parses `adrp xN, <page>` / `add xM, xN, #<imm>` / `adr xN, <addr>` pairs and
reports the address of the instruction that materialises each target.
"""
import re
import sys
import dis

name = sys.argv[1]
targets = [int(t, 0) for t in sys.argv[2:]]
section = "__TEXT_EXEC.__text"
p = dis.disasm(name, section)
lines = p.read_text(encoding="utf-8", errors="replace").splitlines()

rx_ins = re.compile(r"^0x([0-9a-f]+):\s+(?:[0-9a-f]{2} ){4}\s*(\S+)\s*(.*)$")
page = {}
found = {t: [] for t in targets}

for l in lines:
    m = rx_ins.match(l)
    if not m:
        continue
    addr = int(m.group(1), 16)
    mn = m.group(2)
    ops = m.group(3).split(";")[0].strip().replace("\t", " ")
    if mn == "adrp":
        mm = re.match(r"(x\d+),\s*(0x[0-9a-f]+)", ops)
        if mm:
            page[mm.group(1)] = int(mm.group(2), 16)
    elif mn == "adr":
        mm = re.match(r"(x\d+),\s*(0x[0-9a-f]+)", ops)
        if mm:
            page.pop(mm.group(1), None)
            val = int(mm.group(2), 16)
            if val in found:
                found[val].append(addr)
    elif mn == "add":
        mm = re.match(r"(x\d+),\s*(x\d+),\s*#?(0x[0-9a-f]+|\d+)", ops)
        if mm and mm.group(2) in page:
            val = page[mm.group(2)] + int(mm.group(3), 0)
            if val in found:
                found[val].append(addr)

for t in targets:
    if found[t]:
        print(f"{t:#018x}: referenced at " + ", ".join(f"{a:#018x}" for a in found[t]))
    else:
        print(f"{t:#018x}: no reference found")
