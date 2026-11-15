#!/usr/bin/env python3
"""Strict xref: adrp + add pairs only, verifying the adrp immediately precedes
within a small window and no other write to that register occurs in between."""
import re
import sys
import dis

name = sys.argv[1]
targets = {int(t, 0): [] for t in sys.argv[2:]}
section = "__TEXT_EXEC.__text"
p = dis.disasm(name, section)
lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
rx = re.compile(r"^0x([0-9a-f]+):\s+(?:[0-9a-f]{2} ){4}\s*(\S+)\s*(.*)$")
parsed = []
for l in lines:
    m = rx.match(l)
    if m:
        parsed.append((int(m.group(1), 16), m.group(2),
                       m.group(3).split(";")[0].strip().replace("\t", " ")))
regs = set("x%d" % i for i in range(31)) | {"w%d" % i for i in range(31)}
for i, (addr, mn, ops) in enumerate(parsed):
    if mn != "add":
        continue
    mm = re.match(r"(x\d+),\s*(x\d+),\s*#?(0x[0-9a-f]+|\d+)", ops)
    if not mm:
        continue
    dst, src, imm = mm.group(1), mm.group(2), int(mm.group(3), 0)
    base = None
    for j in range(i - 1, max(-1, i - 10), -1):
        a2, mn2, ops2 = parsed[j]
        # any instruction that writes dst/src invalidates
        m2 = re.match(r"(x\d+),", ops2)
        if mn2 == "adrp":
            mm2 = re.match(r"(x\d+),\s*(0x[0-9a-f]+)", ops2)
            if mm2 and mm2.group(1) == src:
                base = int(mm2.group(2), 16)
                break
            if mm2 and mm2.group(1) == dst:
                break
        elif mn2 in ("mov", "movz", "movn", "movk", "ldr", "ldp", "adr", "add", "sub",
                     "ldrb", "ldrh", "ldrsw", "ldur", "ldxr", "ldxp", "ldar", "cas",
                     "eor", "orr", "and", "lsl", "lsr", "mul", "madd", "msub", "neg",
                     "sxtw", "uxtw", "csel", "csinc", "csinv", "csneg", "adrp"):
            if mn2 == "add" and re.match(r"(x\d+),\s*(x\d+),", ops2) and \
                    re.match(r"(x\d+),\s*(x\d+),", ops2).group(1) == src:
                continue
            # any other write to src or dst kills the pair
            if src in regs or dst in regs:
                if re.search(r"\b%s\b" % src, ops2) or re.search(r"\b%s\b" % dst, ops2):
                    break
    if base is None:
        continue
    val = base + imm
    if val in targets:
        targets[val].append(addr)

for t, addrs in targets.items():
    if addrs:
        print(f"{t:#018x}: " + ", ".join(f"{a:#018x}" for a in addrs))
    else:
        print(f"{t:#018x}: no reference found")
