#!/usr/bin/env python3
"""Map an IOExternalMethodDispatch array to the method-name cstrings that the
corresponding callbacks reference.

Usage: mapnames.py <member> <table_va> <count> <stride>
"""
import re
import struct
import sys
import kx
import resolve as R
import dis

name = sys.argv[1]
table = int(sys.argv[2], 0)
count = int(sys.argv[3], 0)
stride = int(sys.argv[4], 0)

m = kx.MachO(kx.EXTRACT / name)
syms = kx.load_symjson()

# --- read the dispatch table (raw chained-fixup encoded) -------------------
entries = []
for i in range(count):
    raw = m.u64(table + i * stride)
    cands = R.resolve(raw & 0xFFFFFFFF)
    entries.append(cands[0][0] if cands else None)

# --- build the set of cstrings --------------------------------------------
strings = {}
for s in m.sections:
    if s["sect"] not in ("__cstring", "__const", "__literal4", "__literal8",
                         "__literal16", "__data", "__os_log"):
        continue
    if s["seg"] == "__LINKEDIT":
        continue
    b = m.data[s["offset"]:s["offset"] + s["size"]]
    for mm in re.finditer(rb"[\x20-\x7e]{6,}", b):
        strings[s["addr"] + mm.start()] = mm.group().decode("ascii", "replace")

# --- disassemble ----------------------------------------------------------
p = dis.disasm(name, "__TEXT_EXEC.__text")
lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
rx = re.compile(r"^0x([0-9a-f]+):\s+(?:[0-9a-f]{2} ){4}\s*(\S+)\s*(.*)$")
insns = []
for l in lines:
    mm = rx.match(l)
    if mm:
        insns.append((int(mm.group(1), 16), mm.group(2),
                      mm.group(3).split(";")[0].strip().replace("\t", " ")))

addr_to_idx = {a: i for i, (a, _, _) in enumerate(insns)}
for i, e in enumerate(entries):
    if e is None:
        print(f"sel {i:3d}: <unresolved>")
        continue
    if i + 1 < len(entries) and entries[i + 1] is not None:
        end = entries[i + 1]
    else:
        end = e + 0x800
    # find index of e
    j = addr_to_idx.get(e)
    if j is None:
        print(f"sel {i:3d}: cb={e:#018x} <not in __text>")
        continue
    k = addr_to_idx.get(end, len(insns))
    names = []
    page = {}
    for a, mn, ops in insns[j:k]:
        if mn == "adrp":
            mm = re.match(r"(x\d+),\s*(0x[0-9a-f]+)", ops)
            if mm:
                page[mm.group(1)] = int(mm.group(2), 16)
        elif mn == "add":
            mm = re.match(r"(x\d+),\s*(x\d+),\s*#?(0x[0-9a-f]+|\d+)", ops)
            if mm and mm.group(2) in page:
                val = page[mm.group(2)] + int(mm.group(3), 0)
                if val in strings:
                    txt = strings[val]
                    if "::" in txt or "extern" in txt:
                        names.append((val, txt))
    seen = []
    for v, t in names:
        if t not in [x[1] for x in seen]:
            seen.append((v, t))
    label = "; ".join(f"{t} @{v:#018x}" for v, t in seen[:3]) or "<no method-name cstring>"
    print(f"sel {i:3d}: cb={e:#018x}  {label}")
