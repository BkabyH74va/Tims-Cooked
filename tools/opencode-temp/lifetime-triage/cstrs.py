#!/usr/bin/env python3
"""List cstrings matching a regex from a member's cstring/const sections.

Usage: cstrs.py <member> <regex>
"""
import re
import sys
import kx

name = sys.argv[1]
pat = re.compile(sys.argv[2])
m = kx.MachO(kx.EXTRACT / name)
for s in m.sections:
    if s["sect"] not in ("__cstring", "__const", "__literal4", "__literal8",
                         "__literal16", "__os_log"):
        continue
    if s["seg"] == "__LINKEDIT":
        continue
    b = m.data[s["offset"]:s["offset"] + s["size"]]
    for mm in re.finditer(rb"[\x20-\x7e]{5,}", b):
        t = mm.group().decode("ascii", "replace")
        if pat.search(t):
            print(f"{s['addr'] + mm.start():#018x}  {t}")
