#!/usr/bin/env python3
"""Grep the cached ipsw disassembly of an extracted kext."""
import re
import sys
from pathlib import Path
import dis

name = sys.argv[1]
pat = sys.argv[2]
section = sys.argv[3] if len(sys.argv) > 3 else "__TEXT_EXEC.__text"
p = dis.disasm(name, section)
rx = re.compile(pat)
lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
n = 0
for i, l in enumerate(lines):
    if rx.search(l):
        print(l)
        n += 1
        if n <= 400:
            continue
print(f"-- matches: {n}")
