#!/usr/bin/env python3
"""Print the cached ipsw disassembly between two addresses."""
import re
import sys
import dis

name = sys.argv[1]
lo = int(sys.argv[2], 0)
hi = int(sys.argv[3], 0)
section = sys.argv[4] if len(sys.argv) > 4 else "__TEXT_EXEC.__text"
p = dis.disasm(name, section)
lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
for l in lines:
    m = re.match(r"^0x([0-9a-f]+):", l)
    if m:
        a = int(m.group(1), 16)
        if lo <= a < hi:
            print(l)
