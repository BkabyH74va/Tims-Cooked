#!/usr/bin/env python3
import re
from pathlib import Path
p = Path('disasm/com_apple_driver_AppleSmartIO2.__TEXT_EXEC___text.txt')
lines = p.read_text(encoding='utf-8', errors='replace').splitlines()
rx = re.compile(r'^0x([0-9a-f]+):\s+(?:[0-9a-f]{2} ){4}\s*(\S+)\s*(.*)$')
n = 0
for l in lines:
    m = rx.match(l)
    if not m:
        if l.startswith('0x'):
            n += 1
            if n < 5:
                print('NOMATCH:', repr(l))
        continue
    if 'adrp' in m.group(2):
        print('MATCH:', repr(l), '|mn=', m.group(2), '|ops=', repr(m.group(3)))
        break
print('total lines', len(lines), 'nomatch', n)
