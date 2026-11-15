#!/usr/bin/env python3
import re
from pathlib import Path
p = Path('disasm/com_apple_driver_AppleSmartIO2.__TEXT_EXEC___text.txt')
lines = p.read_text(encoding='utf-8', errors='replace').splitlines()
rx_ins = re.compile(r"^0x([0-9a-f]+):\s+(?:[0-9a-f]{2} ){4}\s*(\S+)\s*(.*)$")
for l in lines:
    if "0xfffffe000974441c" in l or "0xfffffe0009744420" in l:
        m = rx_ins.match(l)
        print('raw:', repr(l))
        print('  m:', bool(m))
        if m:
            print('  mn=', repr(m.group(2)), 'ops=', repr(m.group(3)))
