#!/usr/bin/env python3
"""Find the vtable slot index of a function address within a class vtable.

Usage: slotof.py <member> <vtable_va> <func_va>
"""
import struct
import sys
import resolve as R
import kcq

member = sys.argv[1]
vt = int(sys.argv[2], 0)
targets = [int(t, 0) for t in sys.argv[3:]]

data = R.KC.read_bytes()
off, nm, sg = kcq.va_to_kc_off(vt)
slots = []
for i in range(0, 0x140):
    raw = struct.unpack_from("<Q", data, off + i * 8)[0]
    c = R.resolve(raw & 0xFFFFFFFF)
    slots.append(c[0][0] if c else None)

for target in targets:
    if target in slots:
        i = slots.index(target)
        print(f"{target:#018x} is vtable slot {i} (vt+{i*8:#06x})")
    else:
        print(f"{target:#018x}: NOT FOUND in vtable {vt:#018x}")
