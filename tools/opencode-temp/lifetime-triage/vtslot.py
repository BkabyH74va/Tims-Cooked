#!/usr/bin/env python3
"""Read IOUserClient vtable slots (by index) from the kernelcache.

Usage: vtslot.py <vtable_va> <slot-index> [count]
"""
import struct
import sys
import resolve as R
import kcq

vt = int(sys.argv[1], 0)
idx = int(sys.argv[2], 0)
count = int(sys.argv[3], 0) if len(sys.argv) > 3 else 1

data = R.KC.read_bytes()
for k in range(count):
    va = vt + (idx + k) * 8
    off, nm, sg = kcq.va_to_kc_off(va)
    val = struct.unpack_from("<Q", data, off)[0]
    c = R.resolve(val & 0xFFFFFFFF)
    cs = f"{c[0][0]:#018x}" if c else f"{val:#018x}"
    print(f"slot {idx + k:4d} (vt+{hex((idx + k) * 8)}) @ {va:#018x} -> {cs}")
