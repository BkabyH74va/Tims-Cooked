#!/usr/bin/env python3
"""Dump specific IOUserClient vtable slots for one user-client class vtable.

Usage: slots1.py <member> <vtable_va> <slot1> [slot2 ...]
"""
import struct
import sys
import resolve as R
import kcq
import kx

member = sys.argv[1]
vt = int(sys.argv[2], 0)
slots = [int(x, 0) for x in sys.argv[3:]]

syms = kx.load_symjson()
data = R.KC.read_bytes()
off, nm, sg = kcq.va_to_kc_off(vt)
for i in slots:
    raw = struct.unpack_from("<Q", data, off + i * 8)[0]
    c = R.resolve(raw & 0xFFFFFFFF)
    tgt = c[0][0] if c else None
    extra = ""
    if tgt is not None:
        s = syms.get(tgt)
        if s:
            extra = f"  <{s}>"
        o2, n2, s2 = kcq.va_to_kc_off(tgt)
        extra += f"  [{n2} {s2}]"
    print(f"slot {i:4d} (vt+{i*8:#06x}): raw={raw:#018x} -> {tgt:#018x}{extra}" if tgt
          else f"slot {i:4d}: raw={raw:#018x} -> unresolved")
