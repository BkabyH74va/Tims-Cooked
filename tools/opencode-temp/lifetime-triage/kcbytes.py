#!/usr/bin/env python3
"""Compare bytes of an address across the extracted member and the kernelcache."""
import sys
import kx
import kcq
import resolve as R

name = sys.argv[1]
for a in sys.argv[2:]:
    va = int(a, 0)
    m = kx.MachO(kx.EXTRACT / name)
    off, nm, sg = kcq.va_to_kc_off(va)
    kc = R.KC.read_bytes()[off:off + 16] if off is not None else b""
    ex = m.read(va, 16) or b""
    print(f"{va:#018x}")
    print(f"   member: {ex.hex() if ex else 'unmapped'}")
    print(f"   kc    : {kc.hex() if kc else 'unmapped'} ({nm} {sg})")
