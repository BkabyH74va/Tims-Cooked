#!/usr/bin/env python3
"""Show the nearest symbol at/just below an address, plus the enclosing kext."""
import bisect
import sys
import kx
import resolve as R

syms = kx.load_symjson()
keys = sorted(syms)
for a in sys.argv[1:]:
    va = int(a, 0)
    i = bisect.bisect_right(keys, va) - 1
    if i < 0:
        print(f"{va:#018x}: <before first symbol>")
        continue
    k = keys[i]
    nm, sg = R.owner(k)
    print(f"{va:#018x}: {syms[k]} @ {k:#018x} (+{va-k:#x})  [{nm} {sg}]")
