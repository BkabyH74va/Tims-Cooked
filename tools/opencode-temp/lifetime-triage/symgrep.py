#!/usr/bin/env python3
"""Search the kernelcache symbol map by substring."""
import sys
import kx

syms = kx.load_symjson()
pat = sys.argv[1]
for a, n in sorted(syms.items()):
    if pat.lower() in n.lower():
        print(f"{a:#018x} {n}")
