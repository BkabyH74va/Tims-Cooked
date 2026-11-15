#!/usr/bin/env python3
"""Survey one extracted kext: segments/sections, cstrings, symbols, vtables."""
import re
import sys
from pathlib import Path
import kx

name = sys.argv[1]
m = kx.MachO(kx.EXTRACT / name)
print(f"=== {name} ({m.path.stat().st_size} bytes) ===")
for s in m.segments:
    print(f"  SEG {s['name']:<14s} vm={s['vmaddr']:#018x}-{s['vmaddr']+s['vmsize']:#018x} "
          f"file={s['fileoff']:#x}+{s['filesize']:#x}")
for s in m.sections:
    print(f"    {s['seg']}.{s['sect']:<24s} {s['addr']:#018x} sz={s['size']:#x} off={s['offset']:#x}")

print("\n--- cstrings ---")
for va, txt in m.cstrings():
    print(f"  {va:#018x}  {txt}")

syms = kx.load_symjson()
print("\n--- symbols (symjson) in this kext's image ---")
lo = min(s["addr"] for s in m.sections)
hi = max(s["addr"] + s["size"] for s in m.sections)
for a, n in kx.syms_in_range(syms, lo, hi):
    print(f"  {a:#018x} {n}")
