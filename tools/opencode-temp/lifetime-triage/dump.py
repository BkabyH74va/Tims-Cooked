#!/usr/bin/env python3
"""Dump a region of an extracted kext member as qwords with symbol + cstring
annotations.  Usage: dump.py <member> <va> [count]"""
import struct
import sys
import kx
import resolve as R

name = sys.argv[1]
va = int(sys.argv[2], 0)
count = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x20
m = kx.MachO(kx.EXTRACT / name)
syms = kx.load_symjson()
b = m.read(va, count * 8)
if b is None:
    raise SystemExit("va not mapped")
for i in range(0, len(b), 8):
    v = struct.unpack_from("<Q", b, i)[0]
    addr = va + i
    extra = ""
    n = syms.get(v)
    if n:
        extra = f"   <{n}>"
    else:
        c = R.resolve(v & 0xFFFFFFFF)
        if c:
            extra = f"   -> {c[0][0]:#018x} {c[0][1]} {c[0][2]}"
    # try cstring
    s = m.read(addr, 96)
    txt = ""
    if s:
        e = s.find(b"\x00")
        if 0 < e < 90:
            try:
                t = s[:e].decode("ascii")
                if all(32 <= ord(c) < 127 for c in t) and len(t) > 2:
                    txt = f'  "{t[:70]}"'
            except Exception:
                pass
    print(f"{addr:#018x}: {v:#018x}{extra}{txt}")
