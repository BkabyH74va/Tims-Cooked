#!/usr/bin/env python3
"""Dump a section of an extracted kext as hex + qwords, and optionally resolve
pointers against the kernelcache symbol map."""
import struct
import sys
import kx

name = sys.argv[1]
seg, sect = sys.argv[2], sys.argv[3]
base = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0
count = int(sys.argv[5], 0) if len(sys.argv) > 5 else 0x40

m = kx.MachO(kx.EXTRACT / name)
s = m.sec(seg, sect)
if not s:
    raise SystemExit("no such section")
data = m.data[s["offset"]:s["offset"] + s["size"]]
syms = kx.load_symjson()

def fmt(v):
    n = syms.get(v)
    if n:
        return f"  <{n}>"
    if 0xfffffe0000000000 <= v <= 0xffffffffffff:
        return ""
    return ""

for i in range(0, min(len(data), count * 8), 8):
    v = struct.unpack_from("<Q", data, i)[0]
    va = s["addr"] + i
    extra = ""
    n = syms.get(v)
    if n:
        extra = f"   <{n}>"
    elif base and (base <= v < base + 0x100000000):
        extra = f"   (base+{v-base:#x})"
    print(f"{va:#018x}: {v:#018x}{extra}   |{data[i:i+8].hex()}")
