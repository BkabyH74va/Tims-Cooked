#!/usr/bin/env python3
"""List function starts (LC_FUNCTION_STARTS) of an extracted kext."""
import struct
import sys
import kx

name = sys.argv[1]
m = kx.MachO(kx.EXTRACT / name)
# find LC_FUNCTION_STARTS
off = 32
base = None
fs_off = fs_size = None
for _ in range(m.ncmds):
    cmd, cmdsize = struct.unpack_from("<II", m.data, off)
    if cmd == 0x26:  # LC_FUNCTION_STARTS
        fs_off, fs_size = struct.unpack_from("<II", m.data, off + 8)
    off += cmdsize
if fs_off is None:
    raise SystemExit("no LC_FUNCTION_STARTS")
# base = lowest text address
text = m.sec("__TEXT_EXEC", "__text")
base = text["addr"]
print(f"base {base:#018x} function starts @{fs_off:#x} size {fs_size:#x}")
data = m.data[fs_off:fs_off + fs_size]
addr = base
i = 0
out = []
while i < len(data):
    val = 0
    shift = 0
    while True:
        b = data[i]
        i += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    if val == 0:
        break
    addr += val
    out.append(addr)
for a in out:
    print(f"{a:#018x}")
print(f"total {len(out)}")
