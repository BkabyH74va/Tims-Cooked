#!/usr/bin/env python3
"""Dump an IOExternalMethodDispatch array from the kernelcache.

Usage: dumptable.py <table_va> <count> <stride>
"""
import struct
import sys
import resolve as R
import kcq

va = int(sys.argv[1], 0)
count = int(sys.argv[2], 0)
stride = int(sys.argv[3], 0)

data = R.KC.read_bytes()
for i in range(count):
    base = va + i * stride
    off, nm, sg = kcq.va_to_kc_off(base)
    cb = struct.unpack_from("<Q", data, off)[0]
    c = R.resolve(cb & 0xFFFFFFFF)
    print(f"sel {i:3d}  base={base:#018x}  cb={c[0][0]:#018x}" if c else
          f"sel {i:3d}  base={base:#018x}  cb=? (raw {cb:#x})")
