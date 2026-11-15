#!/usr/bin/env python3
"""Dump full IOExternalMethodDispatch records (callback + size checks).

Usage: dumptable2.py <table_va> <count> <stride>
"""
import struct
import sys
import resolve as R
import kcq

va = int(sys.argv[1], 0)
count = int(sys.argv[2], 0)
stride = int(sys.argv[3], 0)

data = R.KC.read_bytes()


def rd64(v):
    off, nm, sg = kcq.va_to_kc_off(v)
    return struct.unpack_from("<Q", data, off)[0]


def rd32(v):
    off, nm, sg = kcq.va_to_kc_off(v)
    return struct.unpack_from("<I", data, off)[0]


for i in range(count):
    b = va + i * stride
    cb = rd64(b)
    c = R.resolve(cb & 0xFFFFFFFF)
    cbs = f"{c[0][0]:#018x}" if c else "?"
    scal_in = rd32(b + 8)
    str_in = rd32(b + 0xC)
    scal_out = rd32(b + 0x10)
    str_out = rd32(b + 0x14)
    extra = rd64(b + 0x18) if stride >= 0x20 else 0
    print(f"sel {i:3d} cb={cbs} scalarIn={scal_in:#x} structIn={str_in:#x} "
          f"scalarOut={scal_out:#x} structOut={str_out:#x} extra18={extra:#x}")
