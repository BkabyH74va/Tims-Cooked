#!/usr/bin/env python3
"""Dump an ARM64 PC-relative jump table (ldrsw/br pattern) as handler VAs.

Usage: jumptable.py <member> <table_va> <n_entries> <base_va>
"""
import struct
import sys
import resolve as R
import kcq

tv = int(sys.argv[1], 0)
n = int(sys.argv[2], 0)
base = int(sys.argv[3], 0)

data = R.KC.read_bytes()
for i in range(n):
    va = tv + i * 4
    off, nm, sg = kcq.va_to_kc_off(va)
    d = struct.unpack_from("<i", data, off)[0]
    tgt = base + d
    c = R.resolve(tgt & 0xFFFFFFFF)
    cs = f"{c[0][0]:#018x}" if c else f"{tgt:#018x}"
    print(f"entry {i:3d} @{va:#018x} delta={d:+#x} -> {cs}")
