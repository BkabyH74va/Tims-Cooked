#!/usr/bin/env python3
"""Raw hex dump of IOExternalMethodDispatch records at a kernelcache VA.

Usage: rawrec.py <table_va> <count> <stride>
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
    b = va + i * stride
    off, nm, sg = kcq.va_to_kc_off(b)
    raw = data[off:off + stride]
    cb = struct.unpack_from("<Q", raw, 0)[0]
    c = R.resolve(cb & 0xFFFFFFFF)
    cbs = f"{c[0][0]:#018x}" if c else f"{cb:#018x}(raw)"
    dwords = [struct.unpack_from("<I", raw, o)[0] for o in range(8, stride, 4)]
    hexs = raw.hex()
    print(f"sel {i:3d} va={b:#018x} cb={cbs}")
    print(f"     bytes: {hexs}")
    print(f"     dwords+0x08: " + " ".join(f"{d:#010x}" for d in dwords))
