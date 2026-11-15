#!/usr/bin/env python3
"""Dump a class vtable (from the kernelcache symbol map) and show which slots
are overridden relative to a base-class vtable."""
import struct
import sys
import resolve as R
import kcq
import kx


def vtable_slots(vt_va, n=0x60):
    data = R.KC.read_bytes()
    out = []
    off, nm, sg = kcq.va_to_kc_off(vt_va)
    for i in range(n):
        raw = struct.unpack_from("<Q", data, off + i * 8)[0]
        low = raw & 0xFFFFFFFF
        cands = R.resolve(low)
        out.append((vt_va + i * 8, raw, low, cands[0] if cands else None))
    return out


def main():
    syms = kx.load_symjson()
    base_name = sys.argv[1]
    derived_name = sys.argv[2]
    n = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x60
    bvt = next(a for a, nm in syms.items() if nm == base_name)
    dvt = next(a for a, nm in syms.items() if nm == derived_name)
    print(f"base    {base_name} @ {bvt:#018x}")
    print(f"derived {derived_name} @ {dvt:#018x}")
    b = vtable_slots(bvt, n)
    d = vtable_slots(dvt, n)
    for i in range(n):
        bt = b[i][3][0] if b[i][3] else None
        dt = d[i][3][0] if d[i][3] else None
        mark = "  " if bt == dt else "**"
        bs = f"{bt:#018x}" if bt else "?"
        ds = f"{dt:#018x}" if dt else "?"
        print(f"{mark} slot {i:3d}  base={bs}  derived={ds}")


if __name__ == "__main__":
    main()
