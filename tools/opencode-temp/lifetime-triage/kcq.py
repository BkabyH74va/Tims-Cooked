#!/usr/bin/env python3
"""Read N 64-bit words at a VA directly out of the kernelcache and resolve
chained-fixup encoded pointers to runtime addresses."""
import struct
import sys
from pathlib import Path
import resolve as R
import kx

KC = R.KC
BASE = R.BASE


def va_to_kc_off(addr):
    for mem in R.members():
        for segname, vm, vms, so, ss in mem["segs"]:
            if segname == "__LINKEDIT":
                continue
            if vm <= addr < vm + vms:
                return so + (addr - vm), mem["name"], segname
    return None, None, None


def main():
    va = int(sys.argv[1], 0)
    count = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x20
    syms = kx.load_symjson()
    off, nm, sg = va_to_kc_off(va)
    if off is None:
        raise SystemExit(f"{va:#x} not found in kernelcache")
    data = KC.read_bytes()
    print(f"reading {count} words at {va:#018x} (kc off {off:#x}, {nm} {sg})")
    for i in range(count):
        raw = struct.unpack_from("<Q", data, off + i * 8)[0]
        low = raw & 0xFFFFFFFF
        cands = R.resolve(low)
        s = syms.get(low) or ""
        txt = ""
        if cands:
            t, m2, s2 = cands[0]
            sn = syms.get(t)
            txt = f" -> {t:#018x} {m2} {s2}" + (f"  <{sn}>" if sn else "")
        print(f"{va + i*8:#018x}: raw={raw:#018x} low={low:#010x}{txt}")


if __name__ == "__main__":
    main()
