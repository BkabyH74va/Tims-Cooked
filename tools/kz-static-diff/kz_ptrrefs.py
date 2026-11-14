#!/usr/bin/env python3
"""Find data pointers (and PAC'd pointer forms) equal to a target VA."""
import struct
import sys
from pathlib import Path

import numpy as np

BASE = Path(Path(__file__).resolve().parents[2] / "firmware")


def segments(d):
    ncmds = struct.unpack_from('<I', d, 16)[0]
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', d, off)
        if cmd == 0x19:
            nm = d[off + 8:off + 24].rstrip(b'\0').decode(errors='replace')
            vm, vsz, fo, fsz = struct.unpack_from('<QQQQ', d, off + 24)
            segs.append((nm, vm, vsz, fo, fsz))
        off += cmdsize
    return segs


def main():
    bld = sys.argv[1]
    targets = [int(x, 16) for x in sys.argv[2:]]
    d = (BASE / bld / "kernelcache.release.macho").read_bytes()
    segs = segments(d)
    tset = set(targets)
    for nm, vm, vsz, fo, fsz in segs:
        if "__TEXT" in nm:
            continue
        blob = d[fo:fo + fsz]
        n = len(blob) - (len(blob) % 8)
        arr = np.frombuffer(blob[:n], dtype='<u8')
        va = vm + np.arange(0, n, 8, dtype=np.uint64)
        idx = np.nonzero(np.isin(arr, list(tset)))[0]
        if len(idx):
            print(f"# {nm}: {len(idx)} hits")
            for i in idx[:12]:
                print(f"   slot {va[i]:#x} -> {arr[i]:#018x}")


if __name__ == "__main__":
    main()
