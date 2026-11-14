#!/usr/bin/env python3
"""Function report: boundaries, top string refs, and every call site.
Self-contained (no shared scratch modules)."""
import struct
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "opencode-temp"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "pylibs"))
from kc_fstarts import load_build, func_of, func_refs

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


def find_calls(d, segs, target):
    hits = []
    for nm, vm, vsz, fo, fsz in segs:
        if "__TEXT" not in nm:
            continue
        blob = d[fo:fo + fsz]
        n = len(blob) - (len(blob) % 4)
        arr = np.frombuffer(blob[:n], dtype='<u4')
        va = np.arange(vm, vm + n, 4, dtype=np.uint64)
        for opc, kind in ((np.uint64(0x94000000), "BL"), (np.uint64(0x14000000), "B")):
            m = (arr & np.uint64(0xFC000000)) == opc
            if not m.any():
                continue
            idx = np.nonzero(m)[0]
            imm = arr[idx].astype(np.int64) & np.int64(0x03FFFFFF)
            imm = ((imm << np.int64(38)) >> np.int64(38)) << np.int64(2)
            tgt = (va[idx].astype(np.int64) + imm).astype(np.uint64)
            for i, t in zip(idx, tgt):
                if t == target:
                    hits.append((kind, int(va[i])))
    return sorted(hits, key=lambda x: x[1])


def report(bld, va, maxrefs=8, maxsites=12):
    p = BASE / bld / "kernelcache.release.macho"
    d = p.read_bytes()
    segs = segments(d)
    b = load_build(bld)
    r = func_of(b, va)
    if not r:
        print(f"{bld} {va:#x}: NOFUNC")
        return
    st, nx = r
    sz = (nx - st) if nx else 0
    refs = sorted(func_refs(b, st, st + sz), key=len, reverse=True)[:maxrefs]
    hits = find_calls(d, segs, st)
    print(f"=== {bld} {va:#x}")
    print(f"    func start {st:#x} size {sz:#x}  callsites={len(hits)}")
    for s in refs:
        print(f"      STR {s!r}")
    for kind, pc in hits[:maxsites]:
        f2 = func_of(b, pc)
        print(f"      {kind} <- {pc:#x} in func {f2[0]:#x}" if f2 else f"      {kind} <- {pc:#x}")


if __name__ == "__main__":
    for spec in sys.argv[1:]:
        bld, va = spec.split(":")
        report(bld, int(va, 16))
