#!/usr/bin/env python3
"""Identity report for one or more kernelcache functions.

Prints exact LC_FUNCTION_STARTS boundaries, the top code-referenced strings,
and every direct BL/B caller. Numpy-free (a plain word loop) so it runs in the
same environment as the other kz-static-diff tools.

Usage:
    python kz_fnreport.py <build> <hex-va>[:label] [...]
"""
import bisect
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
BASE = ROOT / "firmware"
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))

from kc_fstarts import load_build, func_of, func_refs  # noqa: E402


def segments(d):
    ncmds = struct.unpack_from("<I", d, 16)[0]
    off = 32
    out = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", d, off)
        if cmd == 0x19:
            nm = d[off + 8:off + 24].rstrip(b"\0").decode(errors="replace")
            vm, vsz, fo, fsz = struct.unpack_from("<QQQQ", d, off + 24)
            out.append((nm, vm, vsz, fo, fsz))
        off += cmdsize
    return out


def find_calls(d, segs, target):
    hits = []
    for nm, vm, vsz, fo, fsz in segs:
        if "__TEXT" not in nm:
            continue
        blob = d[fo:fo + fsz]
        n4 = len(blob) // 4
        for i in range(n4):
            w = struct.unpack_from("<I", blob, i * 4)[0]
            op = w & 0xFC000000
            if op != 0x94000000 and op != 0x14000000:
                continue
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            va = vm + i * 4
            if va + imm * 4 == target:
                kind = "BL" if op == 0x94000000 else "B"
                hits.append((kind, va))
    return sorted(hits, key=lambda x: x[1])


def main(build, specs):
    p = BASE / build / "kernelcache.release.macho"
    d = p.read_bytes()
    segs = segments(d)
    b = load_build(build)
    starts = b["starts"]
    for spec in specs:
        addr_s, _, label = spec.partition(":")
        va = int(addr_s, 16)
        r = func_of(b, va)
        print(f"=== {build} {va:#x} {label}")
        if not r:
            print("    NOFUNC")
            continue
        st, nx = r
        sz = (nx - st) if nx else 0
        refs = sorted(func_refs(b, st, st + sz), key=len, reverse=True)
        print(f"    start {st:#x} size {sz:#x} next {nx if nx is None else hex(nx)}")
        for s in refs[:10]:
            print(f"      STR {s!r}")
        hits = find_calls(d, segs, st)
        print(f"    direct callers: {len(hits)}")
        for kind, site in hits[:20]:
            fr = func_of(b, site)
            owner = hex(fr[0]) if fr else None
            print(f"      {kind} <- {site:#x} in func {owner}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
