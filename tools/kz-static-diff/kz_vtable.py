#!/usr/bin/env python3
"""Auth-pointer vtable finder / cross-build differ for the arm64e kernelcache.

Motivation (2026-11-16): `kz_chainfind.py chainrefs` reports zero indirect slots
for functions reached through an arm64e *auth* pointer table, because those
entries are stored as full 64-bit values (PAC/diversity in the high bits, target
as a 32-bit offset from the __TEXT vmaddr in the low bits) and are NOT part of
the LC_DYLD_CHAINED_FIXUPS blob. Decoding rule measured on 24A446/24B119:

    target_va = TEXT_VMADDR + (entry & 0xFFFFFFFF)

where TEXT_VMADDR is the member's __TEXT vmaddr (0xfffffe0007004000 for the
iOS 27 kernelcaches). Validated: 38-entry table at 0xfffffe0007ebd5e0 (24A446)
and its counterpart at 0xfffffe0007ecd688 (24B119).

Usage:
    python kz_vtable.py find  <build> <hex-func-va>     # locate slots + table
    python kz_vtable.py dump  <build> <hex-table-va> [n]
    python kz_vtable.py diff  <buildA> <hex-tblA> <buildB> <hex-tblB> [n]

Numpy-free; needs capstone and tools/opencode-temp/kc_fstarts.py.
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))

from kc_fstarts import load_build, v2o, o2v  # noqa: E402


def decode(entry):
    return ROOT_TEXT[0] + (entry & 0xFFFFFFFF)


ROOT_TEXT = [0xFFFFFE0007004000]  # chain/auth-pointer rebase base, measured on iOS 27


def seg_of(segs, off):
    for nm, (vm, vsz, fo, fsz) in segs.items():
        if fo <= off < fo + fsz:
            return nm
    return None


def va_of(segs, off):
    for nm, (vm, vsz, fo, fsz) in segs.items():
        if fo <= off < fo + fsz:
            return vm + (off - fo)
    return None


def cmd_find(build, va):
    b = load_build(build)
    d = b["data"]
    segs = b["segs"]
    starts = set(b["starts"])
    fo = v2o(b, va)
    val = fo & 0xFFFFFFFF
    pat = struct.pack("<I", val)
    hits = []
    i = 0
    while True:
        i = d.find(pat, i)
        if i < 0:
            break
        hits.append(i)
        i += 1
        if len(hits) > 200:
            break
    print(f"{build}: target {va:#x} fileoff {fo:#x}; {len(hits)} low32=={val:#x} slots")
    for h in hits:
        sva = va_of(segs, h)
        print(f"\n--- slot file {h:#x} va={sva if sva is None else hex(sva)} seg={seg_of(segs,h)}")
        # walk back to a contiguous run of decodable entries
        start = h
        while start >= 8:
            w = struct.unpack_from("<Q", d, start - 8)[0]
            cand = ROOT_TEXT[0] + (w & 0xFFFFFFFF)
            if cand in starts:
                start -= 8
                if h - start > 0x200:
                    break
                continue
            break
        idx = 0
        q = start
        while q <= h:
            w = struct.unpack_from("<Q", d, q)[0]
            cand = ROOT_TEXT[0] + (w & 0xFFFFFFFF)
            mark = "   <=== TARGET" if q == h else ""
            ok = "FUNC" if cand in starts else "??"
            print(f"   [{idx:3d}] {va_of(segs, q):#x} -> {cand:#x} {ok}{mark}")
            idx += 1
            q += 8
        print(f"   table start {va_of(segs, start):#x}  target index {idx - 1}")


def cmd_dump(build, tbl, n):
    b = load_build(build)
    d = b["data"]
    segs = b["segs"]
    starts = set(b["starts"])
    fo = v2o(b, tbl)
    for i in range(n):
        w = struct.unpack_from("<Q", d, fo + 8 * i)[0]
        cand = ROOT_TEXT[0] + (w & 0xFFFFFFFF)
        ok = "FUNC" if cand in starts else "   "
        print(f"[{i:3d}] va={va_of(segs, fo + 8*i):#x} raw={w:#018x} -> {cand:#x} {ok}")


def cmd_diff(build_a, tbl_a, build_b, tbl_b, n):
    rows = []
    for build, tbl in ((build_a, tbl_a), (build_b, tbl_b)):
        b = load_build(build)
        d = b["data"]
        segs = b["segs"]
        fo = v2o(b, tbl)
        starts = set(b["starts"])
        out = []
        for i in range(n):
            w = struct.unpack_from("<Q", d, fo + 8 * i)[0]
            cand = ROOT_TEXT[0] + (w & 0xFFFFFFFF)
            out.append((cand, cand in starts, w))
        rows.append(out)
    A, B = rows
    print(f"{'idx':>3} {'A func':>18} {'B func':>18} {'delta':>12}  note")
    for i, ((fa, oka, wa), (fb, okb, wb)) in enumerate(zip(A, B)):
        notes = []
        if not oka:
            notes.append("A!func")
        if not okb:
            notes.append("B!func")
        if (wa >> 32) != (wb >> 32):
            notes.append("hi-bits differ")
        if fa == fb:
            notes.append("IDENTICAL")
        print(f"{i:3d} {fa:#018x} {fb:#018x} {fb - fa:+#010x}  {' '.join(notes)}")


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return
    mode = sys.argv[1]
    if mode == "find":
        cmd_find(sys.argv[2], int(sys.argv[3], 16))
    elif mode == "dump":
        cmd_dump(sys.argv[2], int(sys.argv[3], 16), int(sys.argv[4]) if len(sys.argv) > 4 else 40)
    elif mode == "diff":
        cmd_diff(sys.argv[2], int(sys.argv[3], 16), sys.argv[4], int(sys.argv[5], 16),
                 int(sys.argv[6]) if len(sys.argv) > 6 else 38)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
