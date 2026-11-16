#!/usr/bin/env python3
"""Member-scoped arm64e auth-pointer slot finder (data tables in one kext).

`kz_vtable.py find` only works on `com.apple.kernel` VAs because it goes
through `kc_fstarts.load_build()`. This tool uses `kc_member.load_member()`
so a kext member's own `__DATA_CONST` can be scanned for slots whose low 32
bits equal a target function's file offset — i.e. the arm64e auth-pointer
tables that hold a class's dispatch/vtable entries.

Decoding rule (same as kz_vtable.py, measured on iOS 27):
    target_va = TEXT_VMADDR + (slot & 0xFFFFFFFF)
so matching is done on the raw low-32 pattern of the target's file offset.

Usage:
    python kz_member_authscan.py <build> <member> <hex-func-va> [window]
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))

from kc_member import load_member, v2o, o2v  # noqa: E402

TEXT_VMADDR = 0xFFFFFE0007004000


def main(argv):
    if len(argv) < 4:
        raise SystemExit(__doc__)
    bld, member = argv[1], argv[2]
    va = int(argv[3], 16)
    win = int(argv[4], 16) if len(argv) > 4 else 0x200
    b = load_member(bld, member)
    d = b["data"]
    starts = set(b["starts"])
    fo = v2o(b, va)
    pat = struct.pack("<I", fo & 0xFFFFFFFF)
    hits = []
    i = 0
    while True:
        i = d.find(pat, i)
        if i < 0 or len(hits) > 500:
            break
        hits.append(i)
        i += 1
    print(f"{bld} {member}: target {va:#x} fileoff {fo:#x}; {len(hits)} low32 slots")
    for h in hits:
        try:
            sva = o2v(b, h)
        except KeyError:
            sva = None
        # contiguous decodable run ending at h
        start = h
        while start >= 8:
            w = struct.unpack_from("<Q", d, start - 8)[0]
            cand = TEXT_VMADDR + (w & 0xFFFFFFFF)
            if cand in starts:
                start -= 8
                if h - start > win:
                    break
                continue
            break
        idx = 0
        q = start
        while q <= h:
            w = struct.unpack_from("<Q", d, q)[0]
            cand = TEXT_VMADDR + (w & 0xFFFFFFFF)
            mark = "  <=== TARGET" if q == h else ""
            ok = "FUNC" if cand in starts else "?? "
            print(f"   [{idx:3d}] {o2v(b, q):#x} -> {cand:#x} {ok}{mark}")
            idx += 1
            q += 8
        print(f"   table start {o2v(b, start):#x}  target index {idx - 1}")


if __name__ == "__main__":
    main(sys.argv)
