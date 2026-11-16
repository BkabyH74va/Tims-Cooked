#!/usr/bin/env python3
"""Find arm64e auth-pointer-table slots inside one member that point at a VA.

Arm64e auth pointer tables store entries as full 64-bit values whose low 32
bits are the target minus the image's `__TEXT` vmaddr; they are not part of
the chained-fixups blob, so `kz_chainfind` cannot see them. This scans every
segment of a member for such entries and reports the containing table.

Usage:
    python kz_member_vtable.py find <build> <member> <hex-func-va>
    python kz_member_vtable.py dump <build> <member> <hex-table-va> [n]
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
from kc_member import load_member  # noqa: E402


def decode(text_vm, entry):
    return text_vm + (entry & 0xFFFFFFFF)


def main(argv):
    if len(argv) < 5:
        raise SystemExit(__doc__)
    mode, bld, member = argv[1], argv[2], argv[3]
    b = load_member(bld, member)
    text_vm = b["segs"]["__TEXT"][0]
    data = b["data"]

    def entries():
        for nm, (vm, vsz, fo, fsz) in b["segs"].items():
            blob = data[fo:fo + fsz]
            for off in range(0, len(blob) - 8, 8):
                e = struct.unpack_from("<Q", blob, off)[0]
                yield nm, vm + off, e

    if mode == "find":
        tgt = int(argv[4], 16)
        for nm, va, e in entries():
            if e >> 32 == 0 or e >> 48 == 0:
                continue
            if decode(text_vm, e) == tgt:
                print("slot %#x [%s] entry %#018x -> %#x" % (va, nm, e, tgt))
    elif mode == "dump":
        tbl = int(argv[4], 16)
        n = int(argv[5]) if len(argv) > 5 else 40
        seg = [x for x in b["segs"].items() if x[1][0] <= tbl < x[1][0] + x[1][1]]
        if not seg:
            raise SystemExit("table va not in a segment")
        nm, (vm, vsz, fo, fsz) = seg[0]
        base_off = fo + (tbl - vm)
        for i in range(n):
            o = base_off + i * 8
            if o + 8 > fo + fsz:
                break
            e = struct.unpack_from("<Q", data, o)[0]
            print("%+4d %#x [%s] entry %#018x -> %s" %
                  (i, tbl + i * 8, nm, e,
                   ("%#x" % decode(text_vm, e)) if e else "-"))


if __name__ == "__main__":
    main(sys.argv)
