#!/usr/bin/env python3
"""Find vtable-style pointer clusters in the IOSurface kext's __DATA_CONST.

PAC-signed pointers keep the real address in the low 48 bits, so we can find
vtable slots by masking and range-checking.  We then print the clusters so the
class method tables can be read in order.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from kc_iosurface import parse_fileset, member_segments

KEXT = "com.apple.iokit.IOSurface"


def main():
    kc = Path(sys.argv[1])
    data = kc.read_bytes()
    entries, _ = parse_fileset(data)
    e = [x for x in entries if x["name"] == KEXT][0]
    segs = member_segments(data, e["fileoff"])
    tex = segs["__TEXT_EXEC"]
    lo, hi = tex[0], tex[0] + tex[1]
    for sname in ("__DATA_CONST", "__DATA"):
        seg = segs[sname]
        vm, vms, fo, fs = seg
        print(f"== {sname} vm=0x{vm:x} size=0x{fs:x}  text=[0x{lo:x},0x{hi:x})")
        hits = []
        for off in range(0, fs - 7, 8):
            q = struct.unpack_from("<Q", data, fo + off)[0]
            plain = q & 0x0000FFFFFFFFFFFF
            if lo <= plain < hi:
                hits.append((off, vm + off, q, plain))
        for (off, addr, q, plain) in hits:
            print(f"   +0x{off:04x}  0x{addr:x}: q=0x{q:016x} -> fn 0x{plain:x}")
        print()


if __name__ == "__main__":
    main()
