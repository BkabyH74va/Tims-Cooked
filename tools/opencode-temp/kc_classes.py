#!/usr/bin/env python3
"""Locate MetaClass-ish structures in the IOSurface kext's data segments.

Scans for plain pointers into the kext's __TEXT (where the class-name strings
live) and prints the pointed-to string plus the surrounding qwords, so the
class layout and its vtable can be read.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from kc_iosurface import parse_fileset, member_segments

KEXT = "com.apple.iokit.IOSurface"


def cstr(data, off, limit=200):
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = off + limit
    return data[off:end].decode("ascii", "replace")


def main():
    kc = Path(sys.argv[1])
    data = Path(kc).read_bytes()
    entries, _ = parse_fileset(data)
    e = [x for x in entries if x["name"] == KEXT][0]
    segs = member_segments(data, e["fileoff"])
    tvm, tvms, tfo, tfs = segs["__TEXT"]
    print(f"__TEXT vm=0x{tvm:x} size=0x{tfs:x}")
    for sname in ("__DATA_CONST", "__DATA"):
        vm, vms, fo, fs = segs[sname]
        print(f"\n== {sname} vm=0x{vm:x}")
        for off in range(0, fs - 7, 8):
            q = struct.unpack_from("<Q", data, fo + off)[0]
            if tvm <= q < tvm + tfs:
                s = cstr(data, tfo + (q - tvm))
                if s and all(32 <= ord(c) < 127 for c in s):
                    print(f"  +0x{off:04x} 0x{vm+off:x} -> 0x{q:x} \"{s}\"")


if __name__ == "__main__":
    main()
