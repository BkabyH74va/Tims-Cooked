#!/usr/bin/env python3
"""Dump raw bytes / qwords / u32 fields from a kernelcache fileset member's data segment."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from kc_iosurface import parse_fileset, member_segments

KEXT = "com.apple.iokit.IOSurface"


def main():
    kc = Path(sys.argv[1])
    name = sys.argv[2]
    segname = sys.argv[3]
    start = int(sys.argv[4], 0)
    size = int(sys.argv[5], 0)
    data = kc.read_bytes()
    entries, _ = parse_fileset(data)
    e = [x for x in entries if x["name"] == name][0]
    segs = member_segments(data, e["fileoff"])
    vm, vms, fo, fs = segs[segname]
    tex = segs.get("__TEXT_EXEC") or segs["__TEXT"]
    tvm, tvms, tfo, tfs = tex

    memb = [(s, v, f, fs2) for s, (v, vs, f, fs2) in segs.items() if fs2]

    def foff2vm(f):
        for s, v, fo2, fs2 in memb:
            if fo2 <= f < fo2 + fs2:
                return v + (f - fo2)
        return None

    print(f"{segname} vm=0x{vm:x}  dump +0x{start:x} .. +0x{start+size:x}")
    off = start
    while off < start + size:
        q = struct.unpack_from("<Q", data, fo + off)[0]
        w0, w1, w2, w3 = struct.unpack_from("<IIII", data, fo + off)
        plain = q & 0x0000FFFFFFFFFFFF
        r = None
        if tvm <= plain < tvm + tvms:
            r = plain
        else:
            low32 = q & 0xFFFFFFFF
            if low32:
                rr = foff2vm(low32)
                if rr is not None and tvm <= rr < tvm + tvms:
                    r = rr
        tag = f" -> fn 0x{r:x}" if r else ""
        print(f"  +0x{off:04x} vm=0x{vm+off:x}: 0x{q:016x}  u32=[{w0},{w1},{w2},{w3}]{tag}")
        off += 8


if __name__ == "__main__":
    main()
