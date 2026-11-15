#!/usr/bin/env python3
"""Dump cstrings from the IOSurface kext at a vm address range.

Usage: python kc_strings.py <kernelcache> <start_vm> <end_vm>
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from kc_iosurface import parse_fileset, member_segments

KEXT = "com.apple.iokit.IOSurface"


def main():
    kc = Path(sys.argv[1])
    lo = int(sys.argv[2], 0)
    hi = int(sys.argv[3], 0)
    data = kc.read_bytes()
    entries, _ = parse_fileset(data)
    e = [x for x in entries if x["name"] == KEXT][0]
    segs = member_segments(data, e["fileoff"])
    for sname, (vm, vms, fo, fs) in segs.items():
        if not fs:
            continue
        s = max(lo, vm)
        t = min(hi, vm + fs)
        if s >= t:
            continue
        off = fo + (s - vm)
        blob = data[off:off + (t - s)]
        print("== %s vm=0x%x..0x%x" % (sname, s, t))
        i = 0
        while i < len(blob):
            j = blob.find(b"\x00", i)
            if j < 0:
                break
            chunk = blob[i:j]
            if len(chunk) >= 2:
                try:
                    txt = chunk.decode("ascii")
                    if all(32 <= ord(c) < 127 for c in txt):
                        print("  0x%x: %s" % (s + i, txt))
                except Exception:
                    pass
            i = j + 1


if __name__ == "__main__":
    main()
