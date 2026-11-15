#!/usr/bin/env python3
"""Print the raw bytes at given kernel vm addresses (IOSurface kext)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from kc_iosurface import parse_fileset, member_segments

KC = Path(sys.argv[1])
ADDS = [int(a, 0) for a in sys.argv[2:]]

data = KC.read_bytes()
entries, _ = parse_fileset(data)
e = [x for x in entries if x["name"] == "com.apple.iokit.IOSurface"][0]
segs = member_segments(data, e["fileoff"])


def raw(vm, n=48):
    for name, (svm, vms, fo, fs) in segs.items():
        if fs and svm <= vm < svm + fs:
            off = fo + (vm - svm)
            return name, off, data[off:off + n]
    return None, None, b""


for vm in ADDS:
    name, off, b = raw(vm)
    txt = b.split(b"\x00")[0]
    print("0x%x  seg=%s off=%s  %r" % (vm, name, hex(off) if off else "-", txt))
