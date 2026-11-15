#!/usr/bin/env python3
"""Read qwords from the IOSurface kext's data segments and decode auth pointers."""
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
    seg = segs["__DATA_CONST"]
    vm, vms, fo, fs = seg
    print(f"__DATA_CONST vm=0x{vm:x} fileoff=0x{fo:x} size=0x{fs:x}")
    offs = [int(x, 0) for x in sys.argv[2:]] or [0x4c0, 0x4c8, 0x4d0, 0x4d8, 0x4e0, 0x4e8, 0x4f0]
    for off in offs:
        q = struct.unpack_from("<Q", data, fo + off)[0]
        print(f"  +0x{off:04x} (vm 0x{vm+off:x}): 0x{q:016x}"
              f"  low48=0x{q & 0x0000FFFFFFFFFFFF:x}"
              f"  low43=0x{q & 0x7FFFFFFFFFF:x}")


if __name__ == "__main__":
    main()
