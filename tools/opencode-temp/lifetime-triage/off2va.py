#!/usr/bin/env python3
"""Map a kernelcache FILE OFFSET to the owning fileset member and its vmaddr."""
import struct
import sys
from pathlib import Path

KC = Path(r"G:/REPO\firmware\24A446\kernelcache.release.macho")
LC_FILESET_ENTRY = 0x80000035
LC_SEGMENT_64 = 0x19
BASE = 0xFFFFFE0007000000


def cstring_at(data, off, limit=512):
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = off + limit
    return data[off:end].decode("ascii", "replace")


def main():
    target = int(sys.argv[1], 0)
    data = KC.read_bytes()
    _, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_FILESET_ENTRY:
            vmaddr = struct.unpack_from("<Q", data, off + 8)[0]
            foff = struct.unpack_from("<Q", data, off + 16)[0]
            nm = cstring_at(data, off + 32)
            # member's own mach header
            _, _, _, _, ncmds2, _, _, _ = struct.unpack_from("<IiiIIIII", data, foff)
            eoff = foff + 32
            for _ in range(ncmds2):
                ecmd, ecmdsize = struct.unpack_from("<II", data, eoff)
                if ecmd == LC_SEGMENT_64:
                    segname = data[eoff + 8:eoff + 24].rstrip(b"\x00").decode("ascii", "replace")
                    vm, vms, so, ss = struct.unpack_from("<QQQQ", data, eoff + 24)
                    if ss and so <= target < so + ss:
                        print(f"file offset {target:#x} is in {nm} segment {segname}")
                        print(f"   member vmaddr={vmaddr:#018x} seg vm={vm:#018x} file={so:#x}+{ss:#x}")
                        print(f"   delta in file = {target-so:#x}")
                        print(f"   => vmaddr if file-linear = {vm + (target-so):#018x}")
                        print(f"   => vmaddr if base+low32  = {BASE + (target & 0xFFFFFFFF):#018x}")
                eoff += ecmdsize
        off += cmdsize


if __name__ == "__main__":
    main()
