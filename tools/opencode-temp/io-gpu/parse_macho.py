#!/usr/bin/env python3
"""Parse an extracted kext (standalone or prelinked) and report segments/sections."""
import struct
import sys
from pathlib import Path

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB


def parse(path, label=""):
    data = Path(path).read_bytes()
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, _ = struct.unpack_from(
        "<IiiIIIII", data, 0
    )
    print(f"== {label} {path}")
    print(f"   magic={magic:#x} filetype={filetype} ncmds={ncmds} sizeofcmds={sizeofcmds:#x} size={len(data):#x}")
    off = 32
    segs = []
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8:off + 24].rstrip(b"\0").decode("ascii", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            segs.append((segname, vmaddr, vmsize, fileoff, filesize))
            print(
                f"   SEG {segname:<14s} vmaddr={vmaddr:#018x} vmsize={vmsize:#x} "
                f"fileoff={fileoff:#x} filesize={filesize:#x} nsects={nsects}"
            )
            so = off + 72
            for _ in range(nsects):
                sectname = data[so:so + 16].rstrip(b"\0").decode("ascii", "replace")
                seg = data[so + 16:so + 32].rstrip(b"\0").decode("ascii", "replace")
                saddr, ssize = struct.unpack_from("<QQ", data, so + 32)
                soff = struct.unpack_from("<I", data, so + 48)[0]
                print(
                    f"      {seg:<14s}.{sectname:<22s} addr={saddr:#018x} size={ssize:#x} off={soff:#x}"
                )
                so += 80
        else:
            print(f"   LC cmd={cmd:#x} cmdsize={cmdsize:#x}")
        off += cmdsize
    return data, segs


if __name__ == "__main__":
    for p in sys.argv[1:]:
        parse(p)
        print()
