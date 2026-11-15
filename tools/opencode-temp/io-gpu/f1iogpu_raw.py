#!/usr/bin/env python3
"""f1iogpu_raw.py -- raw hexdump + word decode of a kext section."""
import struct
import sys
from pathlib import Path

LC_SEGMENT_64 = 0x19


def parse(path):
    data = Path(path).read_bytes()
    _, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
    off = 32
    sections = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8:off + 24].rstrip(b"\0").decode("ascii", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            so = off + 72
            for _ in range(nsects):
                sectname = data[so:so + 16].rstrip(b"\0").decode("ascii", "replace")
                seg = data[so + 16:so + 32].rstrip(b"\0").decode("ascii", "replace")
                saddr, ssize = struct.unpack_from("<QQ", data, so + 32)
                soff = struct.unpack_from("<I", data, so + 48)[0]
                sections.append((seg, sectname, saddr, ssize, soff))
                so += 80
        off += cmdsize
    return data, sections


if __name__ == "__main__":
    path, seg_want, sect_want = sys.argv[1], sys.argv[2], sys.argv[3]
    start = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0
    count = int(sys.argv[5], 0) if len(sys.argv) > 5 else 0x100
    data, sections = parse(path)
    for seg, sect, saddr, ssize, soff in sections:
        if seg == seg_want and sect == sect_want:
            print(f"{seg}.{sect} addr={saddr:#018x} size={ssize:#x} off={soff:#x}")
            blob = data[soff:soff + ssize]
            for i in range(start, min(len(blob), start + count), 8):
                (w,) = struct.unpack_from("<Q", blob, i)
                raw = blob[i:i + 8].hex(" ")
                print(f"  {saddr+i:#018x}  {raw}   {w:#018x}")
