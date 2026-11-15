#!/usr/bin/env python3
"""Read the raw kernelcache bytes for a fileset member: its segment/section
layout straight out of the kernelcache (prelinked, absolute file offsets)."""
import struct
import sys
from pathlib import Path

KC = Path(r"G:/REPO\firmware\24A446\kernelcache.release.macho")
LC_FILESET_ENTRY = 0x80000035
LC_SEGMENT_64 = 0x19


def cstring_at(data, off, limit=512):
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = off + limit
    return data[off:end].decode("ascii", "replace")


def main():
    name = sys.argv[1]
    data = KC.read_bytes()
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
    off = 32
    entry = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_FILESET_ENTRY:
            vmaddr = struct.unpack_from("<Q", data, off + 8)[0]
            fileoff = struct.unpack_from("<Q", data, off + 16)[0]
            nm = cstring_at(data, off + 32)
            if nm == name:
                entry = (vmaddr, fileoff)
                break
        off += cmdsize
    if not entry:
        raise SystemExit("not found")
    vmaddr, foff = entry
    print(f"{name}: fileset vmaddr={vmaddr:#018x} fileoff={foff:#x}")
    m = KC.read_bytes()[foff:foff + 0x1000]
    _, _, _, _, ncmds2, _, _, _ = struct.unpack_from("<IiiIIIII", m, 0)
    eoff = 32
    for _ in range(ncmds2):
        ecmd, ecmdsize = struct.unpack_from("<II", m, eoff)
        if ecmd == LC_SEGMENT_64:
            segname = m[eoff + 8:eoff + 24].rstrip(b"\x00").decode("ascii", "replace")
            vm, vms, so, ss = struct.unpack_from("<QQQQ", m, eoff + 24)
            nsects = struct.unpack_from("<I", m, eoff + 64)[0]
            print(f"  SEG {segname:<14s} vm={vm:#018x}-{vm+vms:#018x} file={so:#x}+{ss:#x}")
            so2 = eoff + 72
            for _ in range(nsects):
                sn = m[so2:so2 + 16].rstrip(b"\x00").decode("ascii", "replace")
                sg = m[so2 + 16:so2 + 32].rstrip(b"\x00").decode("ascii", "replace")
                addr, size = struct.unpack_from("<QQ", m, so2 + 32)
                fo = struct.unpack_from("<I", m, so2 + 48)[0]
                print(f"      {sg}.{sn:<24s} {addr:#018x} sz={size:#x} fileoff={fo:#x}")
                so2 += 80
        elif ecmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", m, eoff + 8)
            print(f"  LC_SYMTAB symoff={symoff:#x} nsyms={nsyms} stroff={stroff:#x} strsize={strsize:#x}")
        elif ecmd == LC_DYSYMTAB:
            print("  LC_DYSYMTAB")
        eoff += ecmdsize


if __name__ == "__main__":
    main()
