#!/usr/bin/env python3
"""f1iogpu: search the WHOLE kernelcache for ASCII strings and attribute them to the
owning fileset member + section (excluding the shared __LINKEDIT).

Handles the prelinked layout:
  LC_FILESET_ENTRY = 0x80000035, name at +32
  LC_SEGMENT_64 fileoff @ +40, filesize @ +48 (ABSOLUTE into kernelcache)
"""
import re
import struct
import sys
from pathlib import Path

KC = Path(r"G:/REPO\firmware\24A446\kernelcache.release.macho")
LC_SEGMENT_64 = 0x19
LC_FILESET_ENTRY = 0x80000035

data = KC.read_bytes()
_, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)

members = []
off = 32
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == LC_FILESET_ENTRY:
        noff = off + 32
        name = data[noff:data.index(b"\0", noff)].decode("ascii", "replace")
        vmaddr = struct.unpack_from("<Q", data, off + 8)[0]
        foff = struct.unpack_from("<Q", data, off + 16)[0]
        members.append((name, vmaddr, foff))
    off += cmdsize

# Build section ranges, attributed to owner
sections = []
for name, vmaddr, foff in members:
    mn = struct.unpack_from("<I", data, foff + 16)[0]
    mo = foff + 32
    for _ in range(mn):
        cmd, cmdsize = struct.unpack_from("<II", data, mo)
        if cmd == LC_SEGMENT_64:
            segname = data[mo + 8:mo + 24].rstrip(b"\0").decode("ascii", "replace")
            s_vmaddr, s_vmsize, s_fileoff, s_filesize = struct.unpack_from("<QQQQ", data, mo + 24)
            nsects = struct.unpack_from("<I", data, mo + 64)[0]
            so = mo + 72
            for _ in range(nsects):
                sectname = data[so:so + 16].rstrip(b"\0").decode("ascii", "replace")
                saddr, ssize = struct.unpack_from("<QQ", data, so + 32)
                soff = struct.unpack_from("<I", data, so + 48)[0]
                sections.append(
                    (name, segname, sectname, soff, ssize, saddr, s_vmaddr, s_fileoff)
                )
                so += 80
        mo += cmdsize

# linkedit ranges (shared)
le_ranges = set()
for name, vmaddr, foff in members:
    mn = struct.unpack_from("<I", data, foff + 16)[0]
    mo = foff + 32
    for _ in range(mn):
        cmd, cmdsize = struct.unpack_from("<II", data, mo)
        if cmd == LC_SEGMENT_64:
            segname = data[mo + 8:mo + 24].rstrip(b"\0").decode("ascii", "replace")
            if segname == "__LINKEDIT":
                _, _, s_fileoff, s_filesize = struct.unpack_from("<QQQQ", data, mo + 24)
                le_ranges.add((s_fileoff, s_filesize))
        mo += cmdsize


def owner_of(fileoff):
    for (name, seg, sect, soff, ssize, saddr, s_vmaddr, s_fileoff) in sections:
        if ssize and soff <= fileoff < soff + ssize:
            return name, seg, sect, saddr + (fileoff - soff), fileoff
    for (fo, fs) in le_ranges:
        if fo <= fileoff < fo + fs:
            return "<SHARED __LINKEDIT>", "__LINKEDIT", "", 0, fileoff
    return None, None, None, None, None


if __name__ == "__main__":
    pats = sys.argv[1:] or ["ASGR"]
    for pat in pats:
        print(f"\n########## pattern: {pat!r}")
        # byte search for plain substring
        pb = pat.encode()
        start = 0
        hits = 0
        while True:
            i = data.find(pb, start)
            if i < 0:
                break
            start = i + 1
            nm, sg, sc, va, fo = owner_of(i)
            # show context
            ctx = data[max(0, i - 32):i + len(pb) + 48]
            printable = "".join(chr(c) if 32 <= c < 127 else "." for c in ctx)
            print(f"  kc_off={i:#010x} owner={nm} {sg}.{sc} va={va if va is None else hex(va)}")
            print(f"      ctx: {printable}")
            hits += 1
        print(f"  -> {hits} hits")
