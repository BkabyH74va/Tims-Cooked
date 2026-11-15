#!/usr/bin/env python3
"""f1iogpu_pat.py -- search the whole kernelcache for 4-byte instruction encodings,
attributing hits to fileset member + section.

usage: f1iogpu_pat.py <hex32-low> [<hex32-high>] ...
  each arg is a 4-byte little-endian word in hex (e.g. 7131a11f)
"""
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
        members.append((name, struct.unpack_from("<Q", data, off + 8)[0], struct.unpack_from("<Q", data, off + 16)[0]))
    off += cmdsize

sections = []
le = set()
for name, vmaddr, foff in members:
    mn = struct.unpack_from("<I", data, foff + 16)[0]
    mo = foff + 32
    for _ in range(mn):
        cmd, cmdsize = struct.unpack_from("<II", data, mo)
        if cmd == LC_SEGMENT_64:
            segname = data[mo + 8:mo + 24].rstrip(b"\0").decode("ascii", "replace")
            s_vmaddr, s_vmsize, s_fileoff, s_filesize = struct.unpack_from("<QQQQ", data, mo + 24)
            nsects = struct.unpack_from("<I", data, mo + 64)[0]
            if segname == "__LINKEDIT":
                le.add((s_fileoff, s_filesize))
            so = mo + 72
            for _ in range(nsects):
                sectname = data[so:so + 16].rstrip(b"\0").decode("ascii", "replace")
                saddr, ssize = struct.unpack_from("<QQ", data, so + 32)
                soff = struct.unpack_from("<I", data, so + 48)[0]
                sections.append((name, segname, sectname, soff, ssize, saddr))
                so += 80
        mo += cmdsize

sections.sort(key=lambda s: s[3])


def owner(fo):
    for (n, sg, sc, soff, ssize, saddr) in sections:
        if ssize and soff <= fo < soff + ssize:
            return n, sg, sc, saddr + (fo - soff)
    for (a, b) in le:
        if a <= fo < a + b:
            return "<SHARED __LINKEDIT>", "__LINKEDIT", "", None
    return None, None, None, None


for arg in sys.argv[1:]:
    pat = bytes.fromhex(arg)[::-1]
    print(f"\n##### pattern {arg} (LE bytes {pat.hex(' ')})")
    start = 0
    n = 0
    while True:
        i = data.find(pat, start)
        if i < 0:
            break
        start = i + 1
        nm, sg, sc, va = owner(i)
        print(f"  kc_off={i:#010x} owner={nm} {sg}.{sc} va={'?' if va is None else format(va, '#018x')}")
        n += 1
    print(f"  -> {n} hit(s)")
