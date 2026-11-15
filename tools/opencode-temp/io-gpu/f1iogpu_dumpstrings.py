#!/usr/bin/env python3
"""f1iogpu: dump all NUL-terminated ASCII strings from a given fileset member's
non-LINKEDIT sections, with VA attribution.

usage: f1iogpu_dumpstrings.py <member-name> [regex-filter]
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
        members.append((name, struct.unpack_from("<Q", data, off + 8)[0], struct.unpack_from("<Q", data, off + 16)[0]))
    off += cmdsize

want = sys.argv[1]
filt = re.compile(sys.argv[2]) if len(sys.argv) > 2 else None

for name, vmaddr, foff in members:
    if name != want:
        continue
    mn = struct.unpack_from("<I", data, foff + 16)[0]
    mo = foff + 32
    for _ in range(mn):
        cmd, cmdsize = struct.unpack_from("<II", data, mo)
        if cmd == LC_SEGMENT_64:
            segname = data[mo + 8:mo + 24].rstrip(b"\0").decode("ascii", "replace")
            nsects = struct.unpack_from("<I", data, mo + 64)[0]
            so = mo + 72
            for _ in range(nsects):
                sectname = data[so:so + 16].rstrip(b"\0").decode("ascii", "replace")
                saddr, ssize = struct.unpack_from("<QQ", data, so + 32)
                soff = struct.unpack_from("<I", data, so + 48)[0]
                if ssize and segname != "__LINKEDIT":
                    blob = data[soff:soff + ssize]
                    base = saddr
                    for m in re.finditer(rb"[\x20-\x7e]{4,}", blob):
                        s = m.group().decode("ascii")
                        if filt and not filt.search(s):
                            continue
                        print(f"{base + m.start():#018x} {segname}.{sectname:<16s} {s}")
                so += 80
        mo += cmdsize
