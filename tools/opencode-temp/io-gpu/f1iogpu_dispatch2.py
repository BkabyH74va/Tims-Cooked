#!/usr/bin/env python3
"""f1iogpu_dispatch2.py -- locate IOExternalMethodDispatch arrays by scanning for
8-byte words that point at the kext's own __TEXT.__cstring, then decode the
surrounding 32-byte records.

Also prints a raw hexdump of the region for manual inspection.
"""
import re
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


def main():
    path = sys.argv[1]
    data, sections = parse(path)
    cstr = None
    texec = None
    for seg, sect, saddr, ssize, soff in sections:
        if sect == "__cstring":
            cstr = (saddr, saddr + ssize, soff)
        if seg == "__TEXT_EXEC":
            texec = (saddr, saddr + ssize)
    print(f"cstring: {cstr[0]:#018x}..{cstr[1]:#018x}")
    print(f"text_exec: {texec[0]:#018x}..{texec[1]:#018x}")

    def cstr_at(va):
        if cstr[0] <= va < cstr[1]:
            o = cstr[2] + (va - cstr[0])
            e = data.index(b"\0", o)
            return data[o:e].decode("ascii", "replace")
        return None

    entries = []
    for seg, sect, saddr, ssize, soff in sections:
        if seg != "__DATA_CONST":
            continue
        for i in range(0, ssize - 7, 8):
            (w,) = struct.unpack_from("<Q", data, soff + i)
            n = cstr_at(w)
            if n and re.match(r"^[A-Za-z_][A-Za-z0-9_:]{2,}$", n):
                entries.append((saddr + i, n, soff + i))
    print(f"\n{len(entries)} words pointing into __cstring inside __DATA_CONST")
    for va, n, fo in entries:
        print(f"  {va:#018x} -> {n!r}")

    # Now try to group into 32-byte dispatch records
    print("\n=== decoded 32-byte dispatch records ===")
    for va, n, fo in entries:
        rec = data[fo:fo + 32]
        (fn,) = struct.unpack_from("<Q", rec, 8)
        si, ssi, so, sso = struct.unpack_from("<IIII", rec, 16)
        infn = "TEXT_EXEC" if texec[0] <= fn < texec[1] else "?"
        print(
            f"{va:#018x} {n:<52s} fn={fn:#018x}[{infn}] "
            f"scalarIn={si} structIn={ssi:#x} scalarOut={so} structOut={sso:#x}"
        )


if __name__ == "__main__":
    main()
