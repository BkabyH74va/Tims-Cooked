#!/usr/bin/env python3
"""f1iogpu_dispatch.py -- find IOKit IOExternalMethodDispatch tables in an extracted kext.

IOExternalMethodDispatch (64-bit):
    const char *methodName;         // +0
    void *(*method)(...);            // +8
    uint32_t checkScalarInputCount;  // +16
    uint32_t checkStructureInputSize;// +20
    uint32_t checkScalarOutputCount; // +24
    uint32_t checkStructureOutputSize;// +28
                                  // total 32 bytes, padded to 32

We locate them by scanning __DATA_CONST.__const for 8-byte words that point into
the kext's __TEXT.__cstring, then interpreting the following words.
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
    segs = []
    sections = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8:off + 24].rstrip(b"\0").decode("ascii", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            segs.append((segname, vmaddr, vmsize, fileoff, filesize))
            so = off + 72
            for _ in range(nsects):
                sectname = data[so:so + 16].rstrip(b"\0").decode("ascii", "replace")
                seg = data[so + 16:so + 32].rstrip(b"\0").decode("ascii", "replace")
                saddr, ssize = struct.unpack_from("<QQ", data, so + 32)
                soff = struct.unpack_from("<I", data, so + 48)[0]
                sections.append((seg, sectname, saddr, ssize, soff))
                so += 80
        off += cmdsize
    return data, segs, sections


def cstring_at(data, sections, va):
    for seg, sect, saddr, ssize, soff in sections:
        if sect == "__cstring" and saddr <= va < saddr + ssize:
            o = soff + (va - saddr)
            e = data.index(b"\0", o)
            return data[o:e].decode("ascii", "replace")
    return None


def text_va_range(sections):
    for seg, sect, saddr, ssize, soff in sections:
        if seg == "__TEXT_EXEC":
            return saddr, saddr + ssize
    return None


def main():
    path = sys.argv[1]
    data, segs, sections = parse(path)
    tr = text_va_range(sections)
    print(f"file: {path}")
    print(f"__TEXT_EXEC range: {tr[0]:#018x}..{tr[1]:#018x}")
    hits = []
    for seg, sect, saddr, ssize, soff in sections:
        if sect != "__const":
            continue
        print(f"scanning {seg}.{sect} addr={saddr:#018x} size={ssize:#x} off={soff:#x}")
        for i in range(0, ssize - 31, 8):
            (nameptr,) = struct.unpack_from("<Q", data, soff + i)
            name = cstring_at(data, sections, nameptr)
            if not name or not re.match(r"^[A-Za-z_][A-Za-z0-9_:]*$", name):
                continue
            (fn,) = struct.unpack_from("<Q", data, soff + i + 8)
            if not (tr[0] <= fn < tr[1]):
                continue
            si, ssi, so, sso = struct.unpack_from("<IIII", data, soff + i + 16)
            hits.append((saddr + i, name, fn, si, ssi, so, sso))
    print(f"\n=== {len(hits)} dispatch entries ===")
    for va, name, fn, si, ssi, so, sso in hits:
        print(
            f"{va:#018x}  name={name:<50s} fn={fn:#018x} "
            f"scalarIn={si} structIn={ssi:#x} scalarOut={so} structOut={sso:#x}"
        )


if __name__ == "__main__":
    main()
