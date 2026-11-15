#!/usr/bin/env python3
"""Dump a kernelcache data table, resolving chained-fixup encoded pointers.

The kernelcache prelink encodes a pointer target as the low 32 bits of
(target - KERNEL_BASE) plus a per-member delta (the difference between the
member's __TEXT virtual address and its kernelcache file offset, relative to
KERNEL_BASE).  For most kexts that delta is 0x4000.
"""
import struct
import sys
from pathlib import Path
import kx

KC = Path(r"G:/REPO\firmware\24A446\kernelcache.release.macho")
BASE = 0xFFFFFE0007000000
LC_FILESET_ENTRY = 0x80000035
LC_SEGMENT_64 = 0x19


def cstring_at(data, off, limit=512):
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = off + limit
    return data[off:end].decode("ascii", "replace")


def fileset_map():
    """name -> (vmaddr, fileoff, delta, [ (segname, vm, vms, fo, fs) ])"""
    data = KC.read_bytes()
    _, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
    off = 32
    out = {}
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_FILESET_ENTRY:
            vmaddr = struct.unpack_from("<Q", data, off + 8)[0]
            foff = struct.unpack_from("<Q", data, off + 16)[0]
            nm = cstring_at(data, off + 32)
            segs = []
            eoff = foff + 32
            _, _, _, _, ncmds2, _, _, _ = struct.unpack_from("<IiiIIIII", data, foff)
            for _ in range(ncmds2):
                ecmd, ecmdsize = struct.unpack_from("<II", data, eoff)
                if ecmd == LC_SEGMENT_64:
                    segname = data[eoff + 8:eoff + 24].rstrip(b"\x00").decode("ascii", "replace")
                    vm, vms, so, ss = struct.unpack_from("<QQQQ", data, eoff + 24)
                    segs.append((segname, vm, vms, so, ss))
                eoff += ecmdsize
            delta = 0
            for segname, vm, vms, so, ss in segs:
                if segname == "__TEXT":
                    delta = (vm - BASE) - so
                    break
            out[nm] = dict(vmaddr=vmaddr, fileoff=foff, delta=delta, segs=segs)
        off += cmdsize
    return out


def main():
    member = sys.argv[1]
    va = int(sys.argv[2], 0)
    count = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x20
    fm = fileset_map()
    m = kx.MachO(kx.EXTRACT / member)
    syms = kx.load_symjson()
    info = fm[member]
    delta = info["delta"]
    print(f"member {member}: delta={delta:#x} vmaddr={info['vmaddr']:#018x}")
    o = m.va_to_off(va)
    if o is None:
        raise SystemExit("va not in member")
    for i in range(count):
        raw = struct.unpack_from("<Q", m.data, o + i * 8)[0]
        low = raw & 0xFFFFFFFF
        cand = BASE + low + delta
        s = syms.get(cand)
        extra = f"   <{s}>" if s else ""
        print(f"{va + i*8:#018x}: raw={raw:#018x} low={low:#010x} -> {cand:#018x}{extra}")


if __name__ == "__main__":
    main()
