#!/usr/bin/env python3
"""Resolve kernelcache chained-fixup encoded pointers to runtime addresses.

Encoding (observed, see notes in LIFETIME-TRIAGE.md):
    raw_low32 = (target_vmaddr - KERNEL_BASE) - delta(target_member)
where delta(member) = (member.__TEXT.vmaddr - KERNEL_BASE) - member.__TEXT.fileoff
in the kernelcache file.  For com.apple.iokit.CoreAnalyticsFamily this is 0x4000.
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


_MEMBERS = None


def members():
    global _MEMBERS
    if _MEMBERS is not None:
        return _MEMBERS
    data = KC.read_bytes()
    _, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
    off = 32
    out = []
    while off < len(data):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize == 0:
            break
        if cmd == LC_FILESET_ENTRY:
            vmaddr = struct.unpack_from("<Q", data, off + 8)[0]
            foff = struct.unpack_from("<Q", data, off + 16)[0]
            nm = cstring_at(data, off + 32)
            segs = []
            eoff = foff + 32
            try:
                _, _, _, _, ncmds2, _, _, _ = struct.unpack_from("<IiiIIIII", data, foff)
            except struct.error:
                ncmds2 = 0
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
            out.append(dict(name=nm, vmaddr=vmaddr, fileoff=foff, delta=delta, segs=segs))
        off += cmdsize
    _MEMBERS = out
    return out


def resolve(low32):
    """Return [(target, member_name, segment)] candidates for an encoded low32."""
    res = []
    for mem in members():
        t = BASE + low32 + mem["delta"]
        for segname, vm, vms, so, ss in mem["segs"]:
            if segname in ("__TEXT", "__TEXT_EXEC") and vm <= t < vm + vms:
                res.append((t, mem["name"], segname))
    return res


def owner(addr):
    for mem in members():
        for segname, vm, vms, so, ss in mem["segs"]:
            if vm <= addr < vm + vms:
                return mem["name"], segname
    return None, None


if __name__ == "__main__":
    for a in sys.argv[1:]:
        low = int(a, 0) & 0xFFFFFFFF
        print(f"{a}: low={low:#010x}")
        for t, nm, sg in resolve(low):
            print(f"    -> {t:#018x}  {nm} {sg}")
