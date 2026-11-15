#!/usr/bin/env python3
"""Shared helpers for the IOSurface / IOMobileGraphicsFamily static analysis.

Parses the 27.0.1 kernelcache MH_FILESET and standalone extracted kexts.
"""
import re
import struct
from pathlib import Path

ROOT = Path(r"G:/REPO")
KC = ROOT / "firmware" / "24A446" / "kernelcache.release.macho"
TEMP = ROOT / "tools" / "opencode-temp"
IOSURFACE = TEMP / "iosurface-extract" / "com.apple.iokit.IOSurface"
IOMGF = TEMP / "iomgf-extract" / "com.apple.iokit.IOMobileGraphicsFamily"

LC_FILESET_ENTRY = 0x80000035
LC_SEGMENT_64 = 0x19


def cstr(data, off, limit=512):
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = off + limit
    return data[off:end].decode("ascii", "replace")


def parse_fileset(data=None):
    """[(name, vmaddr, fileoff, entry_id, cmd_off)] for every MH_FILESET entry."""
    if data is None:
        data = KC.read_bytes()
    magic, _, _, filetype, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
    off = 32
    out = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize == 0:
            break
        if cmd == LC_FILESET_ENTRY:
            vmaddr = struct.unpack_from("<Q", data, off + 8)[0]
            fileoff = struct.unpack_from("<Q", data, off + 16)[0]
            entry_id = struct.unpack_from("<I", data, off + 24)[0]
            out.append((cstr(data, off + 32), vmaddr, fileoff, entry_id, off))
        off += cmdsize
    return out, filetype


def macho_segments(data, base=0):
    """[(segname, vmaddr, vmsize, fileoff, filesize)] for the Mach-O at *base*."""
    _, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, base)
    off = base + 32
    out = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            name = cstr(data, off + 8, 16)
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            out.append((name, vmaddr, vmsize, fileoff, filesize))
        off += cmdsize
    return out


def macho_sections(data, base=0):
    """[(seg, sect, addr, size, fileoff)] for the Mach-O at *base*."""
    _, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, base)
    off = base + 32
    out = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            so = off + 72
            for _ in range(nsects):
                sectname = cstr(data, so, 16)
                seg = cstr(data, so + 16, 16)
                addr, size = struct.unpack_from("<QQ", data, so + 32)
                foff = struct.unpack_from("<I", data, so + 48)[0]
                out.append((seg, sectname, addr, size, foff))
                so += 80
        off += cmdsize
    return out


def load(path):
    return Path(path).read_bytes()


def sections(path):
    data = load(path)
    return data, macho_sections(data)


def va2off(secs, va):
    for seg, sect, addr, size, off in secs:
        if addr <= va < addr + size:
            return off + (va - addr)
    return None


def strings(data, secs, minlen=4):
    """[(va, section, string)] for printable C strings in data sections."""
    out = []
    for seg, sect, addr, size, off in secs:
        if seg in ("__TEXT", "__DATA_CONST", "__DATA"):
            blob = data[off:off + size]
            for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, blob):
                out.append((addr + m.start(), f"{seg}.{sect}", m.group().decode("ascii")))
    return out
