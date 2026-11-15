#!/usr/bin/env python3
"""Shared helpers for static lifetime triage of extracted kernelcache kexts.

Everything here is read-only against the extracted member files under
tools/opencode-temp/lifetime-triage/extract.
"""
import json
import re
import struct
from pathlib import Path

EXTRACT = Path(r"G:/REPO\tools\opencode-temp\lifetime-triage\extract")
SYMJSON = Path(r"G:/REPO\extraction\extraction\tools\agx-reach\kernel_analysis\kernelcache.release.macho.symbols.json")

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_DATA_IN_CODE = 0x29
LC_FUNCTION_STARTS = 0x26
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_FILESET_ENTRY = 0x80000035


class MachO:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        d = self.data
        magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", d, 0)
        if magic != MH_MAGIC_64:
            raise SystemExit(f"{path}: bad magic {magic:#x}")
        self.ncmds = ncmds
        self.segments = []
        self.sections = []
        self.symtab = None
        self.dysymtab = None
        self.chained_fixups = None
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", d, off)
            if cmd == LC_SEGMENT_64:
                name = d[off + 8:off + 24].rstrip(b"\x00").decode("ascii", "replace")
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", d, off + 24)
                maxprot, initprot = struct.unpack_from("<II", d, off + 56)
                nsects = struct.unpack_from("<I", d, off + 64)[0]
                seg = dict(name=name, vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff,
                           filesize=filesize, maxprot=maxprot, initprot=initprot)
                self.segments.append(seg)
                so = off + 72
                for _ in range(nsects):
                    sectname = d[so:so + 16].rstrip(b"\x00").decode("ascii", "replace")
                    segname = d[so + 16:so + 32].rstrip(b"\x00").decode("ascii", "replace")
                    addr, size = struct.unpack_from("<QQ", d, so + 32)
                    foff = struct.unpack_from("<I", d, so + 48)[0]
                    align, reloff, nreloc, flags = struct.unpack_from("<IIII", d, so + 52)
                    self.sections.append(dict(seg=segname, sect=sectname, addr=addr,
                                              size=size, offset=foff, flags=flags))
                    so += 80
            elif cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", d, off + 8)
                self.symtab = dict(symoff=symoff, nsyms=nsyms, stroff=stroff, strsize=strsize)
            elif cmd == LC_DYSYMTAB:
                self.dysymtab = dict(localsymoff=struct.unpack_from("<I", d, off + 8)[0],
                                     nextdefsym=struct.unpack_from("<I", d, off + 12)[0],
                                     nundefsym=struct.unpack_from("<I", d, off + 16)[0])
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                self.chained_fixups = dict(dataoff=struct.unpack_from("<I", d, off + 8)[0],
                                           datasize=struct.unpack_from("<I", d, off + 12)[0])
            off += cmdsize

    def va_to_off(self, va):
        for s in self.sections:
            if s["addr"] <= va < s["addr"] + s["size"]:
                return s["offset"] + (va - s["addr"])
        for s in self.segments:
            if s["fileoff"] and s["vmaddr"] <= va < s["vmaddr"] + s["vmsize"]:
                return s["fileoff"] + (va - s["vmaddr"])
        return None

    def read(self, va, n):
        o = self.va_to_off(va)
        if o is None:
            return None
        return self.data[o:o + n]

    def u64(self, va):
        b = self.read(va, 8)
        return None if b is None or len(b) < 8 else struct.unpack_from("<Q", b, 0)[0]

    def u32(self, va):
        b = self.read(va, 4)
        return None if b is None or len(b) < 4 else struct.unpack_from("<I", b, 0)[0]

    def sec(self, seg, sect):
        for s in self.sections:
            if s["seg"] == seg and s["sect"] == sect:
                return s
        return None

    def blob(self, seg, sect):
        s = self.sec(seg, sect)
        if not s:
            return b""
        return self.data[s["offset"]:s["offset"] + s["size"]]

    # ---- string helpers -------------------------------------------------
    def cstrings(self, seg="__TEXT", sect="__cstring"):
        s = self.sec(seg, sect)
        if not s:
            return []
        b = self.data[s["offset"]:s["offset"] + s["size"]]
        out = []
        for m in re.finditer(rb"[\x20-\x7e]{3,}", b):
            out.append((s["addr"] + m.start(), m.group().decode("ascii", "replace")))
        return out

    def find_str(self, needle, seg=None, sect=None):
        """Return [(va, text)] for every occurrence of *needle* in cstring-ish data."""
        res = []
        secs = self.sections
        for s in secs:
            if sect and not (s["seg"] == seg and s["sect"] == sect):
                continue
            if not sect and not (s["sect"] in ("__cstring", "__const", "__data", "__os_log",
                                                "__ustring", "__literal4", "__literal8", "__literal16",
                                                "__cstring16", "__gcc_except_tab")):
                continue
            if s["seg"] == "__LINKEDIT":
                continue
            b = self.data[s["offset"]:s["offset"] + s["size"]]
            i = b.find(needle)
            while i >= 0:
                res.append((s["addr"] + i, s["seg"], s["sect"], s["offset"] + i))
                i = b.find(needle, i + 1)
        return res


def load_symjson():
    if not SYMJSON.exists():
        return {}
    j = json.loads(SYMJSON.read_text(encoding="utf-8", errors="replace"))
    out = {}
    for k, v in j.items():
        try:
            out[int(k)] = v
        except ValueError:
            pass
    return out


def sym_at(syms, va):
    return syms.get(va)


def syms_in_range(syms, lo, hi):
    return sorted((a, n) for a, n in syms.items() if lo <= a < hi)


if __name__ == "__main__":
    import sys
    s = load_symjson()
    print("symbols:", len(s))
    lo, hi = (int(sys.argv[1], 0), int(sys.argv[2], 0)) if len(sys.argv) > 2 else (0, 1 << 64)
    n = 0
    for a, name in syms_in_range(s, lo, hi):
        print(f"{a:#018x} {name}")
        n += 1
        if n > 400:
            print("... truncated")
            break
