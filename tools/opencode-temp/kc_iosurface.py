#!/usr/bin/env python3
"""Extract + disassemble the IOSurface kext from an Apple kernelcache fileset.

The kernelcache.release.macho is a Mach-O fileset whose members are prelinked:
segment file offsets are ABSOLUTE into the kernelcache file.

Usage:
    python kc_iosurface.py <kernelcache> [kextname]
    python kc_iosurface.py <kernelcache> --find <hex pattern>   # locate instruction
"""
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

LC_FILESET_ENTRY = 0x80000035
LC_SEGMENT_64 = 0x19
LC_FUNCTION_STARTS = 0x26
MH_MAGIC_64 = 0xFEEDFACF


def cstring_at(data, off, limit=512):
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = off + limit
    return data[off:end].decode("ascii", "replace")


def parse_fileset(data):
    magic, _, _, filetype, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
    if magic != MH_MAGIC_64:
        raise SystemExit(f"unexpected magic {magic:#x}")
    off = 32
    entries = []
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize == 0:
            break
        if cmd == LC_FILESET_ENTRY:
            vmaddr = struct.unpack_from("<Q", data, off + 8)[0]
            fileoff = struct.unpack_from("<Q", data, off + 16)[0]
            name = cstring_at(data, off + 32)
            entries.append({"name": name, "vmaddr": vmaddr, "fileoff": fileoff})
        off += cmdsize
    return entries, filetype


def member_load_commands(data, foff):
    _, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, foff)
    eoff = foff + 32
    cmds = []
    for _ in range(ncmds):
        if eoff + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from("<II", data, eoff)
        if cmdsize == 0:
            break
        cmds.append((cmd, eoff, cmdsize))
        eoff += cmdsize
    return cmds


def member_segments(data, foff):
    segs = {}
    for cmd, eoff, cmdsize in member_load_commands(data, foff):
        if cmd != LC_SEGMENT_64:
            continue
        name = data[eoff + 8:eoff + 24].rstrip(b"\x00").decode("ascii", "replace")
        vmaddr = struct.unpack_from("<Q", data, eoff + 24)[0]
        vmsize = struct.unpack_from("<Q", data, eoff + 32)[0]
        fileoff = struct.unpack_from("<Q", data, eoff + 40)[0]
        filesize = struct.unpack_from("<Q", data, eoff + 48)[0]
        segs[name] = (vmaddr, vmsize, fileoff, filesize)
    return segs


def function_starts(data, foff, base=0):
    out = []
    for cmd, eoff, cmdsize in member_load_commands(data, foff):
        if cmd != LC_FUNCTION_STARTS:
            continue
        dataoff = struct.unpack_from("<I", data, eoff + 8)[0]
        size = struct.unpack_from("<I", data, eoff + 12)[0]
        p = dataoff
        end = dataoff + size
        addr = 0
        while p < end:
            val = 0
            shift = 0
            while True:
                b = data[p]
                p += 1
                val |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            if val == 0:
                break
            addr += val
            out.append(base + addr)
    return out


def text_of(data, segs):
    seg = segs.get("__TEXT_EXEC") or segs.get("__TEXT")
    vmaddr, vmsize, fileoff, filesize = seg
    return vmaddr, data[fileoff:fileoff + filesize]


def disasm(md, text, base, start, end):
    off = start - base
    n = end - start
    for i in md.disasm(text[off:off + n], start):
        print("  %016x  %-10s %s" % (i.address, i.mnemonic, i.op_str))


def main():
    kc = Path(sys.argv[1])
    data = kc.read_bytes()
    entries, filetype = parse_fileset(data)
    name = "com.apple.iokit.IOSurface"
    if "--kext" in sys.argv:
        name = sys.argv[sys.argv.index("--kext") + 1]
    hit = [e for e in entries if e["name"] == name]
    if not hit:
        print("not found; candidates:")
        for e in entries:
            if "urface" in e["name"] or "urface" in e["name"]:
                print("  ", e["name"], hex(e["fileoff"]))
        return
    e = hit[0]
    print(f"kext {e['name']} vmaddr=0x{e['vmaddr']:x} fileoff=0x{e['fileoff']:x}")
    segs = member_segments(data, e["fileoff"])
    for s, (vm, vms, fo, fs) in segs.items():
        print(f"  seg {s:<14s} vm=0x{vm:x} vmsize=0x{vms:x} fileoff=0x{fo:x} filesize=0x{fs:x}")
    base, text = text_of(data, segs)
    fstarts = function_starts(data, e["fileoff"], e["vmaddr"])
    print(f"  __TEXT base 0x{base:x} size 0x{len(text):x}; {len(fstarts)} function starts")

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False

    if "--calls" in sys.argv:
        i = sys.argv.index("--calls")
        targets = {}
        for t in sys.argv[i + 1].split(","):
            targets[int(t, 0)] = []
        for ins in md.disasm(text, base):
            if ins.mnemonic in ("bl", "b") and ins.op_str.startswith("#"):
                try:
                    tgt = int(ins.op_str[1:], 16)
                except ValueError:
                    continue
                if tgt in targets:
                    targets[tgt].append(ins.address)
        for tgt, sites in targets.items():
            print(f"target 0x{tgt:x}: {len(sites)} sites")
            for s in sites:
                prev = None
                for f in fstarts:
                    if f > s:
                        break
                    prev = f
                print(f"   site 0x{s:x}  in fn 0x{prev:x}")
        return

    if "--range" in sys.argv:
        i = sys.argv.index("--range")
        s = int(sys.argv[i + 1], 0)
        e = int(sys.argv[i + 2], 0)
        print(f"range 0x{s:x}..0x{e:x}")
        disasm(md, text, base, s, e)
        return

    if "--find" in sys.argv:
        pat = bytes.fromhex(sys.argv[sys.argv.index("--find") + 1].replace(" ", ""))
        hits = []
        pos = 0
        while True:
            pos = text.find(pat, pos)
            if pos < 0:
                break
            hits.append(base + pos)
            pos += 4
        print(f"pattern {pat.hex()} hits: {[hex(h) for h in hits]}")
        for h in hits:
            # find enclosing function
            prev = None
            for f in fstarts:
                if f > h:
                    break
                prev = f
            nxt = None
            for f in fstarts:
                if f > h:
                    nxt = f
                    break
            print(f"--- hit 0x{h:x} in function 0x{prev:x}..0x{nxt:x} (size {nxt-prev})")
        return

    if "--findfn" in sys.argv:
        pat = bytes.fromhex(sys.argv[sys.argv.index("--findfn") + 1].replace(" ", ""))
        pos = 0
        seen = set()
        while True:
            pos = text.find(pat, pos)
            if pos < 0:
                break
            h = base + pos
            prev = None
            for f in fstarts:
                if f > h:
                    break
                prev = f
            nxt = None
            for f in fstarts:
                if f > h:
                    nxt = f
                    break
            if prev not in seen:
                seen.add(prev)
                print(f"=== hit 0x{h:x} -> function 0x{prev:x}..0x{nxt:x}")
                disasm(md, text, base, prev, nxt)
            pos += 4
        return

    if "--fn" in sys.argv:
        addr = int(sys.argv[sys.argv.index("--fn") + 1], 0)
        idx = None
        for i, f in enumerate(fstarts):
            if f == addr:
                idx = i
        if idx is None:
            print("function start not found")
            return
        start = fstarts[idx]
        end = fstarts[idx + 1] if idx + 1 < len(fstarts) else start + 0x400
        print(f"function 0x{start:x}..0x{end:x}")
        disasm(md, text, base, start, end)
        return

    print("  first 40 function starts:", [hex(f) for f in fstarts[:40]])


if __name__ == "__main__":
    main()
