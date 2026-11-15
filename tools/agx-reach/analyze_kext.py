#!/usr/bin/env python3
"""AGXG18P kext Mach-O parser and cross-reference scanner.

Scans the extracted com.apple.AGXG18P kext (27.0.1 build 24A446) for:
- All Mach-O sections
- References to the OOB-read helper function (0xfffffe0008556f54)
- Vtables containing that function
- OSMetaClass / class registration symbols
- IOUserClient / external method dispatch

Target device: iPhone18,1 / V53AP / t8150 / iOS 27.0.1 (24A446)
"""
import argparse
import struct
import re
from pathlib import Path

KERNEL_BASE = 0xFFFFFE0007000000  # t8150 kernelcache base for 27.x
HELPER_ADDR = 0xFFFFFE0008556F54  # OOB-read helper body (27.0.1)
HELPER_ENTRY = 0xFFFFFE0008556F50  # function entry (bti c)
VTABLE_ADDR = 0xFFFFFE0007ECA388   # suspected vtable


def parse_macho(path):
    data = Path(path).read_bytes()
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
        "<IiiIIIII", data, 0
    )
    if magic != 0xFEEDFACF:
        raise SystemExit(f"not a little-endian 64-bit Mach-O (magic={magic:#x})")

    segments = []
    sections = []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[off + 8:off + 24].rstrip(b"\0").decode("ascii", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            maxprot, initprot, nsects, flag = struct.unpack_from("<IIII", data, off + 56)
            segments.append({
                "name": segname, "vmaddr": vmaddr, "vmsize": vmsize,
                "fileoff": fileoff, "filesize": filesize,
                "initprot": initprot, "nsects": nsects,
            })
            so = off + 72
            for _ in range(nsects):
                sectname = data[so:so + 16].rstrip(b"\0").decode("ascii", "replace")
                seg = data[so + 16:so + 32].rstrip(b"\0").decode("ascii", "replace")
                addr, size = struct.unpack_from("<QQ", data, so + 32)
                offset, align, reloff, nreloc = struct.unpack_from("<IIII", data, so + 48)
                flags2, reserved1, reserved2, reserved3 = struct.unpack_from("<IIII", data, so + 80)
                sections.append({
                    "seg": seg, "sect": sectname, "addr": addr, "size": size,
                    "offset": offset, "align": align, "flags": flags2,
                })
                so += 80
        off += cmdsize
    return data, segments, sections


def va_to_fileoff(sections, va):
    """Convert a virtual address to a file offset using section map."""
    for s in sections:
        if s["addr"] <= va < s["addr"] + s["size"]:
            return s["offset"] + (va - s["addr"])
    return None


def find_refs_to(data, sections, target_va, base=KERNEL_BASE):
    """Find all 8-byte words whose low 32 bits match (target - base) & 0xFFFFFFFF."""
    rel = (target_va - base) & 0xFFFFFFFF
    hits = []
    for s in sections:
        if s["size"] < 8:
            continue
        for i in range(0, s["size"] - 7, 8):
            off = s["offset"] + i
            (val,) = struct.unpack_from("<Q", data, off)
            low = val & 0xFFFFFFFF
            if low == rel:
                hits.append({
                    "va": s["addr"] + i,
                    "val": val,
                    "seg": s["seg"],
                    "sect": s["sect"],
                    "fileoff": off,
                })
    return hits


def find_bl_refs(disasm_path, target_va):
    """Grep disassembly for BL/B instructions targeting the helper."""
    hits = []
    target_hex = f"{target_va:#018x}"
    with open(disasm_path) as f:
        for line in f:
            if f"bl  {target_hex}" in line or f"b  {target_hex}" in line:
                hits.append(line.strip())
    return hits


def find_strings(data, keywords):
    """Find printable strings containing any keyword."""
    strings = re.findall(rb"[\x20-\x7e]{4,}", data)
    results = []
    for s in strings:
        low = s.lower()
        if any(k in low for k in keywords):
            results.append(s.decode("ascii", "replace"))
    return results


def main():
    macho = "G:/REPO/analysis/agx/2701/com.apple.AGXG18P"
    disasm = "G:/REPO/analysis/agx/2701.disasm.txt"

    data, segments, sections = parse_macho(macho)

    print("=== SEGMENTS ===")
    for seg in segments:
        prot = ""
        if seg["initprot"] & 1: prot += "R"
        if seg["initprot"] & 2: prot += "W"
        if seg["initprot"] & 4: prot += "X"
        print(f"  {seg['name']:<24} va={seg['vmaddr']:#018x} size={seg['vmsize']:#x} off={seg['fileoff']:#x} prot={prot}")

    print(f"\n=== SECTIONS ({len(sections)}) ===")
    for s in sections:
        print(f"  {s['seg']}.{s['sect']:<32} va={s['addr']:#018x} size={s['size']:#x} off={s['offset']:#x} flags={s['flags']:#x}")

    rel = (HELPER_ADDR - KERNEL_BASE) & 0xFFFFFFFF
    print(f"\n=== REFS TO HELPER {HELPER_ADDR:#018x} (rel={rel:#010x}) ===")
    hits = find_refs_to(data, sections, HELPER_ADDR)
    for h in hits:
        print(f"  {h['va']:#018x}  val={h['val']:#018x}  {h['seg']}.{h['sect']}")
    print(f"  total: {len(hits)}")

    print(f"\n=== REFS TO HELPER ENTRY {HELPER_ENTRY:#018x} ===")
    hits2 = find_refs_to(data, sections, HELPER_ENTRY)
    for h in hits2:
        print(f"  {h['va']:#018x}  val={h['val']:#018x}  {h['seg']}.{h['sect']}")
    print(f"  total: {len(hits2)}")

    print(f"\n=== REFS TO VTABLE {VTABLE_ADDR:#018x} ===")
    hits3 = find_refs_to(data, sections, VTABLE_ADDR)
    for h in hits3:
        print(f"  {h['va']:#018x}  val={h['val']:#018x}  {h['seg']}.{h['sect']}")
    print(f"  total: {len(hits3)}")

    print(f"\n=== DIRECT BL/B CALLS TO HELPER IN DISASM ===")
    blhits = find_bl_refs(disasm, HELPER_ADDR)
    for h in blhits[:20]:
        print(f"  {h}")
    print(f"  total: {len(blhits)}")

    print(f"\n=== KEYWORD STRINGS ===")
    keywords = [
        b"UserClient", b"ConnectMethod", b"ExternalMethod", b"TargetAndMethod",
        b"IOUserClient", b"OSMetaClass", b"AGXBitmap", b"AGXChannel",
        b"AGX3DChannel", b"AGXCLChannel", b"AGXTAChannel", b"AGXInvalidChannel",
        b"submitBuffer", b"IOGPUChannel", b"IOGPUCommandDescriptor",
        b"kAGXMaxChannelCount", b"site.",
    ]
    strs = find_strings(data, keywords)
    for s in strs[:80]:
        print(f"  {s}")


if __name__ == "__main__":
    main()
