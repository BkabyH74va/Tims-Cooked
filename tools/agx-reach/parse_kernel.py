#!/usr/bin/env python3
"""Parse iOS 27.0.1 kernelcache (iPhone18,1/t8150/24A446) to find fg_cred/so_cred leads."""
import struct
import re
from pathlib import Path

KC = Path("G:/REPO/firmware/24A446/kernelcache.release.macho")
KERNEL_BASE = 0xFFFFFE0007000000  # t8150 kernelcache base for 27.x

def parse_macho(path):
    data = path.read_bytes()
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


def va_to_off(sections, va):
    for s in sections:
        if s["addr"] <= va < s["addr"] + s["size"]:
            return s["offset"] + (va - s["addr"])
    return None


def read_u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def read_u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def main():
    data, segments, sections = parse_macho(KC)
    
    print(f"Kernelcache size: {len(data):,} bytes")
    print(f"Kernel base: {KERNEL_BASE:#018x}")
    print()
    
    # List segments
    print("=== SEGMENTS ===")
    for seg in segments:
        prot = ""
        if seg["initprot"] & 1: prot += "R"
        if seg["initprot"] & 2: prot += "W"
        if seg["initprot"] & 4: prot += "X"
        print(f"  {seg['name']:<24} va={seg['vmaddr']:#018x} size={seg['vmsize']:#x} off={seg['fileoff']:#x} prot={prot}")
    
    # Find __TEXT_EXEC.__text
    text_sec = None
    for s in sections:
        if s["seg"] == "__TEXT_EXEC" and s["sect"] == "__text":
            text_sec = s
            break
    
    if text_sec:
        print(f"\n=== __TEXT_EXEC.__text ===")
        print(f"  va={text_sec['addr']:#018x} size={text_sec['size']:#x} off={text_sec['offset']:#x}")
    
    print(f"\n=== TOTAL SECTIONS: {len(sections)} ===")
    
    # Save the raw text section to a file for further analysis
    if text_sec:
        text_data = data[text_sec["offset"]:text_sec["offset"] + text_sec["size"]]
        out = Path("G:/REPO/tools/agx-reach/kernel_text.bin")
        out.write_bytes(text_data)
        print(f"\nSaved __TEXT_EXEC.__text to {out} ({len(text_data):,} bytes)")
    
    # Known cred accessor addresses from evidence
    cred_reader_va = 0xFFFFFE000AC4B5A0  # t_tro reader
    proc_reader_va = 0xFFFFFE000B0DB174  # p_proc_ro reader
    
    print(f"\n=== Known cred accessors ===")
    print(f"  t_tro reader: {cred_reader_va:#018x}")
    print(f"  p_proc_ro reader: {proc_reader_va:#018x}")
    
    # Convert to file offsets
    cred_off = va_to_off(sections, cred_reader_va)
    proc_off = va_to_off(sections, proc_reader_va)
    print(f"  t_tro reader file off: {cred_off:#x}")
    print(f"  p_proc_ro reader file off: {proc_off:#x}")


if __name__ == "__main__":
    main()
