#!/usr/bin/env python3
"""
Scan com.apple.AGXG18P kext for IOExternalMethodDispatch tables.

IOExternalMethodDispatch structure (24 bytes):
    uint64  function          ; pointer into __TEXT_EXEC.__text
    uint32  scalarInputCount  ; number of 64-bit scalar inputs
    uint32  structInputSize   ; size of structure input in bytes
    uint32  scalarOutputCount ; number of 64-bit scalar outputs
    uint32  structOutputSize  ; size of structure output in bytes

Target: iPhone18,1 / V53AP / t8150 / iOS 27.0.1 (24A446)
Kext: com.apple.AGXG18P (extracted from kernelcache)
"""

import struct
from pathlib import Path

KEXT = Path("G:/REPO/analysis/agx/2701/com.apple.AGXG18P")
DISASM = Path("G:/REPO/analysis/agx/2701.disasm.txt")

KERNEL_BASE = 0xFFFFFE0007000000

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
                "initprot": initprot,
            })
            so = off + 72
            for _ in range(nsects):
                sectname = data[so:so + 16].rstrip(b"\0").decode("ascii", "replace")
                seg = data[so + 16:so + 32].rstrip(b"\0").decode("ascii", "replace")
                addr, size = struct.unpack_from("<QQ", data, so + 32)
                offset = struct.unpack_from("<I", data, so + 48)[0]
                sections.append({
                    "seg": seg, "sect": sectname, "addr": addr, "size": size,
                    "offset": offset,
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


def find_sections(sections, seg_name, sect_name):
    for s in sections:
        if s["seg"] == seg_name and s["sect"] == sect_name:
            return s
    return None


def main():
    data, segments, sections = parse_macho(KEXT)

    print(f"Kext size: {len(data):,} bytes")
    print()

    # Find key sections
    text_exec = find_sections(sections, "__TEXT_EXEC", "__text")
    data_const = find_sections(sections, "__DATA_CONST", "__const")

    if not text_exec or not data_const:
        print("ERROR: Could not find __TEXT_EXEC.__text or __DATA_CONST.__const")
        print("Available sections:")
        for s in sections:
            print(f"  {s['seg']}.{s['sect']}: va={s['addr']:#018x} size={s['size']:#x}")
        return

    text_start = text_exec["addr"]
    text_end = text_exec["addr"] + text_exec["size"]
    const_start = data_const["addr"]
    const_end = data_const["addr"] + data_const["size"]

    print(f"__TEXT_EXEC.__text: va={text_start:#018x} size={text_exec['size']:#x}")
    print(f"__DATA_CONST.__const: va={const_start:#018x} size={data_const['size']:#x}")
    print()

    # Read the __DATA_CONST.__const section data
    const_off = data_const["offset"]
    const_size = data_const["size"]
    const_data = data[const_off:const_off + const_size]

    print(f"Scanning __DATA_CONST.__const ({const_size:,} bytes) for IOExternalMethodDispatch tables...")
    print()

    tables = []
    for i in range(0, const_size - 23, 8):
        off = const_off + i
        va = const_start + i

        # First 8 bytes: function pointer (must be in __TEXT_EXEC.__text)
        func_ptr = read_u64(data, off)
        if not (text_start <= func_ptr < text_end):
            continue

        # Next 16 bytes: four uint32 values
        scalar_in = read_u32(data, off + 8)
        struct_in = read_u32(data, off + 12)
        scalar_out = read_u32(data, off + 16)
        struct_out = read_u32(data, off + 20)

        # Sanity check: scalar counts should be small (<= 16), struct sizes reasonable (<= 4096)
        # Allow reasonable ranges
        if scalar_in > 16 or scalar_out > 16:
            continue
        if struct_in > 65536 or struct_out > 65536:
            continue

        # Valid table entry found
        tables.append({
            "va": va,
            "func": func_ptr,
            "scalar_in": scalar_in,
            "struct_in": struct_in,
            "scalar_out": scalar_out,
            "struct_out": struct_out,
            "offset_in_section": i,
        })

    print(f"Found {len(tables)} potential IOExternalMethodDispatch entries")
    print()
    print(f"{'Idx':>4} {'VA':>18} {'FuncVA':>18} {'ScalarIn':>9} {'StructIn':>9} {'ScalarOut':>10} {'StructOut':>10}")
    print("-" * 85)

    for idx, t in enumerate(tables):
        print(f"{idx:>4} {t['va']:#018x} {t['func']:#018x} {t['scalar_in']:>9} {t['struct_in']:>9} {t['scalar_out']:>10} {t['struct_out']:>10}")

    # Save results
    out = Path("G:/REPO/tools/agx-reach/kernel_analysis/agxg18p_dispatch_tables.txt")
    with open(out, "w") as f:
        f.write(f"AGXG18P IOExternalMethodDispatch tables\n")
        f.write(f"Kext: {KEXT}\n")
        f.write(f"__TEXT_EXEC.__text: {text_start:#018x} - {text_end:#018x}\n")
        f.write(f"__DATA_CONST.__const: {const_start:#018x} - {const_end:#018x}\n")
        f.write(f"\n{'Idx':>4} {'VA':>18} {'FuncVA':>18} {'ScalarIn':>9} {'StructIn':>9} {'ScalarOut':>10} {'StructOut':>10}\n")
        f.write("-" * 85 + "\n")
        for idx, t in enumerate(tables):
            f.write(f"{idx:>4} {t['va']:#018x} {t['func']:#018x} {t['scalar_in']:>9} {t['struct_in']:>9} {t['scalar_out']:>10} {t['struct_out']:>10}\n")

    print(f"\nResults saved to: {out}")


if __name__ == "__main__":
    main()
