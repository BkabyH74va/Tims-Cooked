#!/usr/bin/env python3
"""
Broader scan for dispatch tables in AGXG18P kext.
Tries multiple section patterns and more permissive pointer matching.
"""
import struct
from pathlib import Path

KEXT = Path("G:/REPO/analysis/agx/2701/com.apple.AGXG18P")

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
        if cmd == 0x19:
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


def read_u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def is_kernel_ptr(val):
    """Check if value looks like a kernel pointer (0xfffffe00xxxxxxxx)"""
    return (val & 0xFFFF000000000000) == 0xFFFF000000000000


def is_in_text_exec(val):
    """Check if value is in __TEXT_EXEC.__text range"""
    return 0xFFFFFE00084B1960 <= val < 0xFFFFFE0009815000


def main():
    data, segments, sections = parse_macho(KEXT)

    print("=== All segments ===")
    for seg in segments:
        print(f"  {seg['name']}: va={seg['vmaddr']:#018x} size={seg['vmsize']:#x} fileoff={seg['fileoff']:#x}")

    print(f"\n=== All sections ===")
    for s in sections:
        print(f"  {s['seg']}.{s['sect']}: va={s['addr']:#018x} size={s['size']:#x} off={s['offset']:#x}")

    # Scan ALL __DATA_CONST sections for dispatch-like tables
    print("\n=== Scanning all __DATA_CONST sections for dispatch tables ===")
    for s in sections:
        if s["seg"] != "__DATA_CONST":
            continue

        print(f"\n--- {s['seg']}.{s['sect']}: va={s['addr']:#018x} size={s['size']:#x} ---")
        section_data = data[s["offset"]:s["offset"] + s["size"]]

        tables = []
        for i in range(0, s["size"] - 23, 8):
            off = s["offset"] + i
            func_ptr = read_u64(data, off)

            # Check if function pointer looks like a kernel pointer
            if not is_kernel_ptr(func_ptr):
                continue

            scalar_in = read_u32(data, off + 8)
            struct_in = read_u32(data, off + 12)
            scalar_out = read_u32(data, off + 20)
            struct_out = read_u32(data, off + 24)

            # Sanity check
            if scalar_in > 32 or scalar_out > 32:
                continue
            if struct_in > 131072 or struct_out > 131072:
                continue

            # Must have at least one non-zero field to be interesting
            if scalar_in == 0 and struct_in == 0 and scalar_out == 0 and struct_out == 0:
                continue

            tables.append({
                "va": s["addr"] + i,
                "func": func_ptr,
                "scalar_in": scalar_in,
                "struct_in": struct_in,
                "scalar_out": scalar_out,
                "struct_out": struct_out,
            })

        print(f"  Found {len(tables)} potential dispatch entries")
        for idx, t in enumerate(tables[:30]):
            in_text = "IN_TEXT" if is_in_text_exec(t["func"]) else "OUTSIDE"
            print(f"  [{idx:3d}] va={t['va']:#018x} func={t['func']:#018x} [{t['scalar_in']},{t['struct_in']},{t['scalar_out']},{t['struct_out']}] {in_text}")

    # Also look at what's around the AGXDeviceUserClient string
    print("\n=== Around AGXDeviceUserClient string ===")
    # From earlier: string at va=0xfffffe000712c122 (__TEXT.__cstring) fileoff=0x8fe2
    # That's in __TEXT.__cstring, not data. Let's look at __DATA_CONST around the OMAP entries
    
    # Look for any data that references AGXDeviceUserClient or AGXBitmap strings
    for s in sections:
        if s["seg"] != "__DATA_CONST":
            continue
        section_data = data[s["offset"]:s["offset"] + s["size"]]
        # Search for pointers that might point to the cstring page
        cstring_page = 0xFFFFFE000712C000
        for i in range(0, s["size"] - 7, 8):
            off = s["offset"] + i
            val = read_u64(data, off)
            # Check if it's a chained fixup pointing to cstring page
            if (val & 0xFFFFFFFF) == 0x0012C122:  # low 32 bits of AGXDeviceUserClient string
                print(f"  Possible ref to AGXDeviceUserClient at va={s['addr']+i:#018x} val={val:#018x}")


if __name__ == "__main__":
    main()
