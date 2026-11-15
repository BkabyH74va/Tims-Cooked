#!/usr/bin/env python3
"""
Scan AGXG18P kext for IOExternalMethodDispatch tables, accounting for
arm64e PAC-signed pointers.

On arm64e, function pointers are PAC-signed: top byte may be replaced
with a signature. But bits [55:36] of a kernel pointer still contain
the kernel base (0xFE0). So we look for:
  - 8-byte value where bits [55:36] == 0xFE0 (kernel address range)
  - Next 16 bytes: four small uint32s (scalarIn, structIn, scalarOut, structOut)
"""
import struct
from pathlib import Path

KEXT = Path("G:/REPO/analysis/agx/2701/com.apple.AGXG18P")

def parse_macho(path):
    data = path.read_bytes()
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
        "<IiiIIIII", data, 0
    )
    assert magic == 0xFEEDFACF

    sections = []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            segname = data[off + 8:off + 24].rstrip(b"\0").decode("ascii", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            nsects = struct.unpack_from("<I", data, off + 64)[0]
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
    return data, sections


def read_u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def is_kernel_ptr_pac(val):
    """Check if val could be a PAC-signed kernel pointer.
    Kernel base on t8150 is 0xFFFFFE0000000000.
    Bits [55:36] should be 0xFE0 for any kernel address.
    """
    bits_55_36 = (val >> 36) & 0xFFFFF
    return bits_55_36 == 0xFE0


def is_small_uint32(val, max_val=0x10000):
    return 0 <= val <= max_val


def main():
    data, sections = parse_macho(KEXT)

    print(f"Kext size: {len(data):,} bytes")
    print()

    # Scan all __DATA_CONST sections
    for s in sections:
        if s["seg"] != "__DATA_CONST":
            continue

        section_data = data[s["offset"]:s["offset"] + s["size"]]
        print(f"Scanning {s['seg']}.{s['sect']} ({s['size']:,} bytes)...")

        tables = []
        for i in range(0, s["size"] - 23, 8):
            off = s["offset"] + i
            func_ptr = read_u64(data, off)

            if not is_kernel_ptr_pac(func_ptr):
                continue

            scalar_in = read_u32(data, off + 8)
            struct_in = read_u32(data, off + 12)
            scalar_out = read_u32(data, off + 16)
            struct_out = read_u32(data, off + 20)

            # Sanity checks: small values only
            if not is_small_uint32(scalar_in, 64):
                continue
            if not is_small_uint32(struct_in, 65536):
                continue
            if not is_small_uint32(scalar_out, 64):
                continue
            if not is_small_uint32(struct_out, 65536):
                continue

            tables.append({
                "va": s["addr"] + i,
                "func": func_ptr,
                "scalar_in": scalar_in,
                "struct_in": struct_in,
                "scalar_out": scalar_out,
                "struct_out": struct_out,
            })

        print(f"  Found {len(tables)} candidate dispatch entries")
        for t in tables:
            print(f"  VA={t['va']:#018x} func={t['func']:#018x} "
                  f"scalarIn={t['scalar_in']} structIn={t['struct_in']} "
                  f"scalarOut={t['scalar_out']} structOut={t['struct_out']}")

    print("\nDone scanning.")


if __name__ == "__main__":
    main()
