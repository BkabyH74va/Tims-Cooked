#!/usr/bin/env python3
"""AGXG18P: find IOExternalMethodDispatch tables in __DATA_CONST.__const."""
import struct
from pathlib import Path

MACHO = Path("G:/REPO/analysis/agx/2701/com.apple.AGXG18P")
KERNEL_BASE = 0xFFFFFE0007000000

def parse_macho(path):
    data = path.read_bytes()
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
    assert magic == 0xFEEDFACF
    sections = []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            segname = data[off + 8:off + 24].rstrip(b"\0").decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            so = off + 72
            for _ in range(nsects):
                sectname = data[so:so + 16].rstrip(b"\0").decode()
                seg = data[so + 16:so + 32].rstrip(b"\0").decode()
                addr, size = struct.unpack_from("<QQ", data, so + 32)
                offset = struct.unpack_from("<I", data, so + 48)[0]
                sections.append({"seg": seg, "sect": sectname, "addr": addr,
                                "size": size, "offset": offset})
                so += 80
        off += cmdsize
    return data, sections


def read_u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def main():
    data, sections = parse_macho(MACHO)

    # Find __DATA_CONST.__const section
    const_sec = None
    text_exec_sec = None
    for s in sections:
        if s["seg"] == "__DATA_CONST" and s["sect"] == "__const":
            const_sec = s
        if s["seg"] == "__TEXT_EXEC" and s["sect"] == "__text":
            text_exec_sec = s

    if not const_sec or not text_exec_sec:
        print("Could not find required sections")
        return

    text_start = text_exec_sec["addr"]
    text_end = text_exec_sec["addr"] + text_exec_sec["size"]

    print(f"__DATA_CONST.__const: va={const_sec['addr']:#018x} size={const_sec['size']:#x}")
    print(f"__TEXT_EXEC.__text: va={text_start:#018x} size={text_exec_sec['size']:#x}")
    print()

    # Scan for IOExternalMethodDispatch-like tables
    # Pattern: [func_ptr][u32][u32][u32][u32] where func_ptr is in __TEXT_EXEC.__text
    # and the u32 values are small (< 0x100)
    print("=== Scanning for IOExternalMethodDispatch-like tables ===")
    tables_found = 0
    for i in range(0, const_sec["size"] - 31, 8):
        off = const_sec["offset"] + i
        func_ptr = read_u64(data, off)
        low32 = func_ptr & 0xFFFFFFFF
        target_va = KERNEL_BASE + low32

        # Check if this is a kernel pointer in __TEXT_EXEC.__text
        if not (text_start <= target_va < text_end):
            continue

        # Check if next 4 u32 values are small (typical for dispatch table)
        s1 = read_u32(data, off + 8)
        s2 = read_u32(data, off + 12)
        s3 = read_u32(data, off + 16)
        s4 = read_u32(data, off + 20)

        if all(0 <= v <= 0x100 for v in [s1, s2, s3, s4]):
            table_va = const_sec["addr"] + i
            print(f"  {table_va:#018x}: func={target_va:#018x} scalar_in={s1} struct_in={s2} scalar_out={s3} struct_out={s4}")
            tables_found += 1
            if tables_found >= 50:
                break

    print(f"\nTotal dispatch-like tables found: {tables_found}")

    # Also scan for vtable-like structures (arrays of consecutive function pointers)
    print("\n=== Scanning for vtable-like structures ===")
    vtables = 0
    for i in range(0, const_sec["size"] - 63, 8):
        off = const_sec["offset"] + i
        # Check if we have at least 8 consecutive function pointers
        all_ptr = True
        ptrs = []
        for j in range(8):
            val = read_u64(data, off + j * 8)
            low32 = val & 0xFFFFFFFF
            target_va = KERNEL_BASE + low32
            if not (text_start <= target_va < text_end):
                all_ptr = False
                break
            ptrs.append(target_va)
        if all_ptr:
            table_va = const_sec["addr"] + i
            print(f"  {table_va:#018x}: {len(ptrs)} consecutive function pointers")
            for j, p in enumerate(ptrs[:8]):
                print(f"    slot {j}: {p:#018x}")
            vtables += 1
            if vtables >= 20:
                break

    print(f"\nTotal vtable-like structures found: {vtables}")


if __name__ == "__main__":
    main()
