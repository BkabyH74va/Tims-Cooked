#!/usr/bin/env python3
"""AGXG18P: examine dispatch tables and vtables in detail."""
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

    const_sec = None
    text_exec_sec = None
    for s in sections:
        if s["seg"] == "__DATA_CONST" and s["sect"] == "__const":
            const_sec = s
        if s["seg"] == "__TEXT_EXEC" and s["sect"] == "__text":
            text_exec_sec = s

    text_start = text_exec_sec["addr"]
    text_end = text_exec_sec["addr"] + text_exec_sec["size"]

    print("=== Dispatch tables near 0xfffffe0007f20940 (scalar_out=3) ===")
    for i in range(0x900, 0xA00, 8):
        off = const_sec["offset"] + i
        func_ptr = read_u64(data, off)
        target_va = KERNEL_BASE + (func_ptr & 0xFFFFFFFF)
        if text_start <= target_va < text_end:
            s1 = read_u32(data, off + 8)
            s2 = read_u32(data, off + 12)
            s3 = read_u32(data, off + 16)
            s4 = read_u32(data, off + 20)
            table_va = const_sec["addr"] + i
            print(f"  {table_va:#018x}: func={target_va:#018x} s1={s1} s2={s2} s3={s3} s4={s4}")

    print("\n=== All dispatch tables (full listing) ===")
    for i in range(0, const_sec["size"] - 31, 8):
        off = const_sec["offset"] + i
        func_ptr = read_u64(data, off)
        target_va = KERNEL_BASE + (func_ptr & 0xFFFFFFFF)
        if not (text_start <= target_va < text_end):
            continue
        s1 = read_u32(data, off + 8)
        s2 = read_u32(data, off + 12)
        s3 = read_u32(data, off + 16)
        s4 = read_u32(data, off + 20)
        if any(v > 0x100 for v in [s1, s2, s3, s4]):
            continue
        table_va = const_sec["addr"] + i
        print(f"  {table_va:#018x}: func={target_va:#018x} [{s1},{s2},{s3},{s4}]")

    print("\n=== Checking if OOB helper (0xfffffe0008556f54) appears in any dispatch table ===")
    helper_va = 0xFFFFFE0008556F54
    helper_rel = (helper_va - KERNEL_BASE) & 0xFFFFFFFF
    for i in range(0, const_sec["size"] - 7, 8):
        off = const_sec["offset"] + i
        val = read_u64(data, off)
        if (val & 0xFFFFFFFF) == helper_rel:
            table_va = const_sec["addr"] + i
            print(f"  FOUND at {table_va:#018x} val={val:#018x}")

    print("\n=== Looking at vtables near OOB helper address range ===")
    # Look at vtables that have entries near 0xfffffe0008556f54
    for i in range(0, const_sec["size"] - 63, 8):
        off = const_sec["offset"] + i
        ptrs = []
        all_ptr = True
        for j in range(8):
            val = read_u64(data, off + j * 8)
            target_va = KERNEL_BASE + (val & 0xFFFFFFFF)
            if not (text_start <= target_va < text_end):
                all_ptr = False
                break
            ptrs.append(target_va)
        if all_ptr:
            # Check if any pointer is near the helper (within 0x10000)
            for p in ptrs:
                if abs(p - helper_va) < 0x10000:
                    table_va = const_sec["addr"] + i
                    print(f"  Vtable at {table_va:#018x} has entry near helper:")
                    for j, p in enumerate(ptrs):
                        near = " <-- NEAR HELPER" if abs(p - helper_va) < 0x10000 else ""
                        print(f"    slot {j}: {p:#018x}{near}")
                    break


if __name__ == "__main__":
    main()
