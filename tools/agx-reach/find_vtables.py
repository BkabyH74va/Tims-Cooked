#!/usr/bin/env python3
"""AGXG18P reachability: find vtables, dispatch tables, blraa calls, and key functions."""
from pathlib import Path
import struct

MACHO = Path("G:/REPO/analysis/agx/2701/com.apple.AGXG18P")
DISASM = Path("G:/REPO/analysis/agx/2701.disasm.txt")
KERNEL_BASE = 0xFFFFFE0007000000

def parse_macho(path):
    data = path.read_bytes()
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
    assert magic == 0xFEEDFACF
    segments, sections = [], []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            segname = data[off + 8:off + 24].rstrip(b"\0").decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            segments.append({"name": segname, "vmaddr": vmaddr, "vmsize": vmsize,
                            "fileoff": fileoff, "filesize": filesize})
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
    return data, segments, sections


def va_to_off(sections, va):
    for s in sections:
        if s["addr"] <= va < s["addr"] + s["size"]:
            return s["offset"] + (va - s["addr"])
    return None


def read_u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def scan_vtables(data, sections, text_exec_addr, text_exec_size):
    """Scan __DATA_CONST.__const for arrays of kernel pointers (potential vtables)."""
    vtables = []
    for s in sections:
        if s["seg"] != "__DATA_CONST":
            continue
        if s["sect"] not in ("__const",):
            continue
        for i in range(0, s["size"] - 7, 8):
            off = s["offset"] + i
            val = read_u64(data, off)
            va = s["addr"] + i
            # Check if it's a kernel pointer into __TEXT_EXEC.__text
            if text_exec_addr <= val < text_exec_addr + text_exec_size:
                # Check if next entries are also kernel pointers (vtable-like)
                chain = []
                for j in range(i, min(i + 64, s["size"]), 8):
                    v2 = read_u64(data, s["offset"] + j)
                    if text_exec_addr <= v2 < text_exec_addr + text_exec_size:
                        chain.append((s["addr"] + j, v2))
                    else:
                        break
                if len(chain) >= 3:
                    vtables.append((va, chain))
    return vtables


def find_blraa(disasm_lines):
    """Find all blraa (authenticated indirect branch) instructions."""
    hits = []
    for i, line in enumerate(disasm_lines):
        if "blraa" in line:
            hits.append((i + 1, line.strip()))
    return hits


def find_function_at(disasm_lines, target_va):
    """Find the disassembly line for a given VA."""
    target_hex = f"{target_va:#018x}"
    for i, line in enumerate(disasm_lines):
        if target_hex in line:
            return i + 1, line.strip()
    return None, None


def main():
    data, segments, sections = parse_macho(MACHO)

    # Find __TEXT_EXEC.__text bounds
    text_exec = None
    for s in sections:
        if s["seg"] == "__TEXT_EXEC" and s["sect"] == "__text":
            text_exec = s
            break

    if text_exec:
        print(f"__TEXT_EXEC.__text: va={text_exec['addr']:#018x} size={text_exec['size']:#x}")

    # Read disassembly as UTF-16LE
    with open(DISASM, "r", encoding="utf-16-le") as f:
        lines = f.readlines()

    # Find blraa calls
    print("\n=== blraa (authenticated indirect branch) instructions ===")
    blraa_hits = find_blraa(lines)
    print(f"Total blraa: {len(blraa_hits)}")
    for ln, line in blraa_hits[:30]:
        print(f"  {ln:6d}: {line[:120]}")

    # Look at functions near 0xfffffe000858961c (called with string args)
    print("\n=== Function at 0xfffffe000858961c ===")
    ln, line = find_function_at(lines, 0xFFFFFE000858961C)
    if ln:
        print(f"  Line {ln}: {line}")
        # Show surrounding context
        for j in range(max(0, ln - 3), min(len(lines), ln + 10)):
            print(f"    {j+1:6d}: {lines[j].rstrip()[:120]}")

    # Look at functions near 0xfffffe000858959c  
    print("\n=== Function at 0xfffffe000858959c ===")
    ln, line = find_function_at(lines, 0xFFFFFE000858959C)
    if ln:
        print(f"  Line {ln}: {line}")

    # Look at functions near 0xfffffe0008586f20
    print("\n=== Function at 0xfffffe0008586f20 ===")
    ln, line = find_function_at(lines, 0xFFFFFE0008586F20)
    if ln:
        print(f"  Line {ln}: {line}")

    # Scan for vtables in __DATA_CONST.__const
    if text_exec:
        print("\n=== Potential vtables in __DATA_CONST.__const ===")
        vtables = scan_vtables(data, sections, text_exec["addr"], text_exec["size"])
        print(f"Found {len(vtables)} potential vtable chains")
        for va, chain in vtables[:20]:
            print(f"  vtable at {va:#018x}: {len(chain)} entries")
            for entry_va, entry_val in chain[:8]:
                print(f"    {entry_va:#018x} -> {entry_val:#018x}")


if __name__ == "__main__":
    main()
