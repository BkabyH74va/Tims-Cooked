#!/usr/bin/env python3
"""AGXG18P reachability: trace class ownership and externalMethod dispatch.

Step 1: Find all functions that reference site.AGXDeviceUserClient via adrp+add
Step 2: Search __DATA_CONST.__const for IOExternalMethodDispatch-like tables
Step 3: Disassemble functions near the helper and class registration
"""
import struct
import re
from pathlib import Path

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


def find_string_refs_in_disasm(disasm_lines, target_va):
    """Find all adrp+add sequences that construct target_va."""
    # target_va = page_base + offset
    page_base = target_va & ~0xFFF
    offset = target_va & 0xFFF
    hits = []
    for i, line in enumerate(disasm_lines):
        if f"adrp" in line and f"{page_base:#018x}" in line:
            # Check next few lines for add with the right offset
            for j in range(i + 1, min(i + 5, len(disasm_lines))):
                if "add" in disasm_lines[j] and f"#{offset:#x}" in disasm_lines[j]:
                    hits.append({
                        "adrp_line": i + 1,
                        "adrp_text": disasm_lines[i].strip(),
                        "add_line": j + 1,
                        "add_text": disasm_lines[j].strip(),
                    })
                    break
    return hits


def find_function_boundaries(disasm_lines):
    """Find function start addresses in disassembly."""
    funcs = []
    for i, line in enumerate(disasm_lines):
        # Function starts typically have bti c or just an address at line start
        m = re.match(r'\s*(0x[0-9a-fA-F]+):\s+[0-9a-fA-F\s]+\s+(\w+)', line)
        if m:
            addr = int(m.group(1), 16)
            insn = m.group(2)
            if insn == "bti":
                funcs.append((addr, i + 1))
    return funcs


def find_function_containing(disasm_lines, target_va, funcs):
    """Find which function contains a given VA."""
    for addr, ln in funcs:
        # Next function start
        next_addr = None
        for a2, l2 in funcs:
            if a2 > addr:
                if next_addr is None or a2 < next_addr:
                    next_addr = a2
        if next_addr is None or target_va < next_addr:
            if target_va >= addr:
                return addr, ln
    return None, None


def main():
    data, segments, sections = parse_macho(MACHO)

    # Read disassembly
    with open(DISASM, "r", encoding="utf-16-le") as f:
        lines = f.readlines()

    print(f"Total disasm lines: {len(lines)}")

    # Step 1: Find all functions referencing site.AGXDeviceUserClient
    # String is at va=0xfffffe000712c122
    target_va = 0xFFFFFE000712C122
    print(f"\n=== Functions referencing site.AGXDeviceUserClient (va={target_va:#018x}) ===")
    hits = find_string_refs_in_disasm(lines, target_va)
    print(f"Found {len(hits)} adrp+add pairs")
    for h in hits[:30]:
        print(f"  Line {h['adrp_line']}: {h['adrp_text'][:100]}")
        print(f"  Line {h['add_line']}: {h['add_text'][:100]}")

    # Step 2: Find function boundaries
    print("\n=== Finding function boundaries ===")
    funcs = find_function_boundaries(lines)
    print(f"Found {len(funcs)} functions (bti markers)")

    # Step 3: For each string ref, find containing function
    print("\n=== String ref -> containing function ===")
    for h in hits[:20]:
        # Extract address from adrp line
        m = re.match(r'\s*(0x[0-9a-fA-F]+):', lines[h['adrp_line'] - 1])
        if m:
            addr = int(m.group(1), 16)
            faddr, fln = find_function_containing(lines, addr, funcs)
            if faddr:
                print(f"  {addr:#018x} in function {faddr:#018x} (line {fln})")

    # Step 4: Search __DATA_CONST.__const for IOExternalMethodDispatch-like tables
    # These are arrays of function pointers in __TEXT_EXEC.__text
    print("\n=== Scanning __DATA_CONST.__const for function pointer tables ===")
    const_sec = None
    text_exec_sec = None
    for s in sections:
        if s["seg"] == "__DATA_CONST" and s["sect"] == "__const":
            const_sec = s
        if s["seg"] == "__TEXT_EXEC" and s["sect"] == "__text":
            text_exec_sec = s

    if const_sec and text_exec_sec:
        text_start = text_exec_sec["addr"]
        text_end = text_exec_sec["addr"] + text_exec_sec["size"]
        tables = []
        for i in range(0, const_sec["size"] - 23, 8):
            off = const_sec["offset"] + i
            vals = []
            is_table = True
            for j in range(4):  # Check 4 consecutive pointers
                val = read_u64(data, off + j * 8)
                if not (text_start <= val < text_end):
                    is_table = False
                    break
                vals.append(val)
            if is_table:
                table_va = const_sec["addr"] + i
                tables.append((table_va, vals))
        print(f"Found {len(tables)} potential dispatch tables (4+ consecutive text pointers)")
        for va, vals in tables[:30]:
            print(f"  {va:#018x}: " + " ".join(f"{v:#018x}" for v in vals[:4]))

    # Step 5: Disassemble the helper function area
    print("\n=== Helper function at 0xfffffe0008556f54 ===")
    for i, line in enumerate(lines):
        if "0xfffffe0008556f54:" in line:
            for j in range(max(0, i - 10), min(len(lines), i + 30)):
                print(f"  {j+1:6d}: {lines[j].rstrip()}")
            break


if __name__ == "__main__":
    main()
