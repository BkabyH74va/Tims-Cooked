#!/usr/bin/env python3
"""AGXG18P deep dive: module init funcs, vtables, AGXDeviceUserClient methods.

Target: iPhone18,1 / V53AP / t8150 / iOS 27.0.1 (24A446)
Kext: com.apple.AGXG18P (27.0.1)
"""
import struct
from pathlib import Path

KERNEL_BASE = 0xFFFFFE0007000000
MACHO = Path("G:/REPO/analysis/agx/2701/com.apple.AGXG18P")
DISASM = Path("G:/REPO/analysis/agx/2701.disasm.txt")

MOD_INIT_VA = 0xFFFFFE0007F1E3F0
MOD_INIT_SIZE = 0x3C0
MOD_TERM_VA = 0xFFFFFE0007F1E7B0
MOD_TERM_SIZE = 0x2F0
CONST_VA = 0xFFFFFE0007F1EAA0
CONST_SIZE = 0x11338

def parse_macho(path):
    data = path.read_bytes()
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
    assert magic == 0xFEEDFACF, f"bad magic {magic:#x}"
    segments, sections = [], []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            segname = data[off + 8:off + 24].rstrip(b"\0").decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            segments.append((segname, vmaddr, vmsize, fileoff, filesize))
            so = off + 72
            for _ in range(nsects):
                sectname = data[so:so + 16].rstrip(b"\0").decode()
                seg = data[so + 16:so + 32].rstrip(b"\0").decode()
                addr, size = struct.unpack_from("<QQ", data, so + 32)
                offset = struct.unpack_from("<I", data, so + 48)[0]
                sections.append((seg, sectname, addr, size, offset))
                so += 80
        off += cmdsize
    return data, segments, sections


def va_to_off(sections, va):
    for seg, sect, addr, size, off in sections:
        if addr <= va < addr + size:
            return off + (va - addr)
    return None


def read_u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def dump_section(data, sections, va, size, label):
    off = va_to_off(sections, va)
    if off is None:
        print(f"{label}: va {va:#x} not found in any section")
        return
    print(f"\n=== {label} ===")
    print(f"  va={va:#018x} size={size:#x} fileoff={off:#x}")
    for i in range(0, size, 8):
        val = read_u64(data, off + i)
        cur_va = va + i
        # Try to interpret as pointer
        note = ""
        if 0xFFFFFE0000000000 <= val <= 0xFFFFFE0010000000:
            note = f"  <-- kernel ptr {val:#018x}"
        print(f"  {cur_va:#018x}: {val:#018x}{note}")


def find_in_disasm(disasm, pattern, limit=30):
    hits = []
    with open(disasm) as f:
        for line in f:
            if pattern in line:
                hits.append(line.rstrip())
                if len(hits) >= limit:
                    break
    return hits


def main():
    data, segments, sections = parse_macho(MACHO)

    # Dump mod_init_func
    dump_section(data, sections, MOD_INIT_VA, MOD_INIT_SIZE, "__DATA_CONST.__mod_init_func")

    # Dump mod_term_func
    dump_section(data, sections, MOD_TERM_VA, MOD_TERM_SIZE, "__DATA_CONST.__mod_term_func")

    # Look for AGXDeviceUserClient references in disasm
    print("\n=== AGXDeviceUserClient in disassembly ===")
    for line in find_in_disasm(DISASM, "AGXDeviceUserClient", 30):
        print(f"  {line}")

    # Look for IOUserClient / externalMethod patterns
    print("\n=== externalMethod / IOConnectCallMethod patterns ===")
    for pat in ["externalMethod", "IOConnectCallMethod", "getTargetAndMethodForIndex", "newUserClient", "clientWithTask"]:
        hits = find_in_disasm(DISASM, pat, 10)
        if hits:
            print(f"  --- {pat} ---")
            for h in hits:
                print(f"  {h}")

    # Look for vtable construction near AGXBitmap
    print("\n=== AGXBitmap in disassembly ===")
    for line in find_in_disasm(DISASM, "AGXBitmap", 30):
        print(f"  {line}")

    # Look for the helper function cluster area (0xfffffe0008556f30 - 0xfffffe0008556fb0)
    print("\n=== Helper cluster area (0xfffffe0008556f30-0xfffffe0008556fb0) ===")
    with open(DISASM) as f:
        for line in f:
            addr_str = line.split(":")[0].strip()
            try:
                addr = int(addr_str, 16)
                if 0xFFFFFE0008556F20 <= addr <= 0xFFFFFE0008556FC0:
                    print(f"  {line.rstrip()}")
            except ValueError:
                pass


if __name__ == "__main__":
    main()
