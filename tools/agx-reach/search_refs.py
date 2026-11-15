#!/usr/bin/env python3
"""AGXG18P: search data sections for references to key strings and functions."""
import struct
from pathlib import Path

MACHO = Path("G:/REPO/analysis/agx/2701/com.apple.AGXG18P")
KERNEL_BASE = 0xFFFFFE0007000000

# Target virtual addresses
TARGETS = {
    "site.AGXDeviceUserClient": 0xFFFFFE000712C122,
    "site.AGXBitmap<kAGXMaxChannelCount>": 0xFFFFFE000712A90C,
    "helper_fn_body": 0xFFFFFE0008556F54,
    "helper_fn_entry": 0xFFFFFE0008556F50,
}


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
                                "size": size, "offset": offset, "fileoff": offset})
                so += 80
        off += cmdsize
    return data, sections


def read_u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def main():
    data, sections = parse_macho(MACHO)

    # Compute encoded low32 values for each target
    for name, va in TARGETS.items():
        rel = (va - KERNEL_BASE) & 0xFFFFFFFF
        print(f"{name}: va={va:#018x} rel={rel:#010x}")

    print("\n=== Searching all data sections for target references ===")
    for name, va in TARGETS.items():
        rel = (va - KERNEL_BASE) & 0xFFFFFFFF
        print(f"\n--- {name} (rel={rel:#010x}) ---")
        found = 0
        for s in sections:
            if s["size"] < 8:
                continue
            for i in range(0, s["size"] - 7, 8):
                off = s["offset"] + i
                val = read_u64(data, off)
                low = val & 0xFFFFFFFF
                if low == rel:
                    cur_va = s["addr"] + i
                    high = (val >> 32) & 0xFFFFFFFF
                    print(f"  {cur_va:#018x} val={val:#018x} high={high:#06x} {s['seg']}.{s['sect']}")
                    found += 1
        print(f"  Total: {found}")

    # Also search for the raw VA (not chained fixup encoded)
    print("\n=== Searching for raw VA pointers (not chained fixup) ===")
    for name, va in TARGETS.items():
        print(f"\n--- {name} (raw va={va:#018x}) ---")
        found = 0
        for s in sections:
            if s["size"] < 8:
                continue
            for i in range(0, s["size"] - 7, 8):
                off = s["offset"] + i
                val = read_u64(data, off)
                if val == va:
                    cur_va = s["addr"] + i
                    print(f"  {cur_va:#018x} val={val:#018x} {s['seg']}.{s['sect']}")
                    found += 1
        print(f"  Total: {found}")

    # Dump __DATA_CONST.__const section fully (it's small enough)
    print("\n=== __DATA_CONST.__const hex dump (first 0x2000 bytes) ===")
    for s in sections:
        if s["seg"] == "__DATA_CONST" and s["sect"] == "__const":
            off = s["offset"]
            size = min(s["size"], 0x2000)
            for i in range(0, size, 16):
                chunk = data[off + i:off + i + 16]
                hex_str = " ".join(f"{b:02x}" for b in chunk)
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                cur_va = s["addr"] + i
                print(f"  {cur_va:#018x}: {hex_str:<48s} {ascii_str}")
            break


if __name__ == "__main__":
    main()
