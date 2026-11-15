#!/usr/bin/env python3
"""Find AGXDeviceUserClient class struct and its method table.

Approach:
1. Find the string "site.AGXDeviceUserClient" in the binary
2. Read backward to find the OSMetaClass struct (C++ class metadata)
3. Find the vtable / method list associated with the class
4. Look for externalMethod handler
"""
import re
import struct
from pathlib import Path

MACHO = Path("G:/REPO/analysis/agx/2701/com.apple.AGXG18P")
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


def find_string_va(data, sections, target):
    """Find the virtual address of a null-terminated string."""
    for s in sections:
        if s["size"] < len(target) + 1:
            continue
        for i in range(0, s["size"] - len(target)):
            if data[s["offset"] + i:s["offset"] + i + len(target)] == target:
                return s["addr"] + i, s["seg"], s["sect"], s["offset"] + i
    return None


def read_u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def main():
    data, segments, sections = parse_macho(MACHO)

    # Find key strings
    targets = [
        b"site.AGXDeviceUserClient",
        b"site.AGXBitmap<kAGXMaxChannelCount>",
        b"site.AGX3DChannelSKSMG18P",
        b"site.AGXCLChannelSKSMG18P",
        b"site.AGXTAChannelSKSMG18P",
        b"site.AGXChannel",
    ]
    for t in targets:
        res = find_string_va(data, sections, t)
        if res:
            va, seg, sect, off = res
            print(f"'{t.decode()}' at va={va:#018x} ({seg}.{sect}) fileoff={off:#x}")
            # Show surrounding bytes
            print(f"  context (64 bytes before):")
            start = max(0, off - 64)
            ctx = data[start:off]
            for j in range(0, len(ctx), 8):
                val = struct.unpack_from("<Q", data, start + j)[0] if start + j + 8 <= len(data) else 0
                cur = start + j
                note = ""
                if 0xFFFFFE0000000000 <= val <= 0xFFFFFE0010000000:
                    note = f"  <-- KERN {val:#018x}"
                print(f"    {cur:#018x}: {val:#018x}{note}")
            print(f"  context (64 bytes after):")
            ctx2 = data[off:off + 64]
            for j in range(0, len(ctx2), 8):
                if off + j + 8 > len(data):
                    break
                val = struct.unpack_from("<Q", data, off + j)[0]
                cur = off + j
                note = ""
                if 0xFFFFFE0000000000 <= val <= 0xFFFFFE0010000000:
                    note = f"  <-- KERN {val:#018x}"
                print(f"    {cur:#018x}: {val:#018x}{note}")
            print()
        else:
            print(f"'{t.decode()}' NOT FOUND")

    # Also search __TEXT_EXEC.__text for any reference to the user client class
    print("\n=== Searching disasm for AGXDeviceUserClient nearby code ===")
    # Since disasm has no symbol names, we search for strings "AGXDeviceUserClient" in __TEXT.__cstring
    # which is at va=0xfffffe0007128cca size=0xfccf off=0x5b8a
    # Actually we already found the string. Now we need to find code that references it.
    # Code references use adrp + add pairs. Hard to find without disassembler.
    # Let's instead look at __DATA_CONST.__const for vtable-like structures


if __name__ == "__main__":
    main()
